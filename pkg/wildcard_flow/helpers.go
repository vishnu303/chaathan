package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

var tier1GFPatterns = map[string]bool{
	"xss":         true,
	"sqli":        true,
	"sqli-error":  true,
	"lfi":         true,
	"ssrf":        true,
	"redirect":    true,
	"rce":         true,
	"rce-2":       true,
	"idor":        true,
	"debug_logic": true,
	"ssti":        true,
}

var jsGFPatterns = map[string]bool{
	"domxss":   true,
	"execs":    true,
	"js-sinks": true,
}

var secretGFPatterns = map[string]bool{
	"api-keys": true,
	"aws-keys": true,
	"firebase": true,
	"github":   true,
	"jwt":      true,
}

// ─────────────────────────────────────────────────────────────
// Skip-tool support
// ─────────────────────────────────────────────────────────────

// ErrToolSkipped is returned by runWithSkip when the user presses 's'.
var ErrToolSkipped = fmt.Errorf("tool skipped by user")

// runWithSkip executes fn in a goroutine and monitors the skip channel.
// If the user presses 's', fn's context is cancelled and ErrToolSkipped
// is returned. Parent cancellation propagates as ctx.Err().
func runWithSkip(c *Ctx, toolName string, fn func(ctx context.Context) error) error {
	drainSkipSignal(c)

	toolCtx, toolCancel := context.WithCancel(c.GoCtx)
	defer toolCancel()

	done := make(chan error, 1)
	go func() {
		done <- fn(toolCtx)
	}()

	select {
	case err := <-done:
		return err
	case <-c.SkipChan:
		toolCancel()
		logger.Warning("⏭ Skipped: %s", toolName)
		<-done
		return ErrToolSkipped
	case <-c.GoCtx.Done():
		toolCancel()
		<-done
		return c.GoCtx.Err()
	}
}

// drainSkipSignal discards any pending skip signal before starting a tool,
// so leftover signals from a previous step don't immediately skip the next.
func drainSkipSignal(c *Ctx) {
	for {
		select {
		case <-c.SkipChan:
		default:
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────
// File helpers
// ─────────────────────────────────────────────────────────────

// existingFiles returns only those paths that exist on disk.
func existingFiles(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != "" && utils.FileExists(p) {
			out = append(out, p)
		}
	}
	return out
}

// copyFile copies src to dst, creating dst if needed.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ─────────────────────────────────────────────────────────────
// URL collection helpers
// ─────────────────────────────────────────────────────────────

// collectParamURLsFromFile filters an URL file for parameterised URLs
// (containing ?key=value) and writes the unique results to outputFile.
func collectParamURLsFromFile(inputFile, outputFile string) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	seen := make(map[string]bool)
	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.Contains(line, "?") && strings.Contains(line, "=") {
			if !seen[line] {
				seen[line] = true
				fmt.Fprintln(f, line)
				count++
			}
		}
	}
	return count
}

// collectLiveHostTargetsFromHttpx reads a JSONL httpx output file and
// writes unique host URLs to outputFile. Returns the number written.
func collectLiveHostTargetsFromHttpx(inputFile, outputFile string) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	type httpxTarget struct {
		URL string `json:"url"`
	}

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result httpxTarget
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		if result.URL == "" || seen[result.URL] {
			continue
		}
		seen[result.URL] = true
		fmt.Fprintln(f, result.URL)
		count++
	}
	return count
}

// loadLineSlice reads up to limit non-empty lines from inputFile into a slice.
// Pass limit ≤ 0 to read all lines.
func loadLineSlice(inputFile string, limit int) []string {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if limit > 0 && len(lines) >= limit {
			break
		}
	}
	return lines
}

// collectROIMetadataTargetsFromFile selects high-value URLs from inputFile,
// capped at perHostLimit per host and totalLimit overall.
func collectROIMetadataTargetsFromFile(inputFile, outputFile string, perHostLimit, totalLimit int) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	seen := make(map[string]bool)
	perHost := make(map[string]int)
	count := 0
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] || !isHighValueURL(line) {
			continue
		}
		host := hostFromRawURL(line)
		if host == "" {
			continue
		}
		if perHostLimit > 0 && perHost[host] >= perHostLimit {
			continue
		}
		seen[line] = true
		perHost[host]++
		fmt.Fprintln(f, line)
		count++
		if totalLimit > 0 && count >= totalLimit {
			break
		}
	}
	return count
}

// collectGFTargetURLs runs installed Tier 1 gf patterns against inputFile,
// merges the matches and writes them to outputFile.
func collectGFTargetURLs(c *Ctx, tb *tools.ToolBox, inputFile, outputFile string) int {
	return collectGFMatches(c.GoCtx, tb, inputFile, outputFile, tier1GFPatterns)
}

// collectGFMatches runs the installed gf patterns present in allowlist against
// inputFile, merges the matches and writes them to outputFile.
func collectGFMatches(ctx context.Context, tb *tools.ToolBox, inputFile, outputFile string, allowlist map[string]bool) int {
	patterns := installedGFPatterns(allowlist)
	tmpFiles := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		tmpFile := outputFile + "." + pattern
		if err := tb.RunGFPattern(ctx, pattern, inputFile, tmpFile); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}
		if utils.FileExists(tmpFile) {
			tmpFiles = append(tmpFiles, tmpFile)
			defer os.Remove(tmpFile)
		}
	}

	if len(tmpFiles) == 0 {
		writeEmptyFile(outputFile)
		return 0
	}
	if err := utils.MergeAndDeduplicate(tmpFiles, outputFile); err != nil {
		writeEmptyFile(outputFile)
		return 0
	}
	count, _ := utils.CountFileLines(outputFile)
	return count
}

// installedGFPatterns returns the subset of allowlist currently installed in ~/.gf/.
func installedGFPatterns(allowlist map[string]bool) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	gfDir := filepath.Join(home, ".gf")
	entries, err := os.ReadDir(gfDir)
	if err != nil {
		return nil
	}

	patterns := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if allowlist == nil || allowlist[name] {
			patterns = append(patterns, name)
		}
	}
	sort.Strings(patterns)
	return patterns
}

// writeEmptyFile truncates or creates a file so retry paths do not reuse stale output.
func writeEmptyFile(path string) {
	_ = os.WriteFile(path, nil, 0644)
}

// ─────────────────────────────────────────────────────────────
// URL classification helpers
// ─────────────────────────────────────────────────────────────

// isGFUsable returns true when the gf binary and its pattern pack are present.
func isGFUsable() bool {
	if _, err := exec.LookPath("gf"); err != nil {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	gfDir := filepath.Join(home, ".gf")
	if _, err := os.Stat(gfDir); err != nil {
		return false
	}
	entries, err := os.ReadDir(gfDir)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// isHighValueURL returns true for parameterised URLs or those containing
// known sensitive path markers (admin panels, APIs, auth endpoints, etc.).
func isHighValueURL(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "?") && strings.Contains(lower, "=") {
		return true
	}
	highValueMarkers := []string{
		"/admin", "/login", "/signin", "/signup", "/auth",
		"/oauth", "/token", "/graphql", "/api", "/v1/", "/v2/",
		"/rest/", "/debug", "/console", "/actuator", "/swagger",
		"/openapi", "/health", "/metrics", "/config", "/upload",
		"/callback", "/redirect", "/reset", "/password",
	}
	for _, marker := range highValueMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// hostFromRawURL extracts the lowercase hostname from a raw URL string.
func hostFromRawURL(raw string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
