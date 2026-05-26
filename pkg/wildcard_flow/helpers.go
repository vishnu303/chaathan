package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

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
		logger.Warning("⏭ Skip requested — skipping current tool...")
		logger.Warning("⏭ Skipped: %s", toolName)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			// Tool ignored cancellation or hung on I/O, proceed anyway
		}
		return ErrToolSkipped
	case <-c.GoCtx.Done():
		toolCancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
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
	// 4 MB max line buffer — httpx JSONL can exceed 1 MB when extensive
	// tech detection, header data, or TLS info is emitted.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

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
	if err := scanner.Err(); err != nil {
		logger.Warning("httpx JSONL scanner error (some lines may have been skipped): %v", err)
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


// collectGFMatches runs the installed gf patterns present in allowlist against
// inputFile, merges the matches and writes them to outputFile.
// When scanID > 0, persists each URL-pattern pair in the gf_matches table
// so that ROI scoring can boost URLs that matched vulnerability patterns.
func collectGFMatches(ctx context.Context, tb *tools.ToolBox, inputFile, outputFile string, allowlist map[string]bool, scanID int64) int {
	patterns := installedGFPatterns(allowlist)
	tmpFiles := make([]string, 0, len(patterns))
	// Schedule cleanup of all temp files when this function exits,
	// whether by normal return or panic.
	defer func() {
		for _, f := range tmpFiles {
			os.Remove(f)
		}
	}()

	for _, pattern := range patterns {
		// Bail out early if the context was cancelled (user pressed 's' or Ctrl+C)
		if ctx.Err() != nil {
			break
		}
		tmpFile := outputFile + "." + pattern
		if err := tb.RunGFPattern(ctx, pattern, inputFile, tmpFile); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}
		if utils.FileExists(tmpFile) {
			// Persist matches to DB for ROI scoring
			if scanID > 0 {
				if matchedURLs := loadLineSlice(tmpFile, 0); len(matchedURLs) > 0 {
					database.AddGFMatches(scanID, matchedURLs, pattern)
				}
			}
			tmpFiles = append(tmpFiles, tmpFile)
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

// extractUncoverHosts reads an uncover JSONL output file and writes unique
// hostnames (one per line) to outputFile. Returns the number written.
// This converts Uncover's JSON format into a plain-text list that can be
// merged into all_subdomains.txt by stepDNSConsolidation (Step 6).
func extractUncoverHosts(uncoverJSON, outputFile string) int {
	type uncoverLine struct {
		Host string `json:"host"`
		IP   string `json:"ip"`
	}

	f, err := os.Open(uncoverJSON)
	if err != nil {
		return 0
	}
	defer f.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer out.Close()

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec uncoverLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		host := rec.Host
		if host == "" {
			host = rec.IP
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		fmt.Fprintln(out, host)
		count++
	}
	return count
}

// ─────────────────────────────────────────────────────────────
// CNAME filtering for takeover detection
// ─────────────────────────────────────────────────────────────

// filterCNAMESubdomains reads dnsx_resolved.json and extracts subdomains
// that have CNAME records. Only these are real takeover candidates — a
// subdomain with only A/AAAA records can't be taken over via dangling CNAME.
func filterCNAMESubdomains(dnsxJSONFile, outputFile string) int {
	file, err := os.Open(dnsxJSONFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer out.Close()

	type dnsxRecord struct {
		Host  string   `json:"host"`
		CNAME []string `json:"cname"`
	}

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if len(rec.CNAME) == 0 || rec.Host == "" {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(rec.Host))
		if seen[host] {
			continue
		}
		seen[host] = true
		fmt.Fprintln(out, host)
		count++
	}
	return count
}

// ─────────────────────────────────────────────────────────────
// Scoped URL filtering for DAST and Dalfox
// ─────────────────────────────────────────────────────────────

// junkDomainSuffixes are 3rd-party domains that should never be scanned.
var junkDomainSuffixes = []string{
	"googleapis.com", "gstatic.com", "google-analytics.com",
	"googletagmanager.com", "doubleclick.net", "googlesyndication.com",
	"facebook.com", "fbcdn.net", "twitter.com", "twimg.com",
	"cloudflare.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
	"unpkg.com", "maxcdn.bootstrapcdn.com", "bootstrapcdn.com",
	"jquery.com", "fontawesome.com", "fonts.googleapis.com",
	"gravatar.com", "wp.com", "amazon-adsystem.com",
	"hotjar.com", "clarity.ms", "segment.io", "segment.com",
	"intercom.io", "sentry.io", "newrelic.com", "nr-data.net",
	"akamaihd.net", "akamai.net", "fastly.net", "edgecastcdn.net",
	"cloudfront.net", "azureedge.net", "azurewebsites.net",
	"herokuapp.com", "github.io", "gitlab.io",
	"recaptcha.net", "hcaptcha.com",
}

// staticExtensions are file extensions that can't have injection points.
var staticExtensions = map[string]bool{
	".js": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".otf": true, ".mp4": true, ".webm": true,
	".mp3": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true,
	".map": true, ".webp": true, ".avif": true, ".bmp": true, ".tif": true,
}

// isJunkDomain returns true if the host belongs to a known 3rd-party service.
func isJunkDomain(host string) bool {
	host = strings.ToLower(host)
	for _, suffix := range junkDomainSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// hasStaticExtension returns true if the URL path ends with a static file extension.
func hasStaticExtension(rawURL string) bool {
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for ext := range staticExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}


// pathKey extracts a deduplication key from a URL — the scheme+host+path
// without query parameters, so /api/user?id=1 and /api/user?id=2 map
// to the same key.
func pathKey(rawURL string) string {
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host + parsed.Path)
}

// collectScopedURLs filters all_urls_live.txt for DAST-suitable URLs:
//  1. Must contain parameters (?key=value)
//  2. Must be in-scope domain (matches target domain)
//  3. Skip static extensions
//  4. Skip known 3rd-party domains (when skip_third_party is true)
//  5. Deduplicate by path (keep highest-ROI variant per endpoint)
//  6. Sort by ROI score descending (best targets first)
//  7. Cap at maxURLs
func collectScopedURLs(c *Ctx, inputFile, outputFile string, maxURLs int) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	// Determine whether to filter 3rd-party domains.
	// Default: filter ON. Set skip_third_party: false in config to disable.
	filterJunk := true
	if c.Cfg != nil && !c.Cfg.Tools.Dalfox.SkipThirdParty {
		filterJunk = false
	}

	// Phase 1: collect all qualifying URLs with scores
	type scoredURL struct {
		raw   string
		score int
	}
	// Keep the best-scoring URL per path key
	bestPerPath := make(map[string]scoredURL)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Must have parameters
		if !strings.Contains(line, "?") || !strings.Contains(line, "=") {
			continue
		}
		// Skip static extensions
		if hasStaticExtension(line) {
			continue
		}
		// Extract host for scope and junk checks
		parsed, err := neturl.Parse(line)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			continue
		}
		// Skip 3rd-party domains (when enabled)
		if filterJunk && isJunkDomain(host) {
			continue
		}
		// Must be in-scope for target domain
		target := strings.ToLower(c.Domain)
		if host != target && !strings.HasSuffix(host, "."+target) {
			continue
		}

		// Score this URL for ROI ordering
		score := urlROIScore(line)

		// Deduplicate by path — keep the highest-scoring variant
		pk := pathKey(line)
		if existing, ok := bestPerPath[pk]; ok {
			if score > existing.score {
				bestPerPath[pk] = scoredURL{raw: line, score: score}
			}
		} else {
			bestPerPath[pk] = scoredURL{raw: line, score: score}
		}
	}

	if len(bestPerPath) == 0 {
		return 0
	}

	// Phase 2: sort by ROI score descending
	urls := make([]scoredURL, 0, len(bestPerPath))
	for _, su := range bestPerPath {
		urls = append(urls, su)
	}
	sort.Slice(urls, func(i, j int) bool {
		return urls[i].score > urls[j].score
	})

	// Phase 3: write top N to output file
	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	for _, su := range urls {
		fmt.Fprintln(f, su.raw)
		count++
		if maxURLs > 0 && count >= maxURLs {
			break
		}
	}
	return count
}

// urlROIScore assigns a priority score to a URL for DAST/XSS scanning.
// Higher score = more likely to contain exploitable vulnerabilities.
func urlROIScore(rawURL string) int {
	score := 0
	lower := strings.ToLower(rawURL)

	// More parameters = more injection surface (+2 per param)
	parsed, err := neturl.Parse(rawURL)
	if err == nil {
		score += len(parsed.Query()) * 2
	}

	// High-value path markers (auth, API, debug, etc.)
	highValueMarkers := []string{
		"/admin", "/login", "/signin", "/signup", "/auth",
		"/oauth", "/token", "/graphql", "/api/", "/v1/", "/v2/",
		"/rest/", "/debug", "/console", "/actuator", "/swagger",
		"/openapi", "/upload", "/callback", "/redirect", "/reset",
		"/password", "/search", "/export", "/import", "/webhook",
	}
	for _, marker := range highValueMarkers {
		if strings.Contains(lower, marker) {
			score += 5
			break // one marker match is enough
		}
	}

	// Interesting parameter names (+3 each)
	interestingParams := []string{
		"url", "uri", "path", "redirect", "return", "next", "goto",
		"file", "page", "template", "include", "cmd", "exec",
		"query", "search", "id", "user", "email", "callback",
	}
	if parsed != nil {
		for _, key := range interestingParams {
			if parsed.Query().Get(key) != "" {
				score += 3
			}
		}
	}

	return score
}

// collectScopedParamURLs filters URLs for Dalfox XSS scanning:
// in-scope, parameterized, no static files, no 3rd-party junk (config-driven),
// ROI-ordered (best targets first), deduplicated by path, capped at the configured max.
func collectScopedParamURLs(c *Ctx, inputFile, outputFile string) int {
	maxURLs := 500
	if c.Cfg != nil && c.Cfg.Tools.Dalfox.MaxURLs > 0 {
		maxURLs = c.Cfg.Tools.Dalfox.MaxURLs
	}
	return collectScopedURLs(c, inputFile, outputFile, maxURLs)
}
