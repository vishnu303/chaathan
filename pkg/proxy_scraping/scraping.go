// Package proxy_scraping wraps proxy-scraper-checker (Rust) for proxy scraping
// and mubeng (Go) for IP rotation. It provides a clean interface for the
// wildcard workflow to automatically obtain and rotate free proxies.
package proxy_scraping

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// HarvestConfig controls the proxy-scraper-checker invocation.
type HarvestConfig struct {
	Domain        string   // target domain to validate proxies against
	TimeoutMin    int      // max scraper runtime in minutes (default: 10)
	ProxyTypes    []string // preferred types: ["socks5","http","socks4"]
	MaxConcurrent int      // concurrent checks (default: 256)
	OutputDir     string   // working directory for temp files and output
}

// HarvestResult holds the output of a proxy scraping run.
type HarvestResult struct {
	ProxyListFile string        // path to proxy_pool.txt (one proxy per line)
	TotalScraped  int           // proxies scraped from sources
	TotalValid    int           // proxies that passed domain check
	AllValid      []string      // all valid proxy URLs
	Duration      time.Duration // wall-clock duration of the harvest
}

// proxyEntry represents a single proxy from the JSON output.
type proxyEntry struct {
	Protocol     string  `json:"protocol"`
	Host         string  `json:"host"`
	Port         int     `json:"port"`
	Username     string  `json:"username,omitempty"`
	Password     string  `json:"password,omitempty"`
	ResponseTime float64 `json:"response_time,omitempty"` // seconds
}

// RunHarvest executes proxy-scraper-checker with a context deadline,
// parses the output, and writes valid proxies to a file for mubeng.
func RunHarvest(ctx context.Context, cfg HarvestConfig) (*HarvestResult, error) {
	start := time.Now()

	// Check if proxy-scraper-checker is available
	binPath, err := exec.LookPath("proxy-scraper-checker")
	if err != nil {
		return nil, fmt.Errorf("proxy-scraper-checker not found: install via 'chaathan setup' or download from https://github.com/monosans/proxy-scraper-checker")
	}

	// Create working directory
	workDir := filepath.Join(cfg.OutputDir, "proxy_scraping_work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create proxy scraping work dir: %w", err)
	}

	// Generate config.toml for proxy-scraper-checker
	checkURL := fmt.Sprintf("https://%s", cfg.Domain)
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}

	configContent := generateConfig(checkURL, maxConcurrent, workDir, cfg.ProxyTypes)
	configPath := filepath.Join(workDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return nil, fmt.Errorf("cannot write proxy scraping config: %w", err)
	}

	// Apply timeout
	timeoutMin := cfg.TimeoutMin
	if timeoutMin <= 0 {
		timeoutMin = 10
	}
	harvestCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMin)*time.Minute)
	defer cancel()

	// Run proxy-scraper-checker
	logger.SubStep("Running proxy-scraper-checker (binary: %s)", binPath)
	logger.FileDebug("proxy-scraper-checker config: %s", configPath)

	cmd := exec.Command(binPath)
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Force non-TUI mode: the pre-built binary has ratatui TUI compiled in.
	// When stdout is piped to a buffer, ratatui/crossterm hangs on terminal
	// init because there's no real TTY. Setting TERM=dumb and redirecting
	// stdout/stderr to a file makes is_terminal() return false, so the tool
	// falls back to its non-interactive logging mode.
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PROXY_SCRAPER_CHECKER_CONFIG=%s", configPath),
		"TERM=dumb",
		"NO_COLOR=1",
	)

	// Redirect stdout/stderr to a log file instead of piping to a buffer.
	// Piping creates non-TTY file descriptors, but ratatui may still attempt
	// raw mode on pipes. A file redirect is cleaner and lets us read logs after.
	logPath := filepath.Join(workDir, "proxy-scraper-checker.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("cannot create proxy-scraper-checker log file: %w", err)
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Close stdin so the tool cannot read terminal input.
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var runErr error
	select {
	case runErr = <-done:
		if runErr != nil && ctx.Err() != nil {
			return nil, fmt.Errorf("cancelled: %w", ctx.Err())
		}
	case <-harvestCtx.Done():
		if ctx.Err() != nil {
			// Parent context cancelled (user skip or Ctrl+C)
			logger.Info("proxy-scraper-checker cancelled — stopping...")
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			return nil, fmt.Errorf("cancelled: %w", ctx.Err())
		}

		// harvestCtx reached timeout, send SIGINT to allow proxy-scraper-checker to exit cleanly and flush outfile
		logger.Info("proxy-scraper-checker reached timeout — stopping gracefully to save partial results...")
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)

		select {
		case runErr = <-done:
			logger.Info("proxy-scraper-checker stopped gracefully")
		case <-time.After(5 * time.Second):
			logger.Warning("proxy-scraper-checker did not stop gracefully — killing...")
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			runErr = <-done
		}
	}

	if runErr != nil {
		logger.Warning("proxy-scraper-checker exited with error: %v", runErr)
		// Close and read the log file for debug output.
		logFile.Close()
		if logData, readErr := os.ReadFile(logPath); readErr == nil {
			logger.FileDebug("proxy-scraper-checker output: %s", string(logData))
		}
	}

	// Parse output — proxy-scraper-checker writes to out/ subdirectory
	outDir := filepath.Join(workDir, "out")
	proxies, err := parseProxyOutput(outDir, cfg.ProxyTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy output: %w", err)
	}

	if len(proxies) == 0 {
		return &HarvestResult{
			Duration: time.Since(start),
		}, nil
	}

	// Sort by response time (fastest first)
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].ResponseTime < proxies[j].ResponseTime
	})

	// Write proxy pool file for mubeng
	proxyListFile := filepath.Join(cfg.OutputDir, "proxy_pool.txt")
	var proxyLines []string
	for _, p := range proxies {
		url := formatProxyURL(p)
		proxyLines = append(proxyLines, url)
	}

	if err := os.WriteFile(proxyListFile, []byte(strings.Join(proxyLines, "\n")+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("cannot write proxy pool file: %w", err)
	}

	// Count total scraped (approximate from txt files)
	totalScraped := countScrapedProxies(outDir)

	return &HarvestResult{
		ProxyListFile: proxyListFile,
		TotalScraped:  totalScraped,
		TotalValid:    len(proxies),
		AllValid:      proxyLines,
		Duration:      time.Since(start),
	}, nil
}

// contains checks if a string is present in a slice (case-insensitive).
// If the slice is empty, it returns true to enable all protocols by default.
func contains(slice []string, val string) bool {
	if len(slice) == 0 {
		return true
	}
	for _, item := range slice {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}

// generateConfig creates a config.toml for proxy-scraper-checker.
func generateConfig(checkURL string, maxConcurrent int, outputDir string, proxyTypes []string) string {
	outPath := filepath.Join(outputDir, "out")
	// Use forward slashes for TOML path compatibility
	outPath = filepath.ToSlash(outPath)

	httpEnabled := contains(proxyTypes, "http")
	socks4Enabled := contains(proxyTypes, "socks4")
	socks5Enabled := contains(proxyTypes, "socks5")

	return fmt.Sprintf(`#:schema ./config-schema.json

debug = false

[output]
path = "%s"
sort_by_speed = true

[output.txt]
enabled = true

[output.json]
enabled = true
include_asn = false
include_geolocation = false

[checking]
check_url = "%s"
max_concurrent_checks = %d
timeout = 5.0
connect_timeout = 2.0
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"

[scraping]
max_proxies_per_source = 100000
timeout = 5.0
connect_timeout = 2.0
proxy = ""
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"

[scraping.http]
enabled = %t
urls = [
  "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http",
  "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=https",
  "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
  "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
  "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
  "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
  "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
]

[scraping.socks4]
enabled = %t
urls = [
  "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4",
  "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
  "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
  "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt",
  "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.txt",
]

[scraping.socks5]
enabled = %t
urls = [
  "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5",
  "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
  "https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt",
  "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
  "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt",
  "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt",
]
`, outPath, checkURL, maxConcurrent, httpEnabled, socks4Enabled, socks5Enabled)
}

// parseProxyOutput reads the JSON output files from proxy-scraper-checker.
// It looks for files like http.json, socks4.json, socks5.json in the output dir.
func parseProxyOutput(outDir string, preferredTypes []string) ([]proxyEntry, error) {
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		return nil, nil // no output yet
	}

	var allProxies []proxyEntry

	// Try JSON files first (structured output)
	jsonFiles := []string{"socks5.json", "http.json", "socks4.json"}
	for _, fname := range jsonFiles {
		fpath := filepath.Join(outDir, fname)
		proxies, err := parseJSONProxyFile(fpath)
		if err != nil {
			logger.FileDebug("could not parse %s: %v", fname, err)
			continue
		}
		allProxies = append(allProxies, proxies...)
	}

	// If JSON parsing yielded results, return them
	if len(allProxies) > 0 {
		return allProxies, nil
	}

	// Fall back to plain text files
	txtFiles := []string{"socks5.txt", "http.txt", "socks4.txt"}
	protocols := []string{"socks5", "http", "socks4"}
	for i, fname := range txtFiles {
		fpath := filepath.Join(outDir, fname)
		proxies, err := parseTxtProxyFile(fpath, protocols[i])
		if err != nil {
			continue
		}
		allProxies = append(allProxies, proxies...)
	}

	return allProxies, nil
}

// parseJSONProxyFile parses a single JSON proxy output file.
// The format may be an array of objects or newline-delimited JSON.
func parseJSONProxyFile(path string) ([]proxyEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	// Try as JSON array first
	var proxies []proxyEntry
	if err := json.Unmarshal(data, &proxies); err == nil {
		return proxies, nil
	}

	// Try as newline-delimited JSON
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var p proxyEntry
		if err := json.Unmarshal([]byte(line), &p); err == nil {
			proxies = append(proxies, p)
		}
	}

	return proxies, nil
}

// parseTxtProxyFile parses a plain text proxy file (one proxy per line).
func parseTxtProxyFile(path string, protocol string) ([]proxyEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var proxies []proxyEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Line format: host:port or protocol://host:port
		proxy := line
		if !strings.Contains(proxy, "://") {
			proxy = protocol + "://" + proxy
		}
		proxies = append(proxies, proxyEntry{
			Protocol: protocol,
			Host:     proxy, // store full URL for simplicity
		})
	}
	return proxies, nil
}

// formatProxyURL formats a proxyEntry as a URL string for mubeng.
func formatProxyURL(p proxyEntry) string {
	// If Host already contains ://, it's a full URL from txt parsing
	if strings.Contains(p.Host, "://") {
		return p.Host
	}

	protocol := strings.ToLower(p.Protocol)
	if protocol == "" {
		protocol = "http"
	}

	auth := ""
	if p.Username != "" {
		auth = p.Username
		if p.Password != "" {
			auth += ":" + p.Password
		}
		auth += "@"
	}

	return fmt.Sprintf("%s://%s%s:%d", protocol, auth, p.Host, p.Port)
}

// countScrapedProxies counts approximate total proxies scraped by
// looking at all txt files in the output directory.
func countScrapedProxies(outDir string) int {
	total := 0
	for _, fname := range []string{"socks5.txt", "http.txt", "socks4.txt"} {
		fpath := filepath.Join(outDir, fname)
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				total++
			}
		}
		f.Close()
	}
	return total
}
