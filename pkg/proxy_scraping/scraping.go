// Package proxy_scraping wraps proxy-scraper-checker (Rust) for proxy scraping
// and mubeng (Go) for IP rotation. It provides a clean interface for the
// wildcard workflow to automatically obtain and rotate free proxies.
package proxy_scraping

import (
	"bufio"
	"bytes"
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

	configContent := generateConfig(checkURL, maxConcurrent, workDir)
	configPath := filepath.Join(cfg.OutputDir, "proxy_scraping_config.toml")
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

	cmd := exec.Command(binPath, "--config", configPath)
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Capture output for logging
	var stdoutStderr bytes.Buffer
	cmd.Stdout = &stdoutStderr
	cmd.Stderr = &stdoutStderr

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
		logger.FileDebug("proxy-scraper-checker output: %s", stdoutStderr.String())
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

// generateConfig creates a config.toml for proxy-scraper-checker.
func generateConfig(checkURL string, maxConcurrent int, outputDir string) string {
	outPath := filepath.Join(outputDir, "out")
	// Use forward slashes for TOML path compatibility
	outPath = filepath.ToSlash(outPath)

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
timeout = 10.0
connect_timeout = 5.0
`, outPath, checkURL, maxConcurrent)
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
