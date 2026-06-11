// Package proxy_scraping uses proxybroker2 (CLI: proxybroker) for scraping
// and checking proxies, and mubeng for IP rotation.
//
// Pipeline:
//   1. proxybroker find  — scrapes public sources, checks generic connectivity
//   2. mubeng --check    — filters pool against the actual target domain (WAF check)
//   3. mubeng --rotate   — starts rotating proxy server for scan tools
//
// Install: pip install -U git+https://github.com/bluet/proxybroker2.git
package proxy_scraping

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// HarvestConfig controls the proxybroker + mubeng --check invocation.
type HarvestConfig struct {
	Domain     string   // target domain — used for mubeng WAF check (e.g. "pinterest.com")
	TimeoutMin int      // max total runtime in minutes (default: 10)
	ProxyTypes []string // preferred types: ["SOCKS5","HTTP","SOCKS4"]
	MaxProxies int      // max valid proxies to collect (default: 100)
	OutputDir  string   // working directory for output files
}

// HarvestResult holds the output of a proxy scraping run.
type HarvestResult struct {
	ProxyListFile  string        // path to proxy_pool_checked.txt (WAF-filtered)
	TotalScraped   int           // proxies collected by proxybroker
	TotalValid     int           // proxies that survived mubeng WAF check
	AllValid       []string      // all surviving proxy URLs
	Duration       time.Duration // wall-clock duration of the full harvest
}

// RunHarvest runs the two-phase proxy pipeline:
//  1. proxybroker find  → raw valid proxies
//  2. mubeng --check    → WAF-filtered proxies against cfg.Domain
func RunHarvest(ctx context.Context, cfg HarvestConfig) (*HarvestResult, error) {
	start := time.Now()

	// ── Check binaries ───────────────────────────────────────
	binPath, err := exec.LookPath("proxybroker")
	if err != nil {
		return nil, fmt.Errorf("proxybroker not found: install via 'chaathan setup' or run: pip install -U git+https://github.com/bluet/proxybroker2.git")
	}

	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create proxy output dir: %w", err)
	}

	rawFile     := filepath.Join(cfg.OutputDir, "proxy_pool.txt")
	checkedFile := filepath.Join(cfg.OutputDir, "proxy_pool_checked.txt")

	types := resolveProxyTypes(cfg.ProxyTypes)
	limit := cfg.MaxProxies
	if limit <= 0 {
		limit = 100
	}
	timeoutMin := cfg.TimeoutMin
	if timeoutMin <= 0 {
		timeoutMin = 10
	}

	// Reserve 70% of the timeout for proxybroker, 30% for mubeng --check
	brokerMin := int(float64(timeoutMin) * 0.7)
	if brokerMin < 1 {
		brokerMin = 1
	}
	checkMin := timeoutMin - brokerMin
	if checkMin < 1 {
		checkMin = 1
	}

	// ── Phase 1: proxybroker find ────────────────────────────
	logger.SubStep("Running proxybroker find (binary: %s)", binPath)

	brokerCtx, brokerCancel := context.WithTimeout(ctx, time.Duration(brokerMin)*time.Minute)
	defer brokerCancel()

	args := []string{
		"--max-conn", "200",
		"find",
		"--outfile", rawFile,
		"--limit", fmt.Sprintf("%d", limit),
		"--strict",
	}
	if len(types) > 0 {
		args = append(args, "--types")
		args = append(args, types...)
	}
	logger.FileDebug("proxybroker args: %v", args)

	cmd := exec.CommandContext(brokerCtx, binPath, args...)
	cmd.Dir = cfg.OutputDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if brokerCtx.Err() == context.DeadlineExceeded {
			logger.Info("proxybroker reached timeout — using partial results")
		} else if ctx.Err() != nil {
			return nil, fmt.Errorf("cancelled: %w", ctx.Err())
		} else {
			logger.Warning("proxybroker exited with error: %v", err)
			logger.FileDebug("proxybroker output: %s", string(output))
		}
	}

	rawProxies, err := parseProxyFile(rawFile, types)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxybroker output: %w", err)
	}
	if len(rawProxies) == 0 {
		return &HarvestResult{Duration: time.Since(start)}, nil
	}
	logger.Info("proxybroker found %d working proxies — running WAF check against %s...", len(rawProxies), cfg.Domain)

	// ── Phase 2: mubeng --check against target domain ────────
	checkCtx, checkCancel := context.WithTimeout(ctx, time.Duration(checkMin)*time.Minute)
	defer checkCancel()

	checkedProxies, err := filterWithMubeng(checkCtx, rawFile, checkedFile, cfg.Domain)
	if err != nil {
		// Non-fatal — fall back to raw proxybroker results
		logger.Warning("mubeng WAF check failed (%v) — using unfiltered proxy pool", err)
		checkedProxies = rawProxies
		checkedFile = rawFile
	}

	if len(checkedProxies) == 0 {
		logger.Warning("mubeng WAF check: all proxies blocked by target — using unfiltered pool")
		checkedProxies = rawProxies
		checkedFile = rawFile
	}

	logger.Info("WAF check: %d/%d proxies passed (not blocked by %s)", len(checkedProxies), len(rawProxies), cfg.Domain)

	return &HarvestResult{
		ProxyListFile: checkedFile,
		TotalScraped:  len(rawProxies),
		TotalValid:    len(checkedProxies),
		AllValid:      checkedProxies,
		Duration:      time.Since(start),
	}, nil
}

// filterWithMubeng runs `mubeng --check` against the target domain to drop
// proxies that are blocked by WAF/firewall on the actual target.
//
// Command: mubeng -f rawFile --check -u https://domain -o outFile --output-format "{{proxy}}"
func filterWithMubeng(ctx context.Context, rawFile, outFile, domain string) ([]string, error) {
	mubengPath, err := exec.LookPath("mubeng")
	if err != nil {
		return nil, fmt.Errorf("mubeng not found")
	}

	checkURL := "https://" + domain
	if strings.HasPrefix(domain, "http") {
		checkURL = domain
	}

	args := []string{
		"-f", rawFile,
		"--check",
		"-u", checkURL,
		"-o", outFile,
		"--output-format", "{{proxy}}",
		"-t", "15s", // per-proxy timeout
	}
	logger.FileDebug("mubeng --check args: %v", args)

	cmd := exec.CommandContext(ctx, mubengPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Info("mubeng --check reached timeout — using partial results")
		} else {
			return nil, fmt.Errorf("mubeng --check failed: %v\noutput: %s", err, string(output))
		}
	}

	return parseProxyFile(outFile, nil)
}

// resolveProxyTypes maps internal type names to proxybroker type flags.
// proxybroker accepts: HTTP, HTTPS, SOCKS4, SOCKS5
func resolveProxyTypes(types []string) []string {
	if len(types) == 0 {
		return []string{"SOCKS5", "HTTP"}
	}
	var out []string
	for _, t := range types {
		switch strings.ToLower(t) {
		case "socks5":
			out = append(out, "SOCKS5")
		case "socks4":
			out = append(out, "SOCKS4")
		case "https":
			out = append(out, "HTTPS")
		default:
			out = append(out, "HTTP")
		}
	}
	return out
}

// parseProxyFile reads a proxy list file — one proxy per line.
// Format: "scheme://host:port" or plain "host:port".
func parseProxyFile(path string, types []string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var proxies []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Ensure scheme prefix for mubeng compatibility
		if !strings.Contains(line, "://") {
			scheme := "socks5"
			if len(types) > 0 {
				scheme = strings.ToLower(types[0])
			}
			line = scheme + "://" + line
		}
		proxies = append(proxies, line)
	}
	return proxies, scanner.Err()
}
