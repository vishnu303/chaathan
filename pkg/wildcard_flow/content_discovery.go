// Phase 3 — Content Discovery (Steps 11–17)
//
// Discovers URLs, endpoints, and directories from live hosts.
// Wayback/GAU run here (not in Phase 1) so URLs are collected
// only for validated live hosts.
//
//  11. Historical URL Discovery (Waybackurls + GAU) [Parallel]
//  12. Web Crawling (Katana + GoSpider) [Parallel, Optional]
//  13. JavaScript Analysis — Endpoint Discovery (GoLinkFinder)
//  14. HTTP Parameter Discovery (Arjun) [Optional]
//  15. URL Consolidation & Live Check (httpx) + ROI metadata
//  16. JS Secret Scan (gf JS + Secrets)
//  17. Directory Fuzzing (ffuf) [Optional — requires --wordlist]
package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/metadata"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 11 — Historical URL Discovery (Waybackurls + GAU)
// ─────────────────────────────────────────────────────────────

// stepURLDiscovery runs Waybackurls and GAU in parallel on the target domain.
// Returns true if the scan should be cancelled.
func stepURLDiscovery(c *Ctx) bool {
	if c.State.IsStepCompleted("url_discovery") {
		logger.StepHeader("Step 11: Historical URL Discovery [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.StepHeader("Step 11: Historical URL Discovery")

	// Track individual tool results so we can detect total failure.
	var waybackOK, gauOK bool
	var resultMu sync.Mutex

	err := runWithSkip(c, "url discovery", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Waybackurls")
			logger.FileDebug("waybackurls input: domain=%s out=%s", c.Domain, c.F.WaybackOut)
			if err := c.Tb.RunWaybackurls(sCtx, c.Domain, c.F.WaybackOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("Waybackurls failed: %v", err)
				}
				logger.FileDebug("waybackurls failed: %v", err)
			} else {
				resultMu.Lock()
				waybackOK = true
				resultMu.Unlock()
				logger.SubStep("[Done] Waybackurls")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.WaybackOut, "waybackurls")
					logger.Info("  Found %d URLs", count)
					logger.FileDebug("waybackurls output: %d URLs -> %s", count, c.F.WaybackOut)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GAU")
			logger.FileDebug("gau input: domain=%s out=%s", c.Domain, c.F.GauOut)
			if err := c.Tb.RunGau(sCtx, c.Domain, c.F.GauOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("GAU failed: %v", err)
				}
				logger.FileDebug("gau failed: %v", err)
			} else {
				resultMu.Lock()
				gauOK = true
				resultMu.Unlock()
				logger.SubStep("[Done] GAU")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.GauOut, "gau")
					logger.Info("  Found %d URLs", count)
					logger.FileDebug("gau output: %d URLs -> %s", count, c.F.GauOut)
				}
			}
		}()

		wg.Wait()
		return nil
	})

	if err == ErrToolSkipped {
		// Skipped by user — log partial results from any tool that wrote output before the skip
		if c.ScanID > 0 {
			if utils.FileExists(c.F.WaybackOut) {
				if count, _ := utils.ParseURLsFile(c.ScanID, c.F.WaybackOut, "waybackurls"); count > 0 {
					logger.Info("  Waybackurls partial: %d URLs", count)
				}
			}
			if utils.FileExists(c.F.GauOut) {
				if count, _ := utils.ParseURLsFile(c.ScanID, c.F.GauOut, "gau"); count > 0 {
					logger.Info("  GAU partial: %d URLs", count)
				}
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "url_discovery")
	} else if !waybackOK && !gauOK {
		c.StateMgr.MarkStepFailed(c.State, "url_discovery", fmt.Errorf("both Waybackurls and GAU failed"))
	} else {
		c.StateMgr.MarkStepComplete(c.State, "url_discovery")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 12 — Web Crawling (Katana + GoSpider)
// ─────────────────────────────────────────────────────────────

// stepWebCrawling runs Katana and GoSpider in parallel.
// Returns true if the scan should be cancelled.
func stepWebCrawling(c *Ctx) bool {
	if c.State.IsStepCompleted("web_crawling") {
		logger.StepHeader("Step 12: Web Crawling [RESUMED — skipping]")
		return c.cancelled()
	} else if c.SkipCrawl {
		logger.StepHeader("Step 12: Skipping Web Crawling (--skip-crawl)")
		c.StateMgr.MarkStepComplete(c.State, "web_crawling")
		return c.cancelled()
	}

	logger.StepHeader("Step 12: Web Crawling")
	var katanaOK, gospiderOK bool
	var crawlMu sync.Mutex

	liveHostCount, _ := utils.CountFileLines(c.F.HttpxLiveHosts)
	logger.FileDebug("web_crawling input: %s (%d live hosts)", c.F.HttpxLiveHosts, liveHostCount)

	err := runWithSkip(c, "web crawling", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Katana")
			logger.FileDebug("katana input: %s out=%s", c.F.HttpxLiveHosts, c.F.KatanaOut)
			if err := c.Tb.RunKatana(sCtx, c.F.HttpxLiveHosts, c.F.KatanaOut); err != nil {
				if sCtx.Err() == nil {
					logger.Warning("Katana failed: %v", err)
				}
			} else {
				crawlMu.Lock()
				katanaOK = true
				crawlMu.Unlock()
				logger.SubStep("[Done] Katana")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.KatanaOut, "katana")
					logger.Info("  Katana found %d URLs", count)
					logger.FileDebug("katana output: %d URLs -> %s", count, c.F.KatanaOut)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GoSpider")
			logger.FileDebug("gospider input: %s out=%s", c.F.HttpxLiveHosts, c.F.GospiderOut)
			if err := c.Tb.RunGoSpider(sCtx, c.F.HttpxLiveHosts, c.F.GospiderOut); err != nil {
				if sCtx.Err() == nil {
					logger.Warning("GoSpider failed: %v", err)
				}
			} else {
				crawlMu.Lock()
				gospiderOK = true
				crawlMu.Unlock()
				logger.SubStep("[Done] GoSpider")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.GospiderOut, "gospider")
					logger.Info("  GoSpider found %d URLs", count)
					logger.FileDebug("gospider output: %d URLs -> %s", count, c.F.GospiderOut)
				}
			}
		}()

		wg.Wait()
		return nil
	})

	// Log partial results when skipped — tools may have written output before cancel
	if err == ErrToolSkipped && c.ScanID > 0 {
		if utils.FileExists(c.F.KatanaOut) {
			if count, _ := utils.CountFileLines(c.F.KatanaOut); count > 0 {
				logger.Info("  Katana partial: %d URLs", count)
			}
		}
		if utils.FileExists(c.F.GospiderOut) {
			if count, _ := utils.CountFileLines(c.F.GospiderOut); count > 0 {
				logger.Info("  GoSpider partial: %d URLs", count)
			}
		}
	}

	// Mark step based on outcome: complete if at least one crawler succeeded
	// or the step was skipped; failed only if both crawlers failed.
	if err == ErrToolSkipped || katanaOK || gospiderOK {
		c.StateMgr.MarkStepComplete(c.State, "web_crawling")
	} else {
		c.StateMgr.MarkStepFailed(c.State, "web_crawling", fmt.Errorf("both Katana and GoSpider failed"))
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 13 — JavaScript Analysis (GoLinkFinder)
// ─────────────────────────────────────────────────────────────

// stepJSAnalysis extracts endpoints from JavaScript files with GoLinkFinder.
// Returns true if the scan should be cancelled.
func stepJSAnalysis(c *Ctx) bool {
	if c.State.IsStepCompleted("js_analysis") {
		logger.StepHeader("Step 13: JavaScript Analysis [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.StepHeader("Step 13: JavaScript Analysis")
	logger.SubStep("Running GoLinkFinder...")

	if err := runWithSkip(c, "GoLinkFinder", func(sCtx context.Context) error {
		return c.Tb.RunGoLinkFinder(sCtx, "https://"+c.Domain, c.F.GoLinkFinderOut)
	}); err != nil {
		if err == ErrToolSkipped {
			// Skipped steps are still marked complete so resume skips them
			c.StateMgr.MarkStepComplete(c.State, "js_analysis")
		} else {
			c.StateMgr.MarkStepFailed(c.State, "js_analysis", err)
			logger.Warning("GoLinkFinder failed: %v", err)
		}
	} else {
		if c.ScanID > 0 {
			count, _ := utils.ParseEndpointsFile(c.ScanID, c.F.GoLinkFinderOut, "golinkfinder")
			logger.Info("  Found %d endpoints", count)
		}
		c.StateMgr.MarkStepComplete(c.State, "js_analysis")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 14 — HTTP Parameter Discovery (Arjun)
// ─────────────────────────────────────────────────────────────

// stepParamDiscovery discovers HTTP parameters with Arjun (Step 14).
// After a successful run it converts discovered params into parameterized URLs
// (written to ArjunURLsOut) so they flow into Step 15 consolidation and
// downstream scanners (Nuclei/Dalfox).
// Returns true if the scan should be cancelled.
func stepParamDiscovery(c *Ctx) bool {
	if c.State.IsStepCompleted("param_discovery") {
		logger.StepHeader("Step 14: HTTP Parameter Discovery (Arjun) [RESUMED — skipping]")
		return c.cancelled()
	} else if !c.SkipArjun {
		logger.StepHeader("Step 14: HTTP Parameter Discovery (Arjun)")
		logger.SubStep("Running Arjun on live hosts...")

		// Validate parameters wordlist if configured (same pattern as ffuf/shuffledns).
		// If the file doesn't exist, run Arjun without -w so it uses its built-in default.
		paramWordlist := ""
		if c.Cfg != nil && c.Cfg.General.Wordlists.Parameters != "" {
			if utils.FileExists(c.Cfg.General.Wordlists.Parameters) {
				paramWordlist = c.Cfg.General.Wordlists.Parameters
			} else {
				logger.Warning("Arjun parameters wordlist not found: %s", c.Cfg.General.Wordlists.Parameters)
				logger.Info("  Install seclists (apt install seclists / pacman -S seclists) or set a valid wordlist in config.yaml")
				logger.Info("  Falling back to Arjun's built-in parameter list")
				logger.FileDebug("arjun: configured wordlist does not exist at %s — using built-in default", c.Cfg.General.Wordlists.Parameters)
			}
		}

		if err := runWithSkip(c, "arjun", func(sCtx context.Context) error {
			return c.Tb.RunArjunWithWordlist(sCtx, c.F.HttpxLiveHosts, c.F.ArjunOut, paramWordlist)
		}); err != nil {
			if err == ErrToolSkipped {
				// User-skipped counts as intentional — mark complete so resume skips it too.
				c.StateMgr.MarkStepComplete(c.State, "param_discovery")
			} else {
				c.StateMgr.MarkStepFailed(c.State, "param_discovery", err)
				logger.Warning("Arjun failed: %v", err)
				// Do NOT fall through to MarkStepComplete — failure must persist for resume.
			}
		} else {
			logger.SubStep("[Done] Arjun parameter discovery")
			// Convert Arjun JSON output into parameterized URLs for downstream use
			if count := convertArjunToURLs(c.F.ArjunOut, c.F.ArjunURLsOut); count > 0 {
				logger.Info("  Generated %d parameterized URLs from Arjun output", count)
			}
			// Store discovered parameter counts for ROI scoring
			if c.ScanID > 0 {
				if stored := storeArjunParamCounts(c.ScanID, c.F.ArjunOut); stored > 0 {
					logger.Info("  Stored Arjun param counts for %d URLs", stored)
				}
			}
			c.StateMgr.MarkStepComplete(c.State, "param_discovery")
		}
	} else {
		logger.StepHeader("Step 14: Skipping Arjun (--skip-arjun)")
		c.StateMgr.MarkStepComplete(c.State, "param_discovery")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 15 — URL Consolidation & Live Check
// ─────────────────────────────────────────────────────────────

// stepURLConsolidation merges all URL sources, live-checks them with Httpx,
// and enriches ROI metadata for high-value targets.
// Returns true if the scan should be cancelled.
func stepURLConsolidation(c *Ctx) bool {
	if c.State.IsStepCompleted("url_consolidation") {
		logger.StepHeader("Step 15: URL Consolidation & Live Check [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.StepHeader("Step 15: URL Consolidation & Live Check")

	sources := c.urlSources()
	logger.SubStep("Merging URLs from %d sources...", len(sources))
	logger.FileDebug("url_consolidation sources: %v", sources)
	if err := utils.MergeAndDeduplicate(sources, c.F.AllURLsRaw); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "url_consolidation", err)
		logger.Warning("URL merge failed: %v", err)
	} else {
		// Sanitize: unescape \uXXXX sequences, strip non-URL lines (GoSpider tags,
		// relative paths from GoLinkFinder), and re-deduplicate.
		if err := utils.SanitizeURLFile(c.F.AllURLsRaw); err != nil {
			logger.Warning("URL sanitization failed: %v", err)
		}
		rawCount, _ := utils.CountFileLines(c.F.AllURLsRaw)
		logger.Info("  Merged %d unique URLs", rawCount)
		logger.FileDebug("url_consolidation merged %d raw URLs -> %s", rawCount, c.F.AllURLsRaw)
	}

	// Live-check all URLs with httpx
	logger.SubStep("Running httpx to live-check all URLs...")
	rawCount2, _ := utils.CountFileLines(c.F.AllURLsRaw)
	logger.FileDebug("httpx_url_check input: %s (%d URLs) out=%s", c.F.AllURLsRaw, rawCount2, c.F.AllURLsLive)
	if err := runWithSkip(c, "httpx (URL check)", func(sCtx context.Context) error {
		return c.Tb.RunHttpxURLCheck(sCtx, c.F.AllURLsRaw, c.F.AllURLsLive)
	}); err != nil {
		if err != ErrToolSkipped {
			c.StateMgr.MarkStepFailed(c.State, "url_consolidation", err)
			logger.Warning("URL live-check failed: %v", err)
		}
		// Fallback: use raw URLs if live-check fails/is skipped
		if !utils.FileExists(c.F.AllURLsLive) {
			logger.Info("  Using raw URLs as fallback")
			copyFile(c.F.AllURLsRaw, c.F.AllURLsLive)
		}
	} else {
		liveCount, _ := utils.CountFileLines(c.F.AllURLsLive)
		logger.Success("  %d live URLs confirmed", liveCount)
		logger.FileDebug("httpx_url_check output: %d live URLs -> %s", liveCount, c.F.AllURLsLive)
	}

	// Persist live URLs into DB so GetScanStats / query commands reflect reality.
	// This is intentionally after the skip/fallback block so both paths populate the DB.
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		if dbCount, err := utils.ParseLiveURLsFile(c.ScanID, c.F.AllURLsLive, "httpx-url-check"); err != nil {
			logger.Warning("Failed to persist live URLs to DB: %v", err)
		} else if dbCount > 0 {
			logger.Info("  Stored %d live URLs in database", dbCount)
		}
	}

	// ROI metadata enrichment
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		metaTargetCount := collectROIMetadataTargetsFromFile(c.F.AllURLsLive, c.F.ROIMetadataTargets, 3, 150)
		if metaTargetCount > 0 {
			logger.SubStep("Collecting lightweight metadata for %d high-value URLs...", metaTargetCount)
			metaTargets := loadLineSlice(c.F.ROIMetadataTargets, 150)
			if count, err := metadata.CollectURLMetadata(c.ScanID, metaTargets, c.Proxy); err != nil {
				logger.Warning("URL metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Info("  Stored path metadata for %d ROI candidate URLs", count)
			}
		}
	}

	c.StateMgr.MarkStepComplete(c.State, "url_consolidation")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 16 — JS Secret Scan (gf JS + Secrets)
// ─────────────────────────────────────────────────────────────

// stepJSSecretScan downloads a capped set of JS files, scans their content
// with installed gf JS/secret patterns, and writes merged findings.
type gfPatternFile struct {
	Pattern  string   `json:"pattern"`
	Patterns []string `json:"patterns"`
	Flags    string   `json:"flags"`
}

// loadGFPatterns reads patterns from ~/.gf/ and compiles them to regular expressions.
func loadGFPatterns(allowlist map[string]bool) (map[string][]*regexp.Regexp, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	gfDir := filepath.Join(home, ".gf")
	entries, err := os.ReadDir(gfDir)
	if err != nil {
		return nil, err
	}

	compiledPatterns := make(map[string][]*regexp.Regexp)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if allowlist != nil && !allowlist[name] {
			continue
		}

		filePath := filepath.Join(gfDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var pf gfPatternFile
		if err := json.Unmarshal(data, &pf); err != nil {
			continue
		}

		var rawPatterns []string
		if pf.Pattern != "" {
			rawPatterns = append(rawPatterns, pf.Pattern)
		}
		rawPatterns = append(rawPatterns, pf.Patterns...)

		// Determine Go regex flags
		prefix := ""
		caseInsensitive := strings.Contains(pf.Flags, "i")
		multiline := strings.Contains(pf.Flags, "m")
		if caseInsensitive || multiline {
			prefix = "(?"
			if caseInsensitive {
				prefix += "i"
			}
			if multiline {
				prefix += "m"
			}
			prefix += ")"
		}

		var regexes []*regexp.Regexp
		for _, raw := range rawPatterns {
			re, err := regexp.Compile(prefix + raw)
			if err != nil {
				continue
			}
			regexes = append(regexes, re)
		}
		if len(regexes) > 0 {
			compiledPatterns[name] = regexes
		}
	}
	return compiledPatterns, nil
}

// getFallbackGFPatterns returns hardcoded regexes for offline execution or when ~/.gf is empty.
func getFallbackGFPatterns(allowlist map[string]bool) map[string][]*regexp.Regexp {
	fallbacks := map[string]string{
		"aws-keys": `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
		"api-keys": `(?i)(api_key|apikey|secret|token|auth|password|key|credentials)[=:]["'][a-zA-Z0-9_\-\.\~]{10,80}["']`,
		"jwt":      `eyJhbGciOi`,
		"firebase": `firebaseio\.com`,
		"github":   `(?i)github_token[=:]["'][a-zA-Z0-9]{35,40}["']`,
		"domxss":   `\.(innerHTML|outerHTML|location|href|write|writeln|src|location\.href)`,
		"js-sinks": `(eval|setTimeout|setInterval|Function)\(`,
		"execs":    `exec\(`,
	}

	compiled := make(map[string][]*regexp.Regexp)
	for name, pattern := range fallbacks {
		if allowlist != nil && !allowlist[name] {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled[name] = []*regexp.Regexp{re}
		}
	}
	return compiled
}

// localUserAgents contains common, high-frequency browser User-Agent strings.
var localUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
}

// runInMemoryJSSecretScan concurrently downloads JS files and runs regex matches on them.
func runInMemoryJSSecretScan(ctx context.Context, c *Ctx, urls []string, jsPatterns, secretPatterns map[string][]*regexp.Regexp) (int, int, int64, []string, error) {
	threads := 10
	if c.Cfg != nil && c.Cfg.Tools.Httpx.Threads > 0 {
		threads = c.Cfg.Tools.Httpx.Threads / 5
		if threads < 5 {
			threads = 5
		}
		if threads > 15 {
			threads = 15
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     utils.ModernBrowserTLSConfig(),
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
	if c.Proxy != "" {
		if proxyURL, err := url.Parse(c.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	// Dynamic rate limiting setup (bound to GlobalRPS)
	var rateLimiter *time.Ticker
	if c.Tb.RateLimits != nil && c.Tb.RateLimits.GlobalRPS > 0 {
		interval := time.Second / time.Duration(c.Tb.RateLimits.GlobalRPS)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	jobs := make(chan string, len(urls))
	for _, u := range urls {
		jobs <- u
	}
	close(jobs)

	var wg sync.WaitGroup
	var mu sync.Mutex

	var jsMatches []string
	var secretMatches []string
	var totalBytes int64
	seenHostsWithSecrets := make(map[string]bool)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if rateLimiter != nil {
					select {
					case <-ctx.Done():
						return
					case <-rateLimiter.C:
					}
				}

				req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
				if err != nil {
					continue
				}

				// User agent setup
				ua := localUserAgents[rand.Intn(len(localUserAgents))]
				if c.Tb.General != nil && c.Tb.General.UserAgent != "" {
					ua = c.Tb.General.UserAgent
				}
				req.Header.Set("User-Agent", ua)

				// Inject Custom Cookies
				if c.Tb.CustomCookie != "" {
					req.Header.Set("Cookie", c.Tb.CustomCookie)
				}
				// Inject Custom Headers
				for _, h := range c.Tb.CustomHeaders {
					parts := strings.SplitN(h, ":", 2)
					if len(parts) == 2 {
						req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
					}
				}

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				// Max 10MB per file to protect memory
				body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
				resp.Body.Close()
				if err != nil {
					continue
				}

				mu.Lock()
				totalBytes += int64(len(body))
				mu.Unlock()

				lines := strings.Split(string(body), "\n")
				var localJSMatches []string
				var localSecretMatches []string
				foundSecret := false

				for _, line := range lines {
					lineTrimmed := strings.TrimSpace(line)
					if lineTrimmed == "" {
						continue
					}

					// Scan JS patterns
					for name, regexes := range jsPatterns {
						for _, re := range regexes {
							if re.MatchString(lineTrimmed) {
								matchLine := fmt.Sprintf("[%s] [%s] %s", target, name, lineTrimmed)
								localJSMatches = append(localJSMatches, matchLine)
								break
							}
						}
					}

					// Scan Secret patterns
					for name, regexes := range secretPatterns {
						for _, re := range regexes {
							if re.MatchString(lineTrimmed) {
								matchLine := fmt.Sprintf("[%s] [%s] %s", target, name, lineTrimmed)
								localSecretMatches = append(localSecretMatches, matchLine)
								foundSecret = true
								break
							}
						}
					}
				}

				if len(localJSMatches) > 0 || len(localSecretMatches) > 0 {
					mu.Lock()
					jsMatches = append(jsMatches, localJSMatches...)
					secretMatches = append(secretMatches, localSecretMatches...)
					if foundSecret {
						if parsedURL, err := url.Parse(target); err == nil && parsedURL.Hostname() != "" {
							seenHostsWithSecrets[strings.ToLower(parsedURL.Hostname())] = true
						}
					}
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	if ctx.Err() != nil {
		return 0, 0, 0, nil, ctx.Err()
	}

	if len(jsMatches) > 0 {
		content := strings.Join(jsMatches, "\n") + "\n"
		_ = os.WriteFile(c.F.GFJSMatches, []byte(content), 0644)
	} else {
		writeEmptyFile(c.F.GFJSMatches)
	}

	if len(secretMatches) > 0 {
		content := strings.Join(secretMatches, "\n") + "\n"
		_ = os.WriteFile(c.F.GFSecretsMatches, []byte(content), 0644)
	} else {
		writeEmptyFile(c.F.GFSecretsMatches)
	}

	var secretHosts []string
	for host := range seenHostsWithSecrets {
		secretHosts = append(secretHosts, host)
	}

	return len(jsMatches), len(secretMatches), totalBytes, secretHosts, nil
}

func stepJSSecretScan(c *Ctx) bool {
	if c.State.IsStepCompleted("js_secret_scan") {
		logger.StepHeader("Step 16: JS Secret Scan (gf JS + Secrets) [RESUMED — skipping]")
		return c.cancelled()
	}

	logger.StepHeader("Step 16: JS Secret Scan (gf JS + Secrets)")
	writeEmptyFile(c.F.GFJSMatches)
	writeEmptyFile(c.F.GFSecretsMatches)
	writeEmptyFile(c.F.GFSecretsFinal)

	jsLimit := 0
	if c.Cfg != nil {
		jsLimit = c.Cfg.General.JSLimit
	}
	jsCount := collectJSURLsFromFile(c.F.AllURLsLive, c.F.JSURLsFile, jsLimit)
	if jsCount == 0 {
		logger.Info("  No JavaScript URLs found in live URL set")
		c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
		return c.cancelled()
	}
	logger.Info("  Selected %d JavaScript URL(s) for fetching", jsCount)

	urls := loadLineSlice(c.F.JSURLsFile, 0)

	jsPatterns, err := loadGFPatterns(jsGFPatterns)
	if err != nil || len(jsPatterns) == 0 {
		jsPatterns = getFallbackGFPatterns(jsGFPatterns)
	}
	secretPatterns, err := loadGFPatterns(secretGFPatterns)
	if err != nil || len(secretPatterns) == 0 {
		secretPatterns = getFallbackGFPatterns(secretGFPatterns)
	}

	var jsMatchCount, secretMatchCount int
	var combinedBytes int64
	var secretHosts []string

	logger.SubStep("Fetching & scanning JS files in-memory...")
	scanErr := runWithSkip(c, "JS In-Memory Secret Scan", func(sCtx context.Context) error {
		var err error
		jsMatchCount, secretMatchCount, combinedBytes, secretHosts, err = runInMemoryJSSecretScan(sCtx, c, urls, jsPatterns, secretPatterns)
		return err
	})

	if scanErr != nil {
		if scanErr == ErrToolSkipped {
			logger.Info("  JS scanning skipped by user")
		} else {
			logger.Warning("JS scanning failed: %v", scanErr)
		}
	}

	if err := utils.MergeAndDeduplicate(existingFiles(c.F.GFJSMatches, c.F.GFSecretsMatches), c.F.GFSecretsFinal); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "js_secret_scan", err)
		logger.Warning("Failed to merge JS secret findings: %v", err)
		writeEmptyFile(c.F.GFSecretsFinal)
	}

	totalFindings, _ := utils.CountFileLines(c.F.GFSecretsFinal)
	if totalFindings > 0 {
		logger.Info("  Found %d JS/secret findings (%d JS matches, %d secret matches)", totalFindings, jsMatchCount, secretMatchCount)

		if c.ScanID > 0 && len(secretHosts) > 0 {
			if err := database.MarkHostsJSSecrets(c.ScanID, secretHosts); err != nil {
				logger.Warning("Failed to flag JS-secret hosts: %v", err)
			} else {
				logger.Info("  Flagged %d hosts with JS secrets for ROI boost", len(secretHosts))
			}
		}
	} else {
		logger.Info("  No JS or secret findings matched installed/fallback gf patterns")
	}

	if totalFindings > 0 {
		if content, err := os.ReadFile(c.F.GFSecretsFinal); err == nil {
			header := fmt.Sprintf("// Scan Metadata | JS Combined File Size: %.4f GB\n", float64(combinedBytes)/(1024*1024*1024))
			_ = os.WriteFile(c.F.GFSecretsFinal, append([]byte(header), content...), 0644)
		}
	}

	c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
	return c.cancelled()
}

// extractHostsFromURLFile reads a URL file and returns unique hostnames.
func extractHostsFromURLFile(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	seen := make(map[string]bool)
	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// ─────────────────────────────────────────────────────────────
// Step 17 — Directory Fuzzing (ffuf)
// ─────────────────────────────────────────────────────────────

// stepDirFuzzing runs ffuf when a wordlist is provided via --wordlist.
// Returns true if the scan should be cancelled.
func stepDirFuzzing(c *Ctx) bool {
	if c.State.IsStepCompleted("dir_fuzzing") {
		logger.StepHeader("Step 17: Directory Fuzzing (ffuf) [RESUMED — skipping]")
		return c.cancelled()
	}

	if c.WordlistPath != "" {
		logger.StepHeader("Step 17: Directory Fuzzing (ffuf)")

		// Validate wordlist file exists before invoking ffuf.
		// The path may come from config defaults (e.g. seclists) that aren't installed.
		if !utils.FileExists(c.WordlistPath) {
			logger.Warning("ffuf wordlist not found: %s", c.WordlistPath)
			logger.Info("  Install seclists (apt install seclists / pacman -S seclists) or provide a valid --wordlist path")
			logger.FileDebug("ffuf skipped: wordlist does not exist at %s", c.WordlistPath)
		} else {
			targetURL := fmt.Sprintf("https://%s/FUZZ", c.Domain)
			logger.SubStep("Running ffuf with wordlist: %s", c.WordlistPath)
			logger.FileDebug("ffuf input: target=%s wordlist=%s out=%s", targetURL, c.WordlistPath, c.F.FfufOut)

			if err := runWithSkip(c, "ffuf", func(sCtx context.Context) error {
				return c.Tb.RunFfufWithFUZZ(sCtx, targetURL, c.WordlistPath, c.F.FfufOut)
			}); err != nil {
				if err == ErrToolSkipped {
					// Logged internally by runWithSkip
				} else {
					c.StateMgr.MarkStepFailed(c.State, "dir_fuzzing", err)
					logger.Warning("ffuf failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] ffuf - Results: %s", c.F.FfufOut)
				if c.ScanID > 0 {
					count, err := utils.ParseFfufOutput(c.ScanID, c.F.FfufOut)
					if err != nil {
						logger.Warning("Failed to parse ffuf results: %v", err)
					} else if count > 0 {
						logger.Info("  Stored %d ffuf discoveries for ROI ranking", count)
					}
				}
			}
		}
	} else {
		logger.StepHeader("Step 17: Skipping ffuf (no --wordlist provided)")
		logger.Info("Provide --wordlist to enable ffuf")
	}

	c.StateMgr.MarkStepComplete(c.State, "dir_fuzzing")
	return c.cancelled()
}

// collectJSURLsFromFile filters live URLs for JavaScript files, deduplicates
// them, and writes up to limit entries into outputFile.
func collectJSURLsFromFile(inputFile, outputFile string, limit int) int {
	file, err := os.Open(inputFile)
	if err != nil {
		writeEmptyFile(outputFile)
		return 0
	}
	defer file.Close()

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := extractPrimaryURL(scanner.Text())
		if line == "" || seen[line] || !isUsefulJSURL(line) {
			continue
		}
		seen[line] = true
		fmt.Fprintln(f, line)
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	return count
}

// extractPrimaryURL strips auxiliary tokens (like httpx status codes) and
// returns the leading URL field from a scanner line.
func extractPrimaryURL(raw string) string {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// isUsefulJSURL checks if a URL is a JavaScript file and filters out common
// third-party libraries to maximize the value of the JS download limit.
func isUsefulJSURL(raw string) bool {
	if !isJavaScriptURL(raw) {
		return false
	}
	
	lower := strings.ToLower(raw)
	
	stopwords := []string{
		"jquery", "bootstrap", "react", "react-dom", "vue", "angular", 
		"moment", "lodash", "underscore", "chart", "d3", "analytics", 
		"gtm.js", "google-analytics", "ads.js", "tracking", "fontawesome", 
		"recaptcha", "polyfill", "vendor.js", "node_modules", "swagger-ui",
	}
	
	for _, stopword := range stopwords {
		if strings.Contains(lower, stopword) {
			return false
		}
	}
	return true
}

// isJavaScriptURL returns true when the URL path ends in .js, ignoring query
// strings and fragments.
func isJavaScriptURL(raw string) bool {
	raw = extractPrimaryURL(raw)
	if raw == "" {
		return false
	}
	if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.HasSuffix(strings.ToLower(raw), ".js")
}

// concatenateDownloadedFiles merges all files under downloadDir into outputFile.
func concatenateDownloadedFiles(downloadDir, outputFile string) (int, int64, error) {
	var files []string
	err := filepath.Walk(downloadDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	sort.Strings(files)
	out, err := os.Create(outputFile)
	if err != nil {
		return 0, 0, err
	}
	defer out.Close()

	var totalBytes int64
	writtenFiles := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			os.Remove(path) // also clean up empty files to save space
			continue
		}
		n, err := out.Write(data)
		if err != nil {
			return writtenFiles, totalBytes, err
		}
		totalBytes += int64(n)
		if _, err := io.WriteString(out, "\n"); err != nil {
			return writtenFiles, totalBytes, err
		}
		writtenFiles++

		// Destructive merge: immediately delete the original file to keep storage flat
		os.Remove(path)
	}
	
	// Remove the now-empty download directory completely
	os.RemoveAll(downloadDir)

	return writtenFiles, totalBytes, nil
}

// ─────────────────────────────────────────────────────────────
// convertArjunToURLs — Step 14 helper
// ─────────────────────────────────────────────────────────────

// arjunResult represents one entry in Arjun's -oJ output.
// Arjun outputs a JSON array of objects, each with a URL and discovered params.
type arjunResult struct {
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

// convertArjunToURLs parses Arjun's JSON output and writes parameterized URLs
// to outputFile. For each entry it constructs a URL with all discovered params
// as query parameters (e.g. https://example.com?id=1&page=1).
// Returns the number of URLs written.
func convertArjunToURLs(arjunJSON, outputFile string) int {
	if !utils.FileExists(arjunJSON) {
		return 0
	}

	data, err := os.ReadFile(arjunJSON)
	if err != nil || len(data) == 0 {
		return 0
	}

	// Arjun -oJ can output either a JSON array or a single object.
	var results []arjunResult
	if err := json.Unmarshal(data, &results); err != nil {
		// Try single object
		var single arjunResult
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			logger.Warning("Failed to parse Arjun JSON: %v", err)
			return 0
		}
		results = []arjunResult{single}
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	count := 0
	for _, r := range results {
		if r.URL == "" || len(r.Params) == 0 {
			continue
		}
		// Build parameterized URL preserving original Arjun parameter order.
		// Using url.Values.Encode() would sort alphabetically, which changes
		// the semantics for order-sensitive endpoints and WAFs.
		var paramPairs []string
		for _, p := range r.Params {
			paramPairs = append(paramPairs, url.QueryEscape(p)+"=1")
		}
		qs := strings.Join(paramPairs, "&")
		base := r.URL
		if strings.Contains(base, "?") {
			base += "&" + qs
		} else {
			base += "?" + qs
		}
		fmt.Fprintln(w, base)
		count++
	}
	w.Flush()
	return count
}

// storeArjunParamCounts parses Arjun's JSON output and stores the number of
// discovered hidden parameters per URL in url_metadata for ROI scoring.
func storeArjunParamCounts(scanID int64, arjunJSON string) int {
	if !utils.FileExists(arjunJSON) {
		return 0
	}

	data, err := os.ReadFile(arjunJSON)
	if err != nil || len(data) == 0 {
		return 0
	}

	var results []arjunResult
	if err := json.Unmarshal(data, &results); err != nil {
		var single arjunResult
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return 0
		}
		results = []arjunResult{single}
	}

	stored := 0
	for _, r := range results {
		if r.URL == "" || len(r.Params) == 0 {
			continue
		}
		parsed, parseErr := url.Parse(strings.TrimSpace(r.URL))
		if parseErr != nil || parsed.Hostname() == "" {
			continue
		}
		err := database.UpsertURLMetadata(scanID, database.URLMetadata{
			URL:             r.URL,
			Host:            strings.ToLower(parsed.Hostname()),
			ArjunParamCount: len(r.Params),
		})
		if err != nil {
			logger.Warning("Failed to store Arjun param count for %s: %v", r.URL, err)
		} else {
			stored++
		}
	}
	return stored
}
