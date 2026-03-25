// Phase 3 — Content Discovery (Steps 10–17)
//
// Discovers URLs, endpoints, and directories from live hosts.
// Wayback/GAU run here (not in Phase 1) so URLs are collected
// only for validated live hosts.
//
//  10. Historical URL Discovery (Waybackurls + GAU) [Parallel]
//  11. Web Crawling (Katana + GoSpider) [Parallel, Optional]
//  12. JavaScript Analysis — Endpoint Discovery (LinkFinder)
//  13. JavaScript Subdomain Extraction (SubDomainizer) [Optional]
//      └─ Mini re-probe: new subs get httpx-probed and merged into httpx_live.json
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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/metadata"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

const maxJSDownloads = 200

// ─────────────────────────────────────────────────────────────
// Step 10 — Historical URL Discovery (Waybackurls + GAU)
// ─────────────────────────────────────────────────────────────

// stepURLDiscovery runs Waybackurls and GAU in parallel on the target domain.
// Returns true if the scan should be cancelled.
func stepURLDiscovery(c *Ctx) bool {
	if c.State.IsStepCompleted("url_discovery") {
		logger.Section("Step 10: Historical URL Discovery [RESUMED — skipping]")
		return false
	}
	logger.Section("Step 10: Historical URL Discovery")

	err := runWithSkip(c, "url discovery", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Waybackurls")
			if err := c.Tb.RunWaybackurls(sCtx, c.Domain, c.F.WaybackOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("Waybackurls failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] Waybackurls")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.WaybackOut, "waybackurls")
					logger.Info("  Found %d URLs", count)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GAU")
			if err := c.Tb.RunGau(sCtx, c.Domain, c.F.GauOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("GAU failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] GAU")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.GauOut, "gau")
					logger.Info("  Found %d URLs", count)
				}
			}
		}()

		wg.Wait()
		return nil
	})

	if err == ErrToolSkipped {
		// Logged internally by runWithSkip
	}
	c.StateMgr.MarkStepComplete(c.State, "url_discovery")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 11 — Web Crawling (Katana + GoSpider)
// ─────────────────────────────────────────────────────────────

// stepWebCrawling runs Katana and GoSpider in parallel.
// Returns true if the scan should be cancelled.
func stepWebCrawling(c *Ctx) bool {
	if c.State.IsStepCompleted("web_crawling") {
		logger.Section("Step 11: Web Crawling [RESUMED — skipping]")
		return c.cancelled()
	} else if c.SkipCrawl {
		logger.Section("Step 11: Skipping Web Crawling (--skip-crawl)")
		c.StateMgr.MarkStepComplete(c.State, "web_crawling")
		return c.cancelled()
	}

	logger.Section("Step 11: Web Crawling")
	crawlFailed := false
	var crawlFailMu sync.Mutex

	err := runWithSkip(c, "web crawling", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Katana")
			if err := c.Tb.RunKatana(sCtx, "https://"+c.Domain, c.F.KatanaOut); err != nil {
				if sCtx.Err() == nil {
					crawlFailMu.Lock()
					crawlFailed = true
					crawlFailMu.Unlock()
					logger.Warning("Katana failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] Katana")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.KatanaOut, "katana")
					logger.Info("  Katana found %d URLs", count)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GoSpider")
			if err := c.Tb.RunGoSpider(sCtx, "https://"+c.Domain, c.F.GospiderOut); err != nil {
				if sCtx.Err() == nil {
					crawlFailMu.Lock()
					crawlFailed = true
					crawlFailMu.Unlock()
					logger.Warning("GoSpider failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] GoSpider")
				if c.ScanID > 0 {
					count, _ := utils.ParseURLsFile(c.ScanID, c.F.GospiderOut, "gospider")
					logger.Info("  GoSpider found %d URLs", count)
				}
			}
		}()

		wg.Wait()
		if crawlFailed {
			return fmt.Errorf("one or more crawlers failed")
		}
		return nil
	})

	if err != nil && err != ErrToolSkipped {
		c.StateMgr.MarkStepFailed(c.State, "web_crawling", err)
	} else if err == ErrToolSkipped {
		// Logged internally by runWithSkip
	}
	c.StateMgr.MarkStepComplete(c.State, "web_crawling")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 12 — JavaScript Analysis (LinkFinder)
// ─────────────────────────────────────────────────────────────

// stepJSAnalysis extracts endpoints from JavaScript files with LinkFinder.
// Returns true if the scan should be cancelled.
func stepJSAnalysis(c *Ctx) bool {
	if c.State.IsStepCompleted("js_analysis") {
		logger.Section("Step 12: JavaScript Analysis [RESUMED — skipping]")
		return false
	}
	logger.Section("Step 12: JavaScript Analysis")
	logger.SubStep("Running Linkfinder...")

	if err := runWithSkip(c, "linkfinder", func(sCtx context.Context) error {
		return c.Tb.RunLinkfinder(sCtx, "https://"+c.Domain, c.F.LinkfinderOut)
	}); err != nil {
		if err == ErrToolSkipped {
			// Logged internally by runWithSkip
		} else {
			c.StateMgr.MarkStepFailed(c.State, "js_analysis", err)
			logger.Warning("Linkfinder failed: %v", err)
		}
	} else {
		if c.ScanID > 0 {
			count, _ := utils.ParseEndpointsFile(c.ScanID, c.F.LinkfinderOut, "linkfinder")
			logger.Info("  Found %d endpoints", count)
		}
	}
	c.StateMgr.MarkStepComplete(c.State, "js_analysis")
	return false
}

// ─────────────────────────────────────────────────────────────
// Step 13 — JavaScript Subdomain Extraction (SubDomainizer)
// ─────────────────────────────────────────────────────────────

// stepJSSubdomains discovers subdomains embedded in JavaScript with SubDomainizer.
// After a successful run it performs a mini re-probe: new subdomains not already
// in httpx_live.json are probed with httpx and their results are appended to the
// main httpx_live.json so that Steps 14+ see the full live host set.
// Returns true if the scan should be cancelled.
func stepJSSubdomains(c *Ctx) bool {
	if c.State.IsStepCompleted("js_subdomain_discovery") {
		logger.Section("Step 13: JavaScript Subdomain Extraction (SubDomainizer) [RESUMED — skipping]")
	} else if !c.SkipSubdomainizer {
		logger.Section("Step 13: JavaScript Subdomain Extraction (SubDomainizer)")
		logger.SubStep("Running SubDomainizer on https://%s...", c.Domain)

		if err := runWithSkip(c, "subdomainizer", func(sCtx context.Context) error {
			return c.Tb.RunSubdomainizer(sCtx, "https://"+c.Domain, c.F.SubdomainizerOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "js_subdomain_discovery", err)
				logger.Warning("SubDomainizer failed: %v", err)
			}
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.SubdomainizerOut, "subdomainizer")
				if count > 0 {
					logger.Info("  Found %d subdomains from JavaScript analysis", count)
					// Merge JS-discovered subs into the main consolidated list
					utils.MergeAndDeduplicate(
						[]string{c.F.ConsolidatedSubs, c.F.SubdomainizerOut},
						c.F.ConsolidatedSubs,
					)
					// Mini re-probe: probe novel subs and merge results into httpx_live.json
					miniReprobeNewSubdomains(c)
				} else {
					logger.Info("  No new subdomains found in JavaScript")
				}
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "js_subdomain_discovery")
	} else {
		logger.Section("Step 13: Skipping SubDomainizer (--skip-subdomainizer)")
		c.StateMgr.MarkStepComplete(c.State, "js_subdomain_discovery")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 14 — HTTP Parameter Discovery (Arjun)
// ─────────────────────────────────────────────────────────────

// stepParamDiscovery discovers HTTP parameters with Arjun.
// After a successful run it converts discovered params into parameterized URLs
// (written to ArjunURLsOut) so they flow into Step 15 consolidation and
// downstream scanners (Nuclei/Dalfox).
// Returns true if the scan should be cancelled.
func stepParamDiscovery(c *Ctx) bool {
	if c.State.IsStepCompleted("param_discovery") {
		logger.Section("Step 14: HTTP Parameter Discovery (Arjun) [RESUMED — skipping]")
	} else if !c.SkipArjun {
		logger.Section("Step 14: HTTP Parameter Discovery (Arjun)")
		logger.SubStep("Running Arjun on https://%s...", c.Domain)

		if err := runWithSkip(c, "arjun", func(sCtx context.Context) error {
			return c.Tb.RunArjun(sCtx, "https://"+c.Domain, c.F.ArjunOut)
		}); err != nil {
			if err != ErrToolSkipped {
				c.StateMgr.MarkStepFailed(c.State, "param_discovery", err)
				logger.Warning("Arjun failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Arjun parameter discovery")
			// Convert Arjun JSON output into parameterized URLs for downstream use
			if count := convertArjunToURLs(c.F.ArjunOut, c.F.ArjunURLsOut); count > 0 {
				logger.Info("  Generated %d parameterized URLs from Arjun output", count)
			}
		}
	} else {
		logger.Section("Step 14: Skipping Arjun (--skip-arjun)")
	}
	c.StateMgr.MarkStepComplete(c.State, "param_discovery")
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
		logger.Section("Step 15: URL Consolidation & Live Check [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.Section("Step 15: URL Consolidation & Live Check")

	sources := c.urlSources()
	logger.SubStep("Merging URLs from %d sources...", len(sources))
	if err := utils.MergeAndDeduplicate(sources, c.F.AllURLsRaw); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "url_consolidation", err)
		logger.Warning("URL merge failed: %v", err)
	} else {
		rawCount, _ := utils.CountFileLines(c.F.AllURLsRaw)
		logger.Info("  Merged %d unique URLs", rawCount)
	}

	// Live-check all URLs with httpx
	logger.SubStep("Running httpx to live-check all URLs...")
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
	}

	// ROI metadata enrichment
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		metaTargetCount := collectROIMetadataTargetsFromFile(c.F.AllURLsLive, c.F.ROIMetadataTargets, 3, 150)
		if metaTargetCount > 0 {
			logger.SubStep("Collecting lightweight metadata for %d high-value URLs...", metaTargetCount)
			metaTargets := loadLineSlice(c.F.ROIMetadataTargets, 150)
			if count, err := metadata.CollectURLMetadata(c.ScanID, metaTargets); err != nil {
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
func stepJSSecretScan(c *Ctx) bool {
	if c.State.IsStepCompleted("js_secret_scan") {
		logger.Section("Step 16: JS Secret Scan (gf JS + Secrets) [RESUMED — skipping]")
		return c.cancelled()
	}

	logger.Section("Step 16: JS Secret Scan (gf JS + Secrets)")
	writeEmptyFile(c.F.JSCombinedFile)
	writeEmptyFile(c.F.GFJSMatches)
	writeEmptyFile(c.F.GFSecretsMatches)
	writeEmptyFile(c.F.GFSecretsFinal)

	jsCount := collectJSURLsFromFile(c.F.AllURLsLive, c.F.JSURLsFile, maxJSDownloads)
	if jsCount == 0 {
		logger.Info("  No JavaScript URLs found in live URL set")
		c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
		return c.cancelled()
	}
	logger.Info("  Selected %d JavaScript URL(s) for conservative fetching", jsCount)

	if err := os.RemoveAll(c.F.JSDownloadsDir); err != nil {
		logger.Warning("Failed to reset JS download directory: %v", err)
	}
	if err := os.MkdirAll(c.F.JSDownloadsDir, 0755); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "js_secret_scan", err)
		logger.Warning("Could not create JS download directory: %v", err)
		c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
		return c.cancelled()
	}

	logger.SubStep("Fetching JavaScript files with httpx...")
	if err := runWithSkip(c, "httpx (JS fetch)", func(sCtx context.Context) error {
		return c.Tb.RunHttpxFetchJS(sCtx, c.F.JSURLsFile, c.F.JSDownloadsDir)
	}); err != nil {
		if err == ErrToolSkipped {
			logger.Info("  JS fetching skipped; continuing with any downloaded content")
		} else {
			logger.Warning("JS fetching encountered an error: %v", err)
		}
	}

	downloadedFiles, combinedBytes, err := concatenateDownloadedFiles(c.F.JSDownloadsDir, c.F.JSCombinedFile)
	if err != nil {
		c.StateMgr.MarkStepFailed(c.State, "js_secret_scan", err)
		logger.Warning("Failed to combine downloaded JS content: %v", err)
		c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
		return c.cancelled()
	}
	if combinedBytes == 0 {
		logger.Info("  No JS content retrieved")
		c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
		return c.cancelled()
	}
	logger.Info("  Combined %d downloaded JS response file(s)", downloadedFiles)

	logger.SubStep("Running gf JavaScript patterns on downloaded content...")
	jsMatchCount := collectGFMatches(c.GoCtx, c.Tb, c.F.JSCombinedFile, c.F.GFJSMatches, jsGFPatterns)

	logger.SubStep("Running gf secret patterns on downloaded content...")
	secretMatchCount := collectGFMatches(c.GoCtx, c.Tb, c.F.JSCombinedFile, c.F.GFSecretsMatches, secretGFPatterns)

	if err := utils.MergeAndDeduplicate(existingFiles(c.F.GFJSMatches, c.F.GFSecretsMatches), c.F.GFSecretsFinal); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "js_secret_scan", err)
		logger.Warning("Failed to merge JS secret findings: %v", err)
		writeEmptyFile(c.F.GFSecretsFinal)
	}

	totalFindings, _ := utils.CountFileLines(c.F.GFSecretsFinal)
	if totalFindings > 0 {
		logger.Info("  Found %d JS/secret findings (%d JS matches, %d secret matches)", totalFindings, jsMatchCount, secretMatchCount)
	} else {
		logger.Info("  No JS or secret findings matched installed gf patterns")
	}

	c.StateMgr.MarkStepComplete(c.State, "js_secret_scan")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 17 — Directory Fuzzing (ffuf)
// ─────────────────────────────────────────────────────────────

// stepDirFuzzing runs ffuf when a wordlist is provided via --wordlist.
// Returns true if the scan should be cancelled.
func stepDirFuzzing(c *Ctx) bool {
	if c.State.IsStepCompleted("dir_fuzzing") {
		logger.Section("Step 17: Directory Fuzzing (ffuf) [RESUMED — skipping]")
		return c.cancelled()
	}

	if c.WordlistPath != "" {
		logger.Section("Step 17: Directory Fuzzing (ffuf)")
		targetURL := fmt.Sprintf("https://%s/FUZZ", c.Domain)
		logger.SubStep("Running ffuf with wordlist: %s", c.WordlistPath)

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
	} else {
		logger.Section("Step 17: Skipping ffuf (no --wordlist provided)")
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
		if line == "" || seen[line] || !isJavaScriptURL(line) {
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
	}
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
		// Build parameterized URL
		params := url.Values{}
		for _, p := range r.Params {
			params.Set(p, "1")
		}
		// Append query string to the base URL
		base := r.URL
		if strings.Contains(base, "?") {
			base += "&" + params.Encode()
		} else {
			base += "?" + params.Encode()
		}
		fmt.Fprintln(w, base)
		count++
	}
	w.Flush()
	return count
}

// ─────────────────────────────────────────────────────────────
// miniReprobeNewSubdomains — Step 13 helper
// ─────────────────────────────────────────────────────────────

// miniReprobeNewSubdomains filters SubDomainizer output against subdomains
// already in httpx_live.json, writes the novel ones to a temp file, runs
// httpx on them, and appends the JSONL results into the main httpx output
// so that all later steps have access to any newly discovered live hosts.
func miniReprobeNewSubdomains(c *Ctx) {
	if !utils.FileExists(c.F.SubdomainizerOut) {
		return
	}

	// Build a set of hosts already confirmed live.
	knownLive := loadKnownLiveHosts(c.F.HttpxOut)

	// Determine which SubDomainizer subs are not yet known-live.
	novelSubs := filterNovelSubs(c.F.SubdomainizerOut, knownLive)
	if len(novelSubs) == 0 {
		logger.Info("  No novel subdomains to re-probe")
		return
	}

	logger.SubStep("Mini re-probe: probing %d novel subdomain(s) with httpx...", len(novelSubs))

	// Write novel subs to a temp input file.
	tmpInput := c.F.HttpxOut + ".reprobe_input.txt"
	tmpOutput := c.F.HttpxOut + ".reprobe_out.json"
	defer os.Remove(tmpInput)
	defer os.Remove(tmpOutput)

	if err := writeLines(tmpInput, novelSubs); err != nil {
		logger.Warning("Mini re-probe: failed to write input file: %v", err)
		return
	}

	// Run httpx on the novel subs only.
	if err := runWithSkip(c, "httpx (mini re-probe)", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, tmpInput, tmpOutput)
	}); err != nil {
		if err != ErrToolSkipped {
			logger.Warning("Mini re-probe httpx failed: %v", err)
		} else {
			// Logged internally by runWithSkip
		}
		return
	}

	if !utils.FileExists(tmpOutput) {
		return
	}

	// Append new JSONL records to the main httpx output file.
	newData, err := os.ReadFile(tmpOutput)
	if err != nil || len(newData) == 0 {
		return
	}

	f, err := os.OpenFile(c.F.HttpxOut, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		logger.Warning("Mini re-probe: failed to open httpx_live.json for append: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(newData); err != nil {
		logger.Warning("Mini re-probe: failed to append httpx results: %v", err)
		return
	}

	// Parse & store new live hosts in the DB.
	if c.ScanID > 0 {
		newLive, _ := utils.ParseHttpxOutput(c.ScanID, tmpOutput)
		if newLive > 0 {
			logger.Info("  Mini re-probe: found %d additional live host(s)", newLive)
		}
	}
}

// loadKnownLiveHosts reads httpx JSONL output and returns a set of lowercase
// hostnames that were already confirmed live.
func loadKnownLiveHosts(httpxFile string) map[string]bool {
	known := make(map[string]bool)
	f, err := os.Open(httpxFile)
	if err != nil {
		return known
	}
	defer f.Close()

	type httpxRow struct {
		Input string `json:"input"`
		Host  string `json:"host"`
	}

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Try "input" field first, then "host".
		var row httpxRow
		// minimal JSON field extract — avoid full unmarshal overhead
		if idx := strings.Index(line, `"input":"`); idx >= 0 {
			rest := line[idx+9:]
			if end := strings.Index(rest, `"`); end >= 0 {
				known[strings.ToLower(rest[:end])] = true
				continue
			}
		}
		if idx := strings.Index(line, `"host":"`); idx >= 0 {
			rest := line[idx+8:]
			if end := strings.Index(rest, `"`); end >= 0 {
				known[strings.ToLower(rest[:end])] = true
			}
		}
		_ = row
	}
	return known
}

// filterNovelSubs reads a subdomain list file and returns only those entries
// whose hostname is not present in knownLive.
func filterNovelSubs(subFile string, knownLive map[string]bool) []string {
	f, err := os.Open(subFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var novel []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !knownLive[strings.ToLower(line)] {
			novel = append(novel, line)
		}
	}
	return novel
}

// writeLines writes each entry to a file, one per line.
func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
