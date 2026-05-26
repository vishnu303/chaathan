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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/metadata"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
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

// stepParamDiscovery discovers HTTP parameters with Arjun (Step 13).
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

		if err := runWithSkip(c, "arjun", func(sCtx context.Context) error {
			return c.Tb.RunArjun(sCtx, c.F.HttpxLiveHosts, c.F.ArjunOut)
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
func stepJSSecretScan(c *Ctx) bool {
	if c.State.IsStepCompleted("js_secret_scan") {
		logger.StepHeader("Step 16: JS Secret Scan (gf JS + Secrets) [RESUMED — skipping]")
		return c.cancelled()
	}

	logger.StepHeader("Step 16: JS Secret Scan (gf JS + Secrets)")
	writeEmptyFile(c.F.JSCombinedFile)
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

	if err := os.RemoveAll(c.F.JSDownloadsDir); err != nil {
		logger.Warning("Failed to reset JS download directory: %v", err)
	}
	if err := os.MkdirAll(c.F.JSDownloadsDir, 0755); err != nil {
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
	var jsMatchCount int
	if err := runWithSkip(c, "gf JS patterns", func(sCtx context.Context) error {
		jsMatchCount = collectGFMatches(sCtx, c.Tb, c.F.JSCombinedFile, c.F.GFJSMatches, jsGFPatterns, 0)
		return nil
	}); err != nil && err != ErrToolSkipped {
		logger.Warning("gf JS pattern scan failed: %v", err)
	}

	logger.SubStep("Running gf secret patterns on downloaded content...")
	var secretMatchCount int
	if err := runWithSkip(c, "gf secret patterns", func(sCtx context.Context) error {
		secretMatchCount = collectGFMatches(sCtx, c.Tb, c.F.JSCombinedFile, c.F.GFSecretsMatches, secretGFPatterns, 0)
		return nil
	}); err != nil && err != ErrToolSkipped {
		logger.Warning("gf secret pattern scan failed: %v", err)
	}

	if err := utils.MergeAndDeduplicate(existingFiles(c.F.GFJSMatches, c.F.GFSecretsMatches), c.F.GFSecretsFinal); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "js_secret_scan", err)
		logger.Warning("Failed to merge JS secret findings: %v", err)
		writeEmptyFile(c.F.GFSecretsFinal)
	}

	totalFindings, _ := utils.CountFileLines(c.F.GFSecretsFinal)
	if totalFindings > 0 {
		logger.Info("  Found %d JS/secret findings (%d JS matches, %d secret matches)", totalFindings, jsMatchCount, secretMatchCount)

		// Flag hosts that served JS with secrets for ROI scoring
		if c.ScanID > 0 && secretMatchCount > 0 {
			hosts := extractHostsFromURLFile(c.F.JSURLsFile)
			if len(hosts) > 0 {
				if err := database.MarkHostsJSSecrets(c.ScanID, hosts); err != nil {
					logger.Warning("Failed to flag JS-secret hosts: %v", err)
				} else {
					logger.Info("  Flagged %d hosts with JS secrets for ROI boost", len(hosts))
				}
			}
		}
	} else {
		logger.Info("  No JS or secret findings matched installed gf patterns")
	}

	// Prepend the size of the combined file to the top of the secrets file
	// (only when there are actual findings — avoids a comment-only file in final_files/)
	if totalFindings > 0 {
		if content, err := os.ReadFile(c.F.GFSecretsFinal); err == nil {
			header := fmt.Sprintf("// Scan Metadata | JS Combined File Size: %.4f GB\n", float64(combinedBytes)/(1024*1024*1024))
			_ = os.WriteFile(c.F.GFSecretsFinal, append([]byte(header), content...), 0644)
		}
	}

	// Free up massive amounts of storage by deleting the combined file after the scan finishes
	if err := os.Remove(c.F.JSCombinedFile); err == nil {
		logger.Info("  Cleaned up %s to free storage", c.F.JSCombinedFile)
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
			logger.Info("  Install seclists (apt install seclists) or provide a valid --wordlist path")
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
