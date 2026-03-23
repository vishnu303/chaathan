// Web Crawling & JavaScript Analysis — Steps 11–13
//
//  11. Web Crawling (Katana + GoSpider) [Parallel, Optional]
//  12. JavaScript Analysis — Endpoint Discovery (LinkFinder)
//  13. JavaScript Subdomain Extraction (SubDomainizer) [Optional]
package wildcard_flow

import (
	"context"
	"fmt"
	"sync"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Katana")
		if err := c.Tb.RunKatana(c.GoCtx, "https://"+c.Domain, c.F.KatanaOut); err != nil {
			crawlFailMu.Lock()
			crawlFailed = true
			crawlFailMu.Unlock()
			logger.Warning("Katana failed: %v", err)
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
		if err := c.Tb.RunGoSpider(c.GoCtx, "https://"+c.Domain, c.F.GospiderOut); err != nil {
			crawlFailMu.Lock()
			crawlFailed = true
			crawlFailMu.Unlock()
			logger.Warning("GoSpider failed: %v", err)
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
		c.StateMgr.MarkStepFailed(c.State, "web_crawling", fmt.Errorf("one or more crawlers failed"))
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

	if err := c.Tb.RunLinkfinder(c.GoCtx, "https://"+c.Domain, c.F.LinkfinderOut); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "js_analysis", err)
		logger.Warning("Linkfinder failed: %v", err)
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
				logger.Info("  SubDomainizer skipped")
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
