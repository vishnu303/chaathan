// Phase 0 — Proxy Scraping
//
// Automated proxy scraping, validation, and IP rotation setup.
// This step fetches free proxy lists, validates them with mubeng,
// then starts mubeng as a background rotating proxy server so all
// subsequent tools route through different IP addresses.
//
// Activation:  --auto-proxy flag (skipped otherwise)
// Override:    --proxy takes precedence (manual proxy always wins)
// Failure:     Non-fatal — scan continues without proxy on any error
package wildcard_flow

import (
	"context"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/proxy_scraping"
	"github.com/vishnu303/chaathan/utils"
)

// stepProxyScraping scrapes free proxies, validates them, and starts a mubeng rotating proxy server.
// Returns true if the scan should be cancelled.
func stepProxyScraping(c *Ctx) bool {
	const stepName = "proxy_scraping"

	// ── Resume check ────────────────────────────────────────
	if skipped, cancelled := c.resumeOrSkip(stepName, "Proxy Scraping + Rotation (mubeng)"); skipped {
		return cancelled
	}

	// ── Skip if --proxy was explicitly set (manual always wins) ──
	if c.Proxy != "" {
		logger.StepHeader("Proxy Scraping — skipped (--proxy already set: %s)", c.Proxy)
		if c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		return c.cancelled()
	}

	// ── Skip if --auto-proxy not requested ──────────────────
	if !c.AutoProxy {
		logger.StepHeader("Proxy Scraping — skipped (use --auto-proxy to enable)")
		if c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		return c.cancelled()
	}

	c.runProxyScrapingAndRotation(0)

	if c.StateMgr != nil {
		c.StateMgr.MarkStepComplete(c.State, stepName)
	}
	return c.cancelled()
}

// getStepPhase returns the phase number (1 to 5) for a given step name.
func getStepPhase(stepName string) int {
	switch stepName {
	case "proxy_scraping":
		return 0
	case "passive_enum", "active_enum", "github_recon", "search_engine_recon", "js_subdomain_discovery":
		return 1
	case "dns_resolution", "dns_bruteforce", "http_probing", "tls_analysis", "port_scanning":
		return 2
	case "url_discovery", "web_crawling", "js_analysis", "param_discovery", "url_consolidation", "js_secret_scan", "dir_fuzzing":
		return 3
	case "vuln_scanning", "vuln_scanning_urls", "takeover_detection", "xss_scanning":
		return 4
	case "tech_waf_fingerprinting":
		return 5
	default:
		return -1
	}
}

// isStepSkipped determines if a step will be skipped based on flags, keys, or missing inputs.
func (c *Ctx) isStepSkipped(stepName string) bool {
	switch stepName {
	case "active_enum":
		return c.SkipAmass
	case "github_recon":
		return c.GitHubToken == ""
	case "search_engine_recon":
		return c.SkipUncover
	case "js_subdomain_discovery":
		return c.SkipHakrawler
	case "dns_bruteforce":
		if c.SkipShuffleDNS || c.DNSWordlistPath == "" {
			return true
		}
		if !utils.FileExists(c.DNSWordlistPath) {
			return true
		}
		if c.ResolversPath != "" && !utils.FileExists(c.ResolversPath) {
			return true
		}
		return false
	case "tls_analysis":
		return c.SkipTlsx
	case "port_scanning":
		return c.SkipNaabu
	case "web_crawling":
		if c.SkipCrawl {
			return true
		}
		lines, err := utils.CountFileLines(c.F.HttpxLiveHosts)
		return err != nil || lines == 0
	case "param_discovery":
		if c.SkipArjun {
			return true
		}
		lines, err := utils.CountFileLines(c.F.HttpxLiveHosts)
		return err != nil || lines == 0
	case "dir_fuzzing":
		return c.WordlistPath == "" || !utils.FileExists(c.WordlistPath)
	case "vuln_scanning":
		return c.SkipNuclei
	case "vuln_scanning_urls":
		return c.SkipNuclei
	case "takeover_detection":
		return c.SkipTakeovers
	case "xss_scanning":
		return c.SkipDalfox
	case "tech_waf_fingerprinting":
		return c.SkipFingerprint
	default:
		return false
	}
}

// ensureProxyForPhase checks if we are entering a new phase and, if so,
// refreshes the proxy pool and restarts the rotating proxy.
func (c *Ctx) ensureProxyForPhase(stepName string) {
	if !c.AutoProxy {
		return
	}
	if c.Proxy != "" && c.Rotator == nil {
		// Manual proxy took precedence; don't rotate/scrape automatically.
		return
	}

	phase := getStepPhase(stepName)
	if phase <= 0 {
		return
	}

	if c.LastActivePhase == phase {
		return
	}

	// If step is already completed or will be skipped, don't trigger scraping.
	if c.State != nil && c.State.IsStepCompleted(stepName) {
		return
	}
	if c.isStepSkipped(stepName) {
		return
	}

	c.runProxyScrapingAndRotation(phase)
}

// runProxyScrapingAndRotation stops the existing rotator, scrapes new proxies, and starts a fresh rotator instance.
func (c *Ctx) runProxyScrapingAndRotation(phase int) {
	// Stop existing rotator first if active
	if c.Rotator != nil {
		logger.Info("Stopping proxy rotator from previous phase...")
		c.Rotator.Stop()
		c.Rotator = nil
		c.Proxy = ""
		if c.Cfg != nil {
			c.Cfg.General.Proxy = ""
		}
	}

	// ── Read config values ──────────────────────────────────
	timeoutMin := 10
	maxConcurrent := 512
	proxyTypes := []string{"socks5", "http", "socks4"}
	rotateMethod := "random"
	rotateEvery := 1

	if c.Cfg != nil {
		scrapeCfg := c.Cfg.General.ProxyScraping
		if scrapeCfg.TimeoutMin > 0 {
			timeoutMin = scrapeCfg.TimeoutMin
		}
		if scrapeCfg.MaxConcurrent > 0 {
			maxConcurrent = scrapeCfg.MaxConcurrent
		}
		if len(scrapeCfg.ProxyTypes) > 0 {
			proxyTypes = scrapeCfg.ProxyTypes
		}
		if scrapeCfg.RotateMethod != "" {
			rotateMethod = scrapeCfg.RotateMethod
		}
		if scrapeCfg.RotateEvery > 0 {
			rotateEvery = scrapeCfg.RotateEvery
		}
	}

	// ── Phase A: Scrape & validate proxies ──────────────────
	harvestCfg := proxy_scraping.HarvestConfig{
		Domain:        c.Domain,
		TimeoutMin:    timeoutMin,
		ProxyTypes:    proxyTypes,
		MaxConcurrent: maxConcurrent,
		OutputDir:     filepath.Join(c.ResultDir, "intermediate_files"),
	}

	logger.Info("[Phase %d] Scraping and validating proxies (timeout: %dm)...", phase, timeoutMin)

	var result *proxy_scraping.HarvestResult
	var harvestErr error
	var harvestSkipped bool

	err := runWithSkip(c, "mubeng proxy check", func(sCtx context.Context) error {
		res, hErr := proxy_scraping.RunHarvest(sCtx, harvestCfg)
		result = res
		harvestErr = hErr
		return hErr
	})

	if err == ErrToolSkipped {
		harvestSkipped = true
	}

	if harvestErr != nil && !harvestSkipped {
		logger.Warning("[Phase %d] Proxy scraping failed: %v — continuing without proxy", phase, harvestErr)
		if phase == 0 {
			c.LastActivePhase = 1
		} else {
			c.LastActivePhase = phase
		}
		return
	}

	if result == nil || result.TotalValid == 0 {
		if harvestSkipped {
			logger.Info("  [Phase %d] Proxy scraping skipped — no valid proxies found", phase)
		} else {
			logger.Warning("[Phase %d] No valid proxies found — continuing without proxy", phase)
		}
		if phase == 0 {
			c.LastActivePhase = 1
		} else {
			c.LastActivePhase = phase
		}
		return
	}

	// Store counts on Ctx
	c.ProxyTotalScraped = result.TotalScraped
	c.ProxyTotalValid = result.TotalValid

	label := ""
	if harvestSkipped {
		label = " (partial)"
	}
	logger.Success("[Phase %d] Scraped %d proxies, %d validated%s (took %s)",
		phase, result.TotalScraped, result.TotalValid, label,
		result.Duration.Round(time.Second))

	// ── Phase B: Start mubeng rotating proxy server ─────────
	logger.SubStep("[Phase %d] Starting rotating proxy server (mubeng)...", phase)

	rotatorCfg := proxy_scraping.RotatorConfig{
		ProxyListFile: result.ProxyListFile,
		ListenAddr:    "127.0.0.1:0", // OS picks free port
		RotateEvery:   rotateEvery,
		Method:        rotateMethod,
		Verbose:       c.Verbose,
	}

	rotator, err := proxy_scraping.StartRotator(c.GoCtx, rotatorCfg)
	if err != nil {
		logger.Warning("[Phase %d] Failed to start proxy rotator: %v — continuing without proxy", phase, err)
		if phase == 0 {
			c.LastActivePhase = 1
		} else {
			c.LastActivePhase = phase
		}
		return
	}

	// ── Wire the rotating proxy into the scan context ───────
	c.Rotator = rotator
	c.Proxy = rotator.ProxyURL
	if c.Cfg != nil {
		c.Cfg.General.Proxy = rotator.ProxyURL
	}
	// Re-wire ToolBox proxy so all tools pick it up
	if c.Tb != nil && c.Cfg != nil {
		c.Tb.WithGeneral(&c.Cfg.General)
	}

	logger.Success("[Phase %d] Rotating proxy active: %s (%d proxies in pool, method: %s, rotate every: %d req)",
		phase, rotator.ProxyURL, result.TotalValid, rotateMethod, rotateEvery)

	if phase == 0 {
		c.LastActivePhase = 1
	} else {
		c.LastActivePhase = phase
	}
}
