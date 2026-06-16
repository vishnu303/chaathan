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

	logger.Info("Scraping and validating proxies (timeout: %dm)...", timeoutMin)

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
		logger.Warning("Proxy scraping failed: %v — continuing without proxy", harvestErr)
		if c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		return c.cancelled()
	}

	if result == nil || result.TotalValid == 0 {
		if harvestSkipped {
			logger.Info("  Proxy scraping skipped — no valid proxies found")
		} else {
			logger.Warning("No valid proxies found — continuing without proxy")
		}
		if c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		return c.cancelled()
	}

	// Store counts on Ctx so notifyStepCompletion can embed both numbers
	// in the notification description and FindingsCount.
	c.ProxyTotalScraped = result.TotalScraped
	c.ProxyTotalValid = result.TotalValid

	label := ""
	if harvestSkipped {
		label = " (partial)"
	}
	logger.Success("Scraped %d proxies, %d validated%s (took %s)",
		result.TotalScraped, result.TotalValid, label,
		result.Duration.Round(time.Second))

	// ── Phase B: Start mubeng rotating proxy server ─────────
	logger.SubStep("Starting rotating proxy server (mubeng)...")

	rotatorCfg := proxy_scraping.RotatorConfig{
		ProxyListFile: result.ProxyListFile,
		ListenAddr:    "127.0.0.1:0", // OS picks free port
		RotateEvery:   rotateEvery,
		Method:        rotateMethod,
		Verbose:       c.Verbose,
	}

	rotator, err := proxy_scraping.StartRotator(c.GoCtx, rotatorCfg)
	if err != nil {
		logger.Warning("Failed to start proxy rotator: %v — continuing without proxy", err)
		if c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		return c.cancelled()
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

	logger.Success("Rotating proxy active: %s (%d proxies in pool, method: %s, rotate every: %d req)",
		rotator.ProxyURL, result.TotalValid, rotateMethod, rotateEvery)

	if c.StateMgr != nil {
		c.StateMgr.MarkStepComplete(c.State, stepName)
	}
	return c.cancelled()
}
