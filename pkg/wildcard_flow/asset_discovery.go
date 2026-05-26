// Phase 1 — Asset Discovery (Steps 1–5)
//
// Collects all possible subdomains/assets before any validation.
// Wayback/GAU are intentionally excluded — they run in Phase 3
// (Content Discovery) after live hosts are known.
//
//  1. Passive Subdomain Enumeration (Subfinder + Assetfinder + Sublist3r) [Parallel]
//  2. Active Subdomain Enumeration (Amass) [Optional]
//  3. GitHub Subdomain Discovery [Requires token]
//  4. Search-Engine Dorking (Uncover) [Optional]
//  5. JavaScript Crawling (Hakrawler) [Optional]
package wildcard_flow

import (
	"context"
	"sync"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 1 — Passive Subdomain Enumeration
// ─────────────────────────────────────────────────────────────

// stepPassiveEnum runs Subfinder, Assetfinder, and Sublist3r in parallel.
// Returns true if the scan should be cancelled.
func stepPassiveEnum(c *Ctx) bool {
	if c.State.IsStepCompleted("passive_enum") {
		logger.StepHeader("Step 1: Passive Subdomain Enumeration [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.StepHeader("Step 1: Passive Subdomain Enumeration")

	err := runWithSkip(c, "passive enum", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Subfinder")
			logger.FileDebug("subfinder input: domain=%s out=%s", c.Domain, c.F.SubfinderOut)
			if err := c.Tb.RunSubfinder(sCtx, c.Domain, c.F.SubfinderOut); err != nil {
				if sCtx.Err() == nil {
					logger.Error("Subfinder failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] Subfinder")
				if c.ScanID > 0 {
					count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.SubfinderOut, "subfinder")
					logger.Info("  Found %d subdomains", count)
					logger.FileDebug("subfinder raw lines in output: %d", count)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Assetfinder")
			logger.FileDebug("assetfinder input: domain=%s out=%s", c.Domain, c.F.AssetfinderOut)
			if err := c.Tb.RunAssetfinder(sCtx, c.Domain, c.F.AssetfinderOut); err != nil {
				if sCtx.Err() == nil {
					logger.Error("Assetfinder failed: %v", err)
				}
			} else {
				logger.SubStep("[Done] Assetfinder")
				if c.ScanID > 0 {
					count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.AssetfinderOut, "assetfinder")
					logger.Info("  Found %d subdomains", count)
					logger.FileDebug("assetfinder raw lines in output: %d", count)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Sublist3r")
			logger.FileDebug("sublist3r input: domain=%s out=%s", c.Domain, c.F.Sublist3rOut)
			if err := c.Tb.RunSublist3r(sCtx, c.Domain, c.F.Sublist3rOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("Sublist3r failed: %v", err)
				}
				logger.FileDebug("sublist3r failed: %v", err)
			} else {
				logger.SubStep("[Done] Sublist3r")
				if c.ScanID > 0 {
					count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.Sublist3rOut, "sublist3r")
					logger.Info("  Found %d subdomains", count)
					logger.FileDebug("sublist3r raw lines in output: %d", count)
				}
			}
		}()

		wg.Wait()
		return nil
	})

	if err == ErrToolSkipped {
		// Logged internally by runWithSkip
	}

	c.StateMgr.MarkStepComplete(c.State, "passive_enum")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 2 — Active Subdomain Enumeration (Amass)
// ─────────────────────────────────────────────────────────────

// stepActiveEnum runs Amass unless --skip-amass is set.
// Returns true if the scan should be cancelled.
func stepActiveEnum(c *Ctx) bool {
	if c.State.IsStepCompleted("active_enum") {
		logger.StepHeader("Step 2: Active Subdomain Enumeration (Amass) [RESUMED — skipping]")
	} else if !c.SkipAmass {
		logger.StepHeader("Step 2: Active Subdomain Enumeration (Amass)")
		logger.SubStep("Running Amass (this may take a while)...")
		logger.FileDebug("amass input: domain=%s out=%s", c.Domain, c.F.AmassOut)
		if err := runWithSkip(c, "amass", func(sCtx context.Context) error {
			return c.Tb.RunAmass(sCtx, c.Domain, c.F.AmassOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
				c.StateMgr.MarkStepComplete(c.State, "active_enum")
			} else {
				logger.Error("Amass failed: %v", err)
				c.StateMgr.MarkStepFailed(c.State, "active_enum", err)
			}
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.AmassOut, "amass")
				logger.Info("  Found %d subdomains", count)
				logger.FileDebug("amass raw lines in output: %d", count)
			}
			c.StateMgr.MarkStepComplete(c.State, "active_enum")
		}
	} else {
		logger.StepHeader("Step 2: Skipping Amass (--skip-amass)")
		logger.FileDebug("amass skipped via --skip-amass flag")
		c.StateMgr.MarkStepComplete(c.State, "active_enum")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 3 — GitHub Subdomain Discovery
// ─────────────────────────────────────────────────────────────

// stepGitHubRecon runs github-subdomains when a token is available.
// Returns true if the scan should be cancelled.
func stepGitHubRecon(c *Ctx) bool {
	if c.State.IsStepCompleted("github_recon") {
		logger.StepHeader("Step 3: GitHub Subdomain Discovery [RESUMED — skipping]")
	} else if c.GitHubToken != "" {
		logger.StepHeader("Step 3: GitHub Subdomain Discovery")
		logger.SubStep("Running github-subdomains...")
		logger.FileDebug("github-subdomains input: domain=%s token_len=%d out=%s", c.Domain, len(c.GitHubToken), c.F.GithubSubsOut)
		if err := runWithSkip(c, "github-subdomains", func(sCtx context.Context) error {
			return c.Tb.RunGithubSubdomains(sCtx, c.Domain, c.GitHubToken, c.F.GithubSubsOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "github_recon", err)
				logger.Warning("GitHub subdomains failed: %v", err)
			}
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.GithubSubsOut, "github")
				logger.Info("  Found %d subdomains", count)
				logger.FileDebug("github-subdomains raw lines in output: %d", count)
			}
			logger.SubStep("[Done] GitHub Subdomains")
		}
	} else {
		logger.StepHeader("Step 3: Skipping GitHub Recon (no token provided)")
		logger.Warning("Set GITHUB_TOKEN env var or use --github-token for GitHub recon")
		logger.FileDebug("github_recon skipped: no token provided")
	}
	c.StateMgr.MarkStepComplete(c.State, "github_recon")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 4 — Search-Engine Dorking (Uncover)
// ─────────────────────────────────────────────────────────────

// stepSearchEngineRecon runs Uncover unless --skip-uncover is set.
// Returns true if the scan should be cancelled.
func stepSearchEngineRecon(c *Ctx) bool {
	if c.State.IsStepCompleted("search_engine_recon") {
		logger.StepHeader("Step 4: Passive Search Engine Recon (Uncover) [RESUMED — skipping]")
	} else if !c.SkipUncover {
		logger.StepHeader("Step 4: Passive Search Engine Recon (Uncover)")
		logger.SubStep("Running Uncover (Shodan/Censys/Fofa)...")
		if err := runWithSkip(c, "uncover", func(sCtx context.Context) error {
			return c.Tb.RunUncover(sCtx, c.Domain, c.F.UncoverOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "search_engine_recon", err)
				logger.Warning("Uncover failed: %v (check API keys in config)", err)
			}
		} else {
			if c.ScanID > 0 {
				subs, ports, _ := utils.ParseUncoverOutput(c.ScanID, c.F.UncoverOut)
				logger.Info("  Found %d hosts and %d open ports from search engines", subs, ports)
			}
			// Extract hostnames into a plain-text file so Step 6 can merge them
			// into all_subdomains.txt and feed them into the live-host pipeline.
			if n := extractUncoverHosts(c.F.UncoverOut, c.F.UncoverHostsOut); n > 0 {
				logger.SubStep("[Done] Extracted %d unique hosts from Uncover output", n)
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "search_engine_recon")
	} else {
		logger.StepHeader("Step 4: Skipping Uncover (--skip-uncover)")
		c.StateMgr.MarkStepComplete(c.State, "search_engine_recon")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 5 — JS Crawling (Hakrawler)
// ─────────────────────────────────────────────────────────────

// stepJSCrawl crawls the root domain with Hakrawler to surface additional links and subdomains.
// Returns true if the scan should be cancelled.
func stepJSSubdomains(c *Ctx) bool {
	if c.State.IsStepCompleted("js_subdomain_discovery") {
		logger.StepHeader("Step 5: JS Crawling (Hakrawler) [RESUMED — skipping]")
	} else if !c.SkipHakrawler {
		logger.StepHeader("Step 5: JS Crawling (Hakrawler)")
		logger.SubStep("Running Hakrawler on https://%s...", c.Domain)

		if err := runWithSkip(c, "hakrawler", func(sCtx context.Context) error {
			return c.Tb.RunHakrawler(sCtx, "https://"+c.Domain, c.F.HakrawlerOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "js_subdomain_discovery", err)
				logger.Warning("Hakrawler failed: %v", err)
			}
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.HakrawlerOut, "hakrawler")
				if count > 0 {
					logger.Info("  Found %d links/subdomains from Hakrawler", count)
				} else {
					logger.Info("  No new items found from Hakrawler")
				}
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "js_subdomain_discovery")
	} else {
		logger.StepHeader("Step 5: Skipping Hakrawler (--skip-hakrawler)")
		c.StateMgr.MarkStepComplete(c.State, "js_subdomain_discovery")
	}
	return c.cancelled()
}
