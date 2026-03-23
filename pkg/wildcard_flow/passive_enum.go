// Passive Enumeration — Steps 1–5
//
//  1. Passive Subdomain Enumeration (Subfinder + Assetfinder + Sublist3r) [Parallel]
//  2. Historical URL Discovery (Waybackurls + GAU) [Parallel]
//  3. Active Subdomain Enumeration (Amass) [Optional]
//  4. GitHub Subdomain Discovery [Requires token]
//  5. Search-Engine Dorking (Uncover) [Optional]
package wildcard_flow

import (
	"sync"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 1 — Passive Subdomain Enumeration
// ─────────────────────────────────────────────────────────────

// stepPassiveEnum runs Subfinder, Assetfinder, and Sublist3r in parallel.
// Returns true if the scan should be cancelled.
func stepPassiveEnum(c *Ctx) bool {
	if c.State.IsStepCompleted("passive_enum") {
		logger.Section("Step 1: Passive Subdomain Enumeration [RESUMED — skipping]")
		return false
	}
	logger.Section("Step 1: Passive Subdomain Enumeration")

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Subfinder")
		if err := c.Tb.RunSubfinder(c.GoCtx, c.Domain, c.F.SubfinderOut); err != nil {
			logger.Error("Subfinder failed: %v", err)
		} else {
			logger.SubStep("[Done] Subfinder")
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.SubfinderOut, "subfinder")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Assetfinder")
		if err := c.Tb.RunAssetfinder(c.GoCtx, c.Domain, c.F.AssetfinderOut); err != nil {
			logger.Error("Assetfinder failed: %v", err)
		} else {
			logger.SubStep("[Done] Assetfinder")
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.AssetfinderOut, "assetfinder")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Sublist3r")
		if err := c.Tb.RunSublist3r(c.GoCtx, c.Domain, c.F.Sublist3rOut); err != nil {
			if c.Verbose {
				logger.Warning("Sublist3r failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Sublist3r")
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.Sublist3rOut, "sublist3r")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	wg.Wait()
	c.StateMgr.MarkStepComplete(c.State, "passive_enum")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 2 — Historical URL Discovery
// ─────────────────────────────────────────────────────────────

// stepURLDiscovery runs Waybackurls and GAU in parallel.
// Returns true if the scan should be cancelled.
func stepURLDiscovery(c *Ctx) bool {
	if c.State.IsStepCompleted("url_discovery") {
		logger.Section("Step 2: Historical URL Discovery [RESUMED — skipping]")
		return false
	}
	logger.Section("Step 2: Historical URL Discovery")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Waybackurls")
		if err := c.Tb.RunWaybackurls(c.GoCtx, c.Domain, c.F.WaybackOut); err != nil {
			if c.Verbose {
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
		if err := c.Tb.RunGau(c.GoCtx, c.Domain, c.F.GauOut); err != nil {
			if c.Verbose {
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
	c.StateMgr.MarkStepComplete(c.State, "url_discovery")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 3 — Active Subdomain Enumeration (Amass)
// ─────────────────────────────────────────────────────────────

// stepActiveEnum runs Amass unless --skip-amass is set.
// Returns true if the scan should be cancelled.
func stepActiveEnum(c *Ctx) bool {
	if c.State.IsStepCompleted("active_enum") {
		logger.Section("Step 3: Active Subdomain Enumeration (Amass) [RESUMED — skipping]")
	} else if !c.SkipAmass {
		logger.Section("Step 3: Active Subdomain Enumeration (Amass)")
		logger.SubStep("Running Amass (this may take a while)...")
		if err := c.Tb.RunAmass(c.GoCtx, c.Domain, c.F.AmassOut); err != nil {
			logger.Error("Amass failed: %v", err)
			c.StateMgr.MarkStepFailed(c.State, "active_enum", err)
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.AmassOut, "amass")
				logger.Info("  Found %d subdomains", count)
			}
			c.StateMgr.MarkStepComplete(c.State, "active_enum")
		}
	} else {
		logger.Section("Step 3: Skipping Amass (--skip-amass)")
		c.StateMgr.MarkStepComplete(c.State, "active_enum")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 4 — GitHub Subdomain Discovery
// ─────────────────────────────────────────────────────────────

// stepGitHubRecon runs github-subdomains when a token is available.
// Returns true if the scan should be cancelled.
func stepGitHubRecon(c *Ctx) bool {
	if c.State.IsStepCompleted("github_recon") {
		logger.Section("Step 4: GitHub Subdomain Discovery [RESUMED — skipping]")
	} else if c.GitHubToken != "" {
		logger.Section("Step 4: GitHub Subdomain Discovery")
		logger.SubStep("Running github-subdomains...")
		if err := c.Tb.RunGithubSubdomains(c.GoCtx, c.Domain, c.GitHubToken, c.F.GithubSubsOut); err != nil {
			c.StateMgr.MarkStepFailed(c.State, "github_recon", err)
			logger.Warning("GitHub subdomains failed: %v", err)
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.GithubSubsOut, "github")
				logger.Info("  Found %d subdomains", count)
			}
			logger.SubStep("[Done] GitHub Subdomains")
		}
	} else {
		logger.Section("Step 4: Skipping GitHub Recon (no token provided)")
		logger.Warning("Set GITHUB_TOKEN env var or use --github-token for GitHub recon")
	}
	c.StateMgr.MarkStepComplete(c.State, "github_recon")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 5 — Search-Engine Dorking (Uncover)
// ─────────────────────────────────────────────────────────────

// stepSearchEngineRecon runs Uncover unless --skip-uncover is set.
// Returns true if the scan should be cancelled.
func stepSearchEngineRecon(c *Ctx) bool {
	if c.State.IsStepCompleted("search_engine_recon") {
		logger.Section("Step 5: Passive Search Engine Recon (Uncover) [RESUMED — skipping]")
	} else if !c.SkipUncover {
		logger.Section("Step 5: Passive Search Engine Recon (Uncover)")
		logger.SubStep("Running Uncover (Shodan/Censys/Fofa)...")
		if err := c.Tb.RunUncover(c.GoCtx, c.Domain, c.F.UncoverOut); err != nil {
			c.StateMgr.MarkStepFailed(c.State, "search_engine_recon", err)
			logger.Warning("Uncover failed: %v (check API keys in config)", err)
		} else {
			if c.ScanID > 0 {
				subs, ports, _ := utils.ParseUncoverOutput(c.ScanID, c.F.UncoverOut)
				logger.Info("  Found %d hosts and %d open ports from search engines", subs, ports)
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "search_engine_recon")
	} else {
		logger.Section("Step 5: Skipping Uncover (--skip-uncover)")
		c.StateMgr.MarkStepComplete(c.State, "search_engine_recon")
	}
	return c.cancelled()
}
