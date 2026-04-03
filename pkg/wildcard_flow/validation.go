// Phase 2 — Validation & Fingerprint (Steps 6–10)
//
// Validates discovered assets through DNS resolution, HTTP probing,
// TLS analysis, and port scanning.
//
//  6. Consolidation & DNS Resolution (DNSx)
//  7. DNS Brute-force (ShuffleDNS) [Optional]
//  8. Live Web Server Probing (Httpx)
//  9. TLS Certificate Analysis (tlsx) + host metadata enrichment [Optional]
//  10. Port Scanning (Naabu) [Optional]
package wildcard_flow

import (
	"context"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/metadata"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 6 — Consolidation & DNS Resolution
// ─────────────────────────────────────────────────────────────

// stepDNSConsolidation merges all passive sources and resolves them with DNSx.
// Returns true if the scan should be cancelled.
func stepDNSConsolidation(c *Ctx) bool {
	if c.State.IsStepCompleted("dns_resolution") {
		logger.StepHeader("Step 6: Consolidation & DNS Resolution [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.StepHeader("Step 6: Consolidating Subdomains")

	passiveSources := existingFiles(
		c.F.SubfinderOut,
		c.F.AssetfinderOut,
		c.F.Sublist3rOut,
		c.F.AmassOut,
		c.F.GithubSubsOut,
		c.F.SubdomainizerOut,
		c.F.UncoverHostsOut, // hostnames extracted from uncover.json in Step 4
	)
	if err := utils.MergeAndDeduplicate(passiveSources, c.F.ConsolidatedSubs); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
		logger.Error("Failed to consolidate: %v", err)
		return c.cancelled()
	}
	logger.Success("Consolidated list saved to %s", c.F.ConsolidatedSubs)

	logger.SubStep("Running DNSx for resolution...")
	if err := runWithSkip(c, "dnsx", func(sCtx context.Context) error {
		return c.Tb.RunDnsx(sCtx, c.F.ConsolidatedSubs, c.F.DnsxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			// Logged internally by runWithSkip
		} else {
			c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
			logger.Error("DNSx failed: %v", err)
		}
	}
	c.StateMgr.MarkStepComplete(c.State, "dns_resolution")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 7 — DNS Brute-force (ShuffleDNS)
// ─────────────────────────────────────────────────────────────

// stepDNSBruteforce runs ShuffleDNS when a dns-wordlist is provided.
// Returns true if the scan should be cancelled.
func stepDNSBruteforce(c *Ctx) bool {
	if c.State.IsStepCompleted("dns_bruteforce") {
		logger.StepHeader("Step 7: DNS Brute-force (ShuffleDNS) [RESUMED — skipping]")
	} else if !c.SkipShuffleDNS && c.DNSWordlistPath != "" {
		logger.StepHeader("Step 7: DNS Brute-force (ShuffleDNS)")
		logger.SubStep("Running ShuffleDNS with wordlist: %s", c.DNSWordlistPath)

		if err := runWithSkip(c, "shuffledns", func(sCtx context.Context) error {
			return c.Tb.RunShuffleDNS(sCtx, c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "dns_bruteforce", err)
				logger.Warning("ShuffleDNS failed: %v", err)
			}
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.ShufflednsOut, "shuffledns")
				logger.Info("  Found %d subdomains via DNS brute-force", count)
			}
			// Merge brute-forced subs back into the consolidated list
			utils.MergeAndDeduplicate(
				[]string{c.F.ConsolidatedSubs, c.F.ShufflednsOut},
				c.F.ConsolidatedSubs,
			)
		}
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	} else if c.SkipShuffleDNS {
		logger.StepHeader("Step 7: Skipping ShuffleDNS (--skip-shuffledns)")
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	} else {
		logger.StepHeader("Step 7: Skipping ShuffleDNS (no --dns-wordlist provided)")
		logger.Info("Use --dns-wordlist to enable DNS brute-force")
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 8 — Live Web Server Probing (Httpx)
// ─────────────────────────────────────────────────────────────

// stepHTTPProbing probes all consolidated subdomains with Httpx.
// Returns true if the scan should be cancelled.
func stepHTTPProbing(c *Ctx) bool {
	if c.State.IsStepCompleted("http_probing") {
		logger.StepHeader("Step 8: Live Web Server Probing [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.StepHeader("Step 8: Live Web Server Probing")
	logger.SubStep("Running Httpx...")

	if err := runWithSkip(c, "httpx", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, c.F.ConsolidatedSubs, c.F.HttpxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			// Logged internally by runWithSkip
		} else {
			c.StateMgr.MarkStepFailed(c.State, "http_probing", err)
			logger.Error("Httpx failed: %v", err)
		}
	} else {
		if c.ScanID > 0 {
			count, _ := utils.ParseHttpxOutput(c.ScanID, c.F.HttpxOut)
			logger.Info("  Found %d live hosts", count)
		}
	}
	c.StateMgr.MarkStepComplete(c.State, "http_probing")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 9 — TLS Certificate Analysis (tlsx) + host metadata
// ─────────────────────────────────────────────────────────────

// stepTLSAnalysis examines TLS certificates and enriches host metadata.
// Returns true if the scan should be cancelled.
func stepTLSAnalysis(c *Ctx) bool {
	if c.State.IsStepCompleted("tls_analysis") {
		logger.StepHeader("Step 9: TLS Certificate Analysis (tlsx) [RESUMED — skipping]")
	} else if !c.SkipTlsx {
		logger.StepHeader("Step 9: TLS Certificate Analysis (tlsx)")
		logger.SubStep("Running tlsx — extracting SANs and checking cert issues...")

		if err := runWithSkip(c, "tlsx", func(sCtx context.Context) error {
			return c.Tb.RunTlsx(sCtx, c.F.ConsolidatedSubs, c.F.TlsxOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "tls_analysis", err)
				logger.Warning("tlsx failed: %v", err)
			}
		} else {
			if c.ScanID > 0 {
				newSubs, certVulns, _ := utils.ParseTlsxOutput(c.ScanID, c.F.TlsxOut, c.Domain)
				if newSubs > 0 {
					logger.Info("  Discovered %d new subdomains from certificate SANs", newSubs)
				}
				if certVulns > 0 {
					logger.Info("  Found %d certificate issues (expired/self-signed/mismatch)", certVulns)
				}
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "tls_analysis")
	} else {
		logger.StepHeader("Step 9: Skipping tlsx (--skip-tlsx)")
		c.StateMgr.MarkStepComplete(c.State, "tls_analysis")
	}

	// Host metadata enrichment (always attempted after step 9)
	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		hostTargetCount := collectLiveHostTargetsFromHttpx(c.F.HttpxOut, c.F.HttpxLiveHosts)
		if hostTargetCount > 0 {
			logger.SubStep("Collecting lightweight host metadata for ROI scoring...")
			hostTargets := loadLineSlice(c.F.HttpxLiveHosts, 250)
			if count, err := metadata.CollectHostMetadata(c.ScanID, hostTargets, c.Proxy); err != nil {
				logger.Warning("Host metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Info("  Stored metadata for %d live hosts", count)
				// Ensure these hosts are marked live in the subdomains table,
				// even if httpx was skipped and ParseHttpxOutput never ran.
				for _, h := range hostTargets {
					database.UpdateSubdomainLive(c.ScanID, h, true, "")
				}
			}
		}
	}

	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 10 — Port Scanning (Naabu)
// ─────────────────────────────────────────────────────────────

// stepPortScanning runs Naabu against all discovered subdomains.
// Returns true if the scan should be cancelled.
func stepPortScanning(c *Ctx) bool {
	if c.State.IsStepCompleted("port_scanning") {
		logger.StepHeader("Step 10: Port Scanning [RESUMED — skipping]")
	} else if !c.SkipNaabu {
		logger.StepHeader("Step 10: Port Scanning")
		logger.SubStep("Running Naabu on all discovered subdomains...")

		if err := runWithSkip(c, "naabu", func(sCtx context.Context) error {
			return c.Tb.RunNaabuList(sCtx, c.F.ConsolidatedSubs, c.F.NaabuOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "port_scanning", err)
				logger.Error("Naabu failed: %v", err)
			}
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseNaabuOutput(c.ScanID, c.F.NaabuOut)
				logger.Info("  Found %d open ports", count)
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "port_scanning")
	} else {
		logger.StepHeader("Step 10: Skipping Naabu (--skip-naabu)")
		c.StateMgr.MarkStepComplete(c.State, "port_scanning")
	}
	return c.cancelled()
}
