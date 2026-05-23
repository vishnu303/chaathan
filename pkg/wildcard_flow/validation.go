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
	neturl "net/url"
	"strings"

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
		c.F.HakrawlerOut,
		c.F.UncoverHostsOut, // hostnames extracted from uncover.json in Step 4
	)
	logger.FileDebug("dns_consolidation: %d passive source files available (subfinder, assetfinder, sublist3r, amass, github, hakrawler, uncover_hosts)", len(passiveSources))
	if err := utils.MergeAndDeduplicate(passiveSources, c.F.ConsolidatedSubs); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
		logger.Error("Failed to consolidate: %v", err)
		return c.cancelled()
	}
	subCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
	logger.Success("Consolidated %d unique subdomains", subCount)
	logger.FileDebug("consolidated subs total: %d -> %s", subCount, c.F.ConsolidatedSubs)

	// Apply scope filtering (removes out-of-scope subdomains before DNS resolution)
	if c.ScopeFilter != nil {
		if err := utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
			return c.ScopeFilter.IsInScope(line) && !c.ScopeFilter.IsOutOfScope(line)
		}); err == nil {
			afterCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
			if filtered := subCount - afterCount; filtered > 0 {
				logger.Info("  Filtered %d out-of-scope subdomains", filtered)
				logger.FileDebug("scope filter: %d -> %d subdomains", subCount, afterCount)
			}
		}
	}

	logger.SubStep("Running DNSx for resolution...")
	logger.FileDebug("dnsx input: %s (%d lines) out=%s", c.F.ConsolidatedSubs, subCount, c.F.DnsxOut)
	if err := runWithSkip(c, "dnsx", func(sCtx context.Context) error {
		return c.Tb.RunDnsx(sCtx, c.F.ConsolidatedSubs, c.F.DnsxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			// Logged internally by runWithSkip
		} else {
			c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
			logger.Error("DNSx failed: %v", err)
		}
	} else {
		resolvedCount, _ := utils.CountFileLines(c.F.DnsxOut)
		logger.Info("  Resolved %d subdomains via DNS", resolvedCount)
		logger.FileDebug("dnsx output: %d resolved records -> %s", resolvedCount, c.F.DnsxOut)
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
		logger.FileDebug("shuffledns input: domain=%s wordlist=%s resolvers=%s out=%s",
			c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)

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
				logger.FileDebug("shuffledns output: %d subdomains -> %s", count, c.F.ShufflednsOut)
			}
			// Merge brute-forced subs back into the consolidated list
			utils.MergeAndDeduplicate(
				[]string{c.F.ConsolidatedSubs, c.F.ShufflednsOut},
				c.F.ConsolidatedSubs,
			)
			if merged, _ := utils.CountFileLines(c.F.ConsolidatedSubs); merged > 0 {
				logger.FileDebug("consolidated subs after shuffledns merge: %d", merged)
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	} else if c.SkipShuffleDNS {
		logger.StepHeader("Step 7: Skipping ShuffleDNS (--skip-shuffledns)")
		logger.FileDebug("shuffledns skipped via --skip-shuffledns flag")
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	} else {
		logger.StepHeader("Step 7: Skipping ShuffleDNS (no --dns-wordlist provided)")
		logger.Info("Use --dns-wordlist to enable DNS brute-force")
		logger.FileDebug("shuffledns skipped: no --dns-wordlist provided")
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
	hostInputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
	logger.FileDebug("httpx input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, hostInputCount, c.F.HttpxOut)

	if err := runWithSkip(c, "httpx", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, c.F.ConsolidatedSubs, c.F.HttpxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			// Logged internally by runWithSkip
		} else {
			c.StateMgr.MarkStepFailed(c.State, "http_probing", err)
			logger.Error("Httpx failed: %v", err)
		}
	}
	// Parse and log results regardless of skip/success — partial output may exist
	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		count, _ := utils.ParseHttpxOutput(c.ScanID, c.F.HttpxOut)
		if count > 0 {
			logger.Info("  Found %d live hosts", count)
		}
		logger.FileDebug("httpx output: %d live hosts -> %s", count, c.F.HttpxOut)
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
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("tlsx input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.TlsxOut)

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
				// hostTargets contains full URLs (e.g. https://host); extract the
				// plain hostname so the UPDATE matches the domain column correctly.
				for _, h := range hostTargets {
					host := h
					if parsed, err := neturl.Parse(h); err == nil && parsed.Hostname() != "" {
						host = strings.ToLower(parsed.Hostname())
					}
					database.UpdateSubdomainLive(c.ScanID, host, true, "")
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
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("naabu input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.NaabuOut)

		if err := runWithSkip(c, "naabu", func(sCtx context.Context) error {
			return c.Tb.RunNaabuList(sCtx, c.F.ConsolidatedSubs, c.F.NaabuOut)
		}); err != nil {
			if err == ErrToolSkipped {
				// Logged internally by runWithSkip
			} else {
				c.StateMgr.MarkStepFailed(c.State, "port_scanning", err)
				logger.Error("Naabu failed: %v", err)
			}
		}
		// Parse and log results regardless of skip/success — partial output may exist
		if c.ScanID > 0 && utils.FileExists(c.F.NaabuOut) {
			count, _ := utils.ParseNaabuOutput(c.ScanID, c.F.NaabuOut)
			if count > 0 {
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
