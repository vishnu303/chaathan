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

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/metadata"
	"github.com/vishnu303/chaathan/utils"
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
	writeEmptyFile(c.F.DnsxOut)

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

	// Sync consolidated subdomains to DB
	if c.ScanID > 0 {
		if count, err := utils.ParseSubdomainsFile(c.ScanID, c.F.ConsolidatedSubs, "consolidated"); err != nil {
			logger.Warning("Failed to sync consolidated subdomains to database: %v", err)
		} else {
			logger.FileDebug("synced %d consolidated subdomains to database", count)
		}
	}

	logger.SubStep("Running DNSx for resolution...")
	logger.FileDebug("dnsx input: %s (%d lines) out=%s", c.F.ConsolidatedSubs, subCount, c.F.DnsxOut)
	
	var dnsxSkipped bool
	if err := runWithSkip(c, "dnsx", func(sCtx context.Context) error {
		return c.Tb.RunDnsx(sCtx, c.F.ConsolidatedSubs, c.F.DnsxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			dnsxSkipped = true
		} else {
			c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
			logger.Error("DNSx failed: %v", err)
		}
	}

	if utils.FileExists(c.F.DnsxOut) {
		uniqueHosts, _ := utils.CountUniqueDNSxHosts(c.F.DnsxOut)
		resolvedCount, _ := utils.CountFileLines(c.F.DnsxOut)
		if uniqueHosts > 0 || resolvedCount > 0 {
			label := ""
			if dnsxSkipped {
				label = " (partial)"
			}
			logger.Info("  Resolved %d hosts (%d DNS records)%s", uniqueHosts, resolvedCount, label)
			logger.FileDebug("dnsx output: %d hosts (%d resolved records) -> %s", uniqueHosts, resolvedCount, c.F.DnsxOut)
		} else if dnsxSkipped {
			logger.Info("  DNSx skipped — no hosts resolved")
		} else {
			logger.Info("  Resolved 0 hosts (0 DNS records)")
		}
	}

	// Only mark complete if not failed
	hasFailure := false
	for _, fs := range c.State.FailedSteps {
		if fs.Name == "dns_resolution" {
			hasFailure = true
			break
		}
	}
	if !hasFailure {
		c.StateMgr.MarkStepComplete(c.State, "dns_resolution")
	}
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
		writeEmptyFile(c.F.ShufflednsOut)

		// Validate DNS wordlist exists (may be a default config path like seclists)
		if !utils.FileExists(c.DNSWordlistPath) {
			logger.Warning("DNS wordlist not found: %s", c.DNSWordlistPath)
			logger.Info("  Install seclists (apt install seclists / pacman -S seclists) or provide a valid --dns-wordlist path")
			logger.FileDebug("shuffledns skipped: wordlist does not exist at %s", c.DNSWordlistPath)
			c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
		} else if c.ResolversPath != "" && !utils.FileExists(c.ResolversPath) {
			// Resolvers file was explicitly provided but doesn't exist
			logger.Warning("Resolvers file not found: %s", c.ResolversPath)
			logger.Info("  Provide a valid --resolvers file path")
			logger.FileDebug("shuffledns skipped: resolvers file does not exist at %s", c.ResolversPath)
			c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
		} else {
			logger.SubStep("Running ShuffleDNS with wordlist: %s", c.DNSWordlistPath)
			logger.FileDebug("shuffledns input: domain=%s wordlist=%s resolvers=%s out=%s",
				c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)

			var shufflednsSkipped bool
			if err := runWithSkip(c, "shuffledns", func(sCtx context.Context) error {
				return c.Tb.RunShuffleDNS(sCtx, c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)
			}); err != nil {
				if err == ErrToolSkipped {
					shufflednsSkipped = true
				} else {
					c.StateMgr.MarkStepFailed(c.State, "dns_bruteforce", err)
					logger.Warning("ShuffleDNS failed: %v", err)
				}
			} else {
				// Merge brute-forced subs back into the consolidated list
				utils.MergeAndDeduplicate(
					[]string{c.F.ConsolidatedSubs, c.F.ShufflednsOut},
					c.F.ConsolidatedSubs,
				)
				if merged, _ := utils.CountFileLines(c.F.ConsolidatedSubs); merged > 0 {
					logger.FileDebug("consolidated subs after shuffledns merge: %d", merged)
				}
			}

			if c.ScanID > 0 && utils.FileExists(c.F.ShufflednsOut) {
				count, _ := utils.ParseSubdomainsFile(c.ScanID, c.F.ShufflednsOut, "shuffledns")
				if count > 0 {
					label := ""
					if shufflednsSkipped {
						label = " (partial)"
					}
					logger.Info("  Found %d subdomains via DNS brute-force%s", count, label)
					logger.FileDebug("shuffledns output: %d subdomains -> %s", count, c.F.ShufflednsOut)
				} else if shufflednsSkipped {
					logger.Info("  ShuffleDNS skipped — no subdomains found")
				} else {
					logger.Info("  Found 0 subdomains via DNS brute-force")
				}
			}

			// Only mark complete if not failed
			hasFailure := false
			for _, fs := range c.State.FailedSteps {
				if fs.Name == "dns_bruteforce" {
					hasFailure = true
					break
				}
			}
			if !hasFailure {
				c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
			}
		}
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
	writeEmptyFile(c.F.HttpxOut)
	writeEmptyFile(c.F.HttpxLiveHosts)
	logger.SubStep("Running Httpx...")
	hostInputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
	logger.FileDebug("httpx input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, hostInputCount, c.F.HttpxOut)

	var httpxSkipped bool
	if err := runWithSkip(c, "httpx", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, c.F.ConsolidatedSubs, c.F.HttpxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			httpxSkipped = true
		} else {
			c.StateMgr.MarkStepFailed(c.State, "http_probing", err)
			logger.Error("Httpx failed: %v", err)
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		count, _ := utils.ParseHttpxOutput(c.ScanID, c.F.HttpxOut)
		if count > 0 {
			label := ""
			if httpxSkipped {
				label = " (partial)"
			}
			logger.Info("  Found %d live hosts%s", count, label)
			logger.FileDebug("httpx output: %d live hosts -> %s", count, c.F.HttpxOut)
		} else if httpxSkipped {
			logger.Info("  Httpx skipped — no live host data from this scan")
		} else {
			logger.Info("  Found 0 live hosts")
		}
	}

	// Trigger active WAF bypass Origin IP resolution
	if err := runWithSkip(c, "WAF Origin IP Bypass", func(sCtx context.Context) error {
		return RunOriginIPBypass(sCtx, c)
	}); err != nil {
		if err == ErrToolSkipped {
			// Logged internally by runWithSkip
		} else {
			logger.Warning("WAF Origin IP Bypass failed: %v", err)
		}
	}

	// Only mark complete if not failed
	hasFailure := false
	for _, fs := range c.State.FailedSteps {
		if fs.Name == "http_probing" {
			hasFailure = true
			break
		}
	}
	if !hasFailure {
		c.StateMgr.MarkStepComplete(c.State, "http_probing")
	}
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
		writeEmptyFile(c.F.TlsxOut)
		logger.SubStep("Running tlsx — extracting SANs and checking cert issues...")
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("tlsx input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.TlsxOut)

		var tlsxSkipped bool
		if err := runWithSkip(c, "tlsx", func(sCtx context.Context) error {
			return c.Tb.RunTlsx(sCtx, c.F.ConsolidatedSubs, c.F.TlsxOut)
		}); err != nil {
			if err == ErrToolSkipped {
				tlsxSkipped = true
			} else {
				c.StateMgr.MarkStepFailed(c.State, "tls_analysis", err)
				logger.Warning("tlsx failed: %v", err)
			}
		}

		if c.ScanID > 0 && utils.FileExists(c.F.TlsxOut) {
			newSubs, certVulns, _ := utils.ParseTlsxOutput(c.ScanID, c.F.TlsxOut, c.Domain)
			label := ""
			if tlsxSkipped {
				label = " (partial)"
			}
			if newSubs > 0 || certVulns > 0 {
				if newSubs > 0 {
					logger.Info("  Discovered %d new subdomains from certificate SANs%s", newSubs, label)
				}
				if certVulns > 0 {
					logger.Info("  Found %d certificate issues (expired/self-signed/mismatch)%s", certVulns, label)
				}
			} else if tlsxSkipped {
				logger.Info("  Tlsx skipped — no new subdomains or certificate issues found")
			} else {
				logger.Info("  Discovered 0 new subdomains and 0 certificate issues")
			}
		}

		// Only mark complete if not failed
		hasFailure := false
		for _, fs := range c.State.FailedSteps {
			if fs.Name == "tls_analysis" {
				hasFailure = true
				break
			}
		}
		if !hasFailure {
			c.StateMgr.MarkStepComplete(c.State, "tls_analysis")
		}
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
				// Ensure these hosts are marked live in the subdomains table
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
		writeEmptyFile(c.F.NaabuOut)
		logger.SubStep("Running Naabu on all discovered subdomains...")
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("naabu input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.NaabuOut)

		var naabuSkipped bool
		if err := runWithSkip(c, "naabu", func(sCtx context.Context) error {
			return c.Tb.RunNaabuList(sCtx, c.F.ConsolidatedSubs, c.F.NaabuOut)
		}); err != nil {
			if err == ErrToolSkipped {
				naabuSkipped = true
			} else {
				c.StateMgr.MarkStepFailed(c.State, "port_scanning", err)
				logger.Error("Naabu failed: %v", err)
			}
		}
		// Parse and log results regardless of skip/success — partial output may exist
		if c.ScanID > 0 && utils.FileExists(c.F.NaabuOut) {
			count, _ := utils.ParseNaabuOutput(c.ScanID, c.F.NaabuOut)
			if count > 0 {
				label := ""
				if naabuSkipped {
					label = " (partial)"
				}
				logger.Info("  Found %d open ports%s", count, label)
			} else if naabuSkipped {
				logger.Info("  Naabu skipped — no open ports found")
			} else {
				logger.Info("  Found 0 open ports")
			}
		}

		// Only mark complete if not failed
		hasFailure := false
		for _, fs := range c.State.FailedSteps {
			if fs.Name == "port_scanning" {
				hasFailure = true
				break
			}
		}
		if !hasFailure {
			c.StateMgr.MarkStepComplete(c.State, "port_scanning")
		}
	} else {
		logger.StepHeader("Step 10: Skipping Naabu (--skip-naabu)")
		c.StateMgr.MarkStepComplete(c.State, "port_scanning")
	}
	return c.cancelled()
}
