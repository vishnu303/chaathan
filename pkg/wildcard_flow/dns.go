// DNS Resolution & Brute-force — Steps 6–7
//
//  6. Consolidation & DNS Resolution (DNSx)
//  7. DNS Brute-force (ShuffleDNS) [Optional]
package wildcard_flow

import (
	"context"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 6 — Consolidation & DNS Resolution
// ─────────────────────────────────────────────────────────────

// stepDNSConsolidation merges all passive sources and resolves them with DNSx.
// Returns true if the scan should be cancelled.
func stepDNSConsolidation(c *Ctx) bool {
	if c.State.IsStepCompleted("dns_resolution") {
		logger.Section("Step 6: Consolidation & DNS Resolution [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.Section("Step 6: Consolidating Subdomains")

	passiveSources := existingFiles(
		c.F.SubfinderOut,
		c.F.AssetfinderOut,
		c.F.Sublist3rOut,
		c.F.AmassOut,
		c.F.GithubSubsOut,
		c.F.SubdomainizerOut,
	)
	if err := utils.MergeAndDeduplicate(passiveSources, c.F.ConsolidatedSubs); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
		logger.Error("Failed to consolidate: %v", err)
	}
	logger.Success("Consolidated list saved to %s", c.F.ConsolidatedSubs)

	logger.SubStep("Running DNSx for resolution...")
	if err := c.Tb.RunDnsx(c.GoCtx, c.F.ConsolidatedSubs, c.F.DnsxOut); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "dns_resolution", err)
		logger.Error("DNSx failed: %v", err)
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
		logger.Section("Step 7: DNS Brute-force (ShuffleDNS) [RESUMED — skipping]")
	} else if !c.SkipShuffleDNS && c.DNSWordlistPath != "" {
		logger.Section("Step 7: DNS Brute-force (ShuffleDNS)")
		logger.SubStep("Running ShuffleDNS with wordlist: %s", c.DNSWordlistPath)

		if err := runWithSkip(c, "shuffledns", func(sCtx context.Context) error {
			return c.Tb.RunShuffleDNS(sCtx, c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)
		}); err != nil {
			if err == ErrToolSkipped {
				logger.Info("  ShuffleDNS skipped")
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
		logger.Section("Step 7: Skipping ShuffleDNS (--skip-shuffledns)")
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	} else {
		logger.Section("Step 7: Skipping ShuffleDNS (no --dns-wordlist provided)")
		logger.Info("Use --dns-wordlist to enable DNS brute-force")
		c.StateMgr.MarkStepComplete(c.State, "dns_bruteforce")
	}
	return c.cancelled()
}
