// Vulnerability Scanning — Steps 17–18
//
//  17. Vulnerability Scanning — Infrastructure (Nuclei on live httpx hosts)
//  18. Vulnerability Scanning — URLs (Nuclei on filtered/GF-matched URLs)
package wildcard_flow

import (
	"context"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 17 — Vulnerability Scanning — Infrastructure (Nuclei)
// ─────────────────────────────────────────────────────────────

// stepVulnScanningInfra runs Nuclei against live httpx hosts.
// Returns true if the scan should be cancelled.
func stepVulnScanningInfra(c *Ctx) bool {
	if c.State.IsStepCompleted("vuln_scanning") {
		logger.Section("Step 17: Vulnerability Scanning — Infra (Nuclei) [RESUMED — skipping]")
	} else if !c.SkipNuclei {
		logger.Section("Step 17: Vulnerability Scanning — Infra (Nuclei)")

		liveHostCount := collectLiveHostTargetsFromHttpx(c.F.HttpxOut, c.F.HttpxLiveHosts)
		if liveHostCount == 0 {
			logger.Info("  Skipping Nuclei infra scan (no live httpx hosts available)")
		} else {
			logger.SubStep("Running Nuclei on %d live httpx hosts...", liveHostCount)

			if err := runWithSkip(c, "nuclei (infra)", func(sCtx context.Context) error {
				return c.Tb.RunNuclei(sCtx, c.F.HttpxLiveHosts, c.F.NucleiOut)
			}); err != nil {
				if err == ErrToolSkipped {
					logger.Info("  Nuclei infra scan skipped")
				} else {
					c.StateMgr.MarkStepFailed(c.State, "vuln_scanning", err)
					logger.Error("Nuclei failed: %v", err)
				}
			} else {
				if c.ScanID > 0 {
					count, _ := utils.ParseNucleiOutput(c.ScanID, c.F.NucleiOut)
					logger.Info("  Found %d vulnerabilities", count)

					// Notify critical/high findings immediately
					if c.Notifier != nil && count > 0 {
						sendVulnNotifications(c, notify.Finding{
							Target:    c.Domain,
							Type:      "vulnerability",
							Timestamp: time.Now(),
						})
					}
				}
			}
		}
	} else {
		logger.Section("Step 17: Skipping Nuclei (--skip-nuclei)")
	}
	c.StateMgr.MarkStepComplete(c.State, "vuln_scanning")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 18 — Vulnerability Scanning — URLs (Nuclei)
// ─────────────────────────────────────────────────────────────

// stepVulnScanningURLs runs Nuclei against parameterised / high-value URLs.
// Returns true if the scan should be cancelled.
func stepVulnScanningURLs(c *Ctx) bool {
	if c.State.IsStepCompleted("vuln_scanning_urls") {
		logger.Section("Step 18: Vulnerability Scanning — URLs (Nuclei) [RESUMED — skipping]")
	} else if !c.SkipNuclei && utils.FileExists(c.F.AllURLsLive) {
		logger.Section("Step 18: Vulnerability Scanning — URLs (Nuclei)")

		gfCount := 0
		if isGFUsable() {
			logger.SubStep("Filtering live URLs with gf patterns before nuclei...")
			gfCount = collectGFTargetURLs(c, c.Tb, c.F.AllURLsLive, c.F.NucleiGFMatches)
			if gfCount > 0 {
				logger.Info("  gf matched %d URLs across vulnerability patterns", gfCount)
			} else {
				logger.Info("  gf found no matches or no usable patterns; keeping fallback filter active")
			}
		} else {
			logger.Info("  gf not available or pattern pack missing; using fallback URL filter")
		}

		fallbackCount := collectHighValueURLsFromFile(c.F.AllURLsLive, c.F.NucleiFallback)
		urlTargetCount := 0
		if err := utils.MergeAndDeduplicate(existingFiles(c.F.NucleiGFMatches, c.F.NucleiFallback), c.F.NucleiURLTargets); err == nil {
			urlTargetCount, _ = utils.CountFileLines(c.F.NucleiURLTargets)
		}

		if urlTargetCount == 0 {
			logger.Info("  Skipping Nuclei URL scan (no parameterized or high-value URLs available)")
		} else {
			logger.SubStep("Running Nuclei on %d filtered URLs (gf + fallback high-value paths)...", urlTargetCount)
			if fallbackCount > 0 {
				logger.Info("  Fallback filter contributed %d parameterized/high-value URLs", fallbackCount)
			}

			if err := runWithSkip(c, "nuclei (URLs)", func(sCtx context.Context) error {
				return c.Tb.RunNucleiURLs(sCtx, c.F.NucleiURLTargets, c.F.NucleiURLOut)
			}); err != nil {
				if err == ErrToolSkipped {
					logger.Info("  Nuclei URL scan skipped")
				} else {
					c.StateMgr.MarkStepFailed(c.State, "vuln_scanning_urls", err)
					logger.Warning("Nuclei URL scan failed: %v", err)
				}
			} else {
				if c.ScanID > 0 {
					count, _ := utils.ParseNucleiOutput(c.ScanID, c.F.NucleiURLOut)
					logger.Info("  Found %d URL-specific vulnerabilities", count)
				}
			}
		}
	} else if c.SkipNuclei {
		logger.Section("Step 18: Skipping Nuclei URLs (--skip-nuclei)")
	} else {
		logger.Section("Step 18: Skipping Nuclei URLs (no live URLs available)")
	}
	c.StateMgr.MarkStepComplete(c.State, "vuln_scanning_urls")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Internal — send notifications for critical/high findings
// ─────────────────────────────────────────────────────────────

func sendVulnNotifications(c *Ctx, base notify.Finding) {
	vulns, _ := database.GetVulnerabilities(c.ScanID)
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			c.Notifier.SendFinding(notify.Finding{
				Target:      base.Target,
				Type:        base.Type,
				Name:        v.Name,
				Severity:    v.Severity,
				Description: v.Description,
				URL:         v.URL,
				TemplateID:  v.TemplateID,
				Timestamp:   base.Timestamp,
			})
		}
	}
}
