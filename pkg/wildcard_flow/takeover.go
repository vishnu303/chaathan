// Subdomain Takeover Detection — Step 19
//
//  19. Subdomain Takeover Detection (Subjack) [Optional]
package wildcard_flow

import (
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 19 — Subdomain Takeover Detection (Subjack)
// ─────────────────────────────────────────────────────────────

// stepTakeoverDetection runs Subjack to find dangling CNAMEs.
// Returns true if the scan should be cancelled.
func stepTakeoverDetection(c *Ctx) bool {
	if c.State.IsStepCompleted("takeover_detection") {
		logger.Section("Step 19: Subdomain Takeover Detection (Subjack) [RESUMED — skipping]")
	} else if !c.SkipSubjack {
		logger.Section("Step 19: Subdomain Takeover Detection (Subjack)")
		logger.SubStep("Running Subjack — checking for dangling CNAMEs...")

		if err := c.Tb.RunSubjack(c.GoCtx, c.F.ConsolidatedSubs, c.F.SubjackOut); err != nil {
			c.StateMgr.MarkStepFailed(c.State, "takeover_detection", err)
			logger.Warning("Subjack failed: %v", err)
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseSubjackOutput(c.ScanID, c.F.SubjackOut)
				if count > 0 {
					logger.Success("  🚨 Found %d potential subdomain takeovers!", count)
					// Notify immediately — takeovers are critical
					if c.Notifier != nil {
						sendTakeoverNotifications(c)
					}
				} else {
					logger.Info("  No subdomain takeovers detected")
				}
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "takeover_detection")
	} else {
		logger.Section("Step 19: Skipping Subjack (--skip-subjack)")
		c.StateMgr.MarkStepComplete(c.State, "takeover_detection")
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Internal — send notifications for takeover findings
// ─────────────────────────────────────────────────────────────

func sendTakeoverNotifications(c *Ctx) {
	vulns, _ := database.GetVulnerabilities(c.ScanID)
	for _, v := range vulns {
		if v.TemplateID == "subdomain-takeover" {
			c.Notifier.SendFinding(notify.Finding{
				Target:    c.Domain,
				Type:      "subdomain-takeover",
				Name:      v.Name,
				Severity:  "critical",
				URL:       v.Host,
				Timestamp: time.Now(),
			})
		}
	}
}
