// Port Scanning — Step 10
//
//  10. Port Scanning on all subdomains (Naabu) [Optional]
package wildcard_flow

import (
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 10 — Port Scanning (Naabu)
// ─────────────────────────────────────────────────────────────

// stepPortScanning runs Naabu against all discovered subdomains.
// Returns true if the scan should be cancelled.
func stepPortScanning(c *Ctx) bool {
	if c.State.IsStepCompleted("port_scanning") {
		logger.Section("Step 10: Port Scanning [RESUMED — skipping]")
	} else if !c.SkipNaabu {
		logger.Section("Step 10: Port Scanning")
		logger.SubStep("Running Naabu on all discovered subdomains...")

		if err := c.Tb.RunNaabuList(c.GoCtx, c.F.ConsolidatedSubs, c.F.NaabuOut); err != nil {
			c.StateMgr.MarkStepFailed(c.State, "port_scanning", err)
			logger.Error("Naabu failed: %v", err)
		} else {
			if c.ScanID > 0 {
				count, _ := utils.ParseNaabuOutput(c.ScanID, c.F.NaabuOut)
				logger.Info("  Found %d open ports", count)
			}
		}
		c.StateMgr.MarkStepComplete(c.State, "port_scanning")
	} else {
		logger.Section("Step 10: Skipping Naabu (--skip-naabu)")
		c.StateMgr.MarkStepComplete(c.State, "port_scanning")
	}
	return c.cancelled()
}
