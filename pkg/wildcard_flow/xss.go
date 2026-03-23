// XSS Scanning — Step 20
//
//  20. XSS Scanning (Dalfox) on parameterised live URLs [Optional]
package wildcard_flow

import (
	"context"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 20 — XSS Scanning (Dalfox)
// ─────────────────────────────────────────────────────────────

// stepXSSScanning collects parameterised URLs from the live URL file and
// feeds them to Dalfox. This is the final step; it never signals cancellation.
func stepXSSScanning(c *Ctx) {
	if c.State.IsStepCompleted("xss_scanning") {
		logger.Section("Step 20: XSS Scanning (Dalfox) [RESUMED — skipping]")
		return
	}

	if !c.SkipDalfox {
		logger.Section("Step 20: XSS Scanning (Dalfox)")
		logger.SubStep("Collecting parameterized URLs from live URLs...")

		paramCount := collectParamURLsFromFile(c.F.AllURLsLive, c.F.ParamURLsFile)

		if paramCount > 0 {
			logger.Info("  Found %d parameterized URLs to test", paramCount)
			logger.SubStep("Running Dalfox on parameterized URLs...")

			if err := runWithSkip(c, "dalfox", func(sCtx context.Context) error {
				return c.Tb.RunDalfox(sCtx, c.F.ParamURLsFile, c.F.DalfoxOut)
			}); err != nil {
				if err == ErrToolSkipped {
					logger.Info("  Dalfox skipped")
				} else {
					c.StateMgr.MarkStepFailed(c.State, "xss_scanning", err)
					logger.Warning("Dalfox failed: %v", err)
				}
			} else {
				if c.ScanID > 0 {
					count, _ := utils.ParseDalfoxOutput(c.ScanID, c.F.DalfoxOut)
					if count > 0 {
						logger.Success("  Found %d XSS vulnerabilities!", count)
					} else {
						logger.Info("  No XSS vulnerabilities found")
					}
				}
			}
		} else {
			logger.Info("  No parameterized URLs found to test for XSS")
		}
		c.StateMgr.MarkStepComplete(c.State, "xss_scanning")
	} else {
		logger.Section("Step 20: Skipping Dalfox (--skip-dalfox)")
		c.StateMgr.MarkStepComplete(c.State, "xss_scanning")
	}
}
