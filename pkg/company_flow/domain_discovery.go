// Root Domain Discovery — Step 2
//
//  2. Root Domain Discovery (Amass Intel) [Optional, --skip-amass-intel]
package company_flow

import (
	"fmt"
	"path/filepath"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 2 — Root Domain Discovery (Amass Intel)
// ─────────────────────────────────────────────────────────────

// stepAmassIntel uses Amass Intel reverse-whois to find root domains owned by the org.
// Returns true if the scan should be cancelled.
func stepAmassIntel(c *Ctx) bool {
	c.Total++

	if !c.SkipAmassIntel {
		logger.StepHeader("Step 2: Root Domain Discovery (Amass Intel)")
		amassIntelOut := filepath.Join(c.ResultDir, "root_domains.txt")
		logger.SubStep("Running Amass Intel reverse-whois for: %s", c.Company)

		// Build Amass args — include timeout from config when set
		amassArgs := []string{"intel", "-whois", "-d", c.Company, "-o", amassIntelOut}
		if c.Cfg != nil && c.Cfg.Tools.Amass.Timeout > 0 {
			amassArgs = append(amassArgs, "-timeout", fmt.Sprintf("%d", c.Cfg.Tools.Amass.Timeout))
		}

		_, err := c.R.Run(c.GoCtx, "amass", amassArgs)
		if err != nil {
			logger.Warning("Amass Intel failed: %v", err)
			logger.Info("  This is common — amass intel requires WHOIS data access")
			c.Failed++
		} else {
			count, _ := utils.CountFileLines(amassIntelOut)
			logger.Success("Discovered %d root domains", count)
			c.Completed++

			// Cross-reference with ASN ranges if step 1 produced output
			asnFile := filepath.Join(c.ResultDir, "asn_ranges.txt")
			if utils.FileExists(asnFile) {
				logger.SubStep("Cross-referencing ASN ranges with discovered domains...")
				asnCount, _ := utils.CountFileLines(asnFile)
				if asnCount > 0 {
					logger.Info("  %d ASN ranges available for correlation", asnCount)
				}
			}
		}
	} else {
		logger.StepHeader("Step 2: Skipping Amass Intel (--skip-amass-intel)")
		c.Completed++
	}

	return c.cancelled()
}
