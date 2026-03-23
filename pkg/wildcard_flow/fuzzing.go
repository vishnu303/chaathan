// Directory Fuzzing — Step 16
//
//  16. Directory Fuzzing (ffuf) [Optional — requires --wordlist]
package wildcard_flow

import (
	"fmt"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 16 — Directory Fuzzing (ffuf)
// ─────────────────────────────────────────────────────────────

// stepDirFuzzing runs ffuf when a wordlist is provided via --wordlist.
// Returns true if the scan should be cancelled.
func stepDirFuzzing(c *Ctx) bool {
	if c.State.IsStepCompleted("dir_fuzzing") {
		logger.Section("Step 16: Directory Fuzzing (ffuf) [RESUMED — skipping]")
		return c.cancelled()
	}

	if c.WordlistPath != "" {
		logger.Section("Step 16: Directory Fuzzing (ffuf)")
		targetURL := fmt.Sprintf("https://%s/FUZZ", c.Domain)
		logger.SubStep("Running ffuf with wordlist: %s", c.WordlistPath)

		if err := c.Tb.RunFfufWithFUZZ(c.GoCtx, targetURL, c.WordlistPath, c.F.FfufOut); err != nil {
			c.StateMgr.MarkStepFailed(c.State, "dir_fuzzing", err)
			logger.Warning("ffuf failed: %v", err)
		} else {
			logger.SubStep("[Done] ffuf - Results: %s", c.F.FfufOut)
			if c.ScanID > 0 {
				count, err := utils.ParseFfufOutput(c.ScanID, c.F.FfufOut)
				if err != nil {
					logger.Warning("Failed to parse ffuf results: %v", err)
				} else if count > 0 {
					logger.Info("  Stored %d ffuf discoveries for ROI ranking", count)
				}
			}
		}
	} else {
		logger.Section("Step 16: Skipping ffuf (no --wordlist provided)")
		logger.Info("Provide --wordlist to enable ffuf")
	}

	c.StateMgr.MarkStepComplete(c.State, "dir_fuzzing")
	return c.cancelled()
}
