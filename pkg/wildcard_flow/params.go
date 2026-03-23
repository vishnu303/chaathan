// Parameter Discovery & URL Consolidation — Steps 14–15
//
//  14. HTTP Parameter Discovery (Arjun) [Optional]
//  15. URL Consolidation & Live Check (httpx) + ROI metadata
package wildcard_flow

import (
	"context"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/metadata"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 14 — HTTP Parameter Discovery (Arjun)
// ─────────────────────────────────────────────────────────────

// stepParamDiscovery discovers HTTP parameters with Arjun.
// Returns true if the scan should be cancelled.
func stepParamDiscovery(c *Ctx) bool {
	if c.State.IsStepCompleted("param_discovery") {
		logger.Section("Step 14: HTTP Parameter Discovery (Arjun) [RESUMED — skipping]")
	} else if !c.SkipArjun {
		logger.Section("Step 14: HTTP Parameter Discovery (Arjun)")
		logger.SubStep("Running Arjun on https://%s...", c.Domain)

		if err := runWithSkip(c, "arjun", func(sCtx context.Context) error {
			return c.Tb.RunArjun(sCtx, "https://"+c.Domain, c.F.ArjunOut)
		}); err != nil {
			if err != ErrToolSkipped {
				c.StateMgr.MarkStepFailed(c.State, "param_discovery", err)
				logger.Warning("Arjun failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Arjun parameter discovery")
		}
	} else {
		logger.Section("Step 14: Skipping Arjun (--skip-arjun)")
	}
	c.StateMgr.MarkStepComplete(c.State, "param_discovery")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 15 — URL Consolidation & Live Check
// ─────────────────────────────────────────────────────────────

// stepURLConsolidation merges all URL sources, live-checks them with Httpx,
// and enriches ROI metadata for high-value targets.
// Returns true if the scan should be cancelled.
func stepURLConsolidation(c *Ctx) bool {
	if c.State.IsStepCompleted("url_consolidation") {
		logger.Section("Step 15: URL Consolidation & Live Check [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.Section("Step 15: URL Consolidation & Live Check")

	sources := c.urlSources()
	logger.SubStep("Merging URLs from %d sources...", len(sources))
	if err := utils.MergeAndDeduplicate(sources, c.F.AllURLsRaw); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "url_consolidation", err)
		logger.Warning("URL merge failed: %v", err)
	} else {
		rawCount, _ := utils.CountFileLines(c.F.AllURLsRaw)
		logger.Info("  Merged %d unique URLs", rawCount)
	}

	// Live-check all URLs with httpx
	logger.SubStep("Running httpx to live-check all URLs...")
	if err := runWithSkip(c, "httpx (URL check)", func(sCtx context.Context) error {
		return c.Tb.RunHttpxURLCheck(sCtx, c.F.AllURLsRaw, c.F.AllURLsLive)
	}); err != nil {
		if err != ErrToolSkipped {
			c.StateMgr.MarkStepFailed(c.State, "url_consolidation", err)
			logger.Warning("URL live-check failed: %v", err)
		}
		// Fallback: use raw URLs if live-check fails/is skipped
		if !utils.FileExists(c.F.AllURLsLive) {
			logger.Info("  Using raw URLs as fallback")
			copyFile(c.F.AllURLsRaw, c.F.AllURLsLive)
		}
	} else {
		liveCount, _ := utils.CountFileLines(c.F.AllURLsLive)
		logger.Success("  %d live URLs confirmed", liveCount)
	}

	// ROI metadata enrichment
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		metaTargetCount := collectROIMetadataTargetsFromFile(c.F.AllURLsLive, c.F.ROIMetadataTargets, 3, 150)
		if metaTargetCount > 0 {
			logger.SubStep("Collecting lightweight metadata for %d high-value URLs...", metaTargetCount)
			metaTargets := loadLineSlice(c.F.ROIMetadataTargets, 150)
			if count, err := metadata.CollectURLMetadata(c.ScanID, metaTargets); err != nil {
				logger.Warning("URL metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Info("  Stored path metadata for %d ROI candidate URLs", count)
			}
		}
	}

	c.StateMgr.MarkStepComplete(c.State, "url_consolidation")
	return c.cancelled()
}
