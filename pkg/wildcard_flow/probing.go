// Live Web Probing & TLS Analysis — Steps 8–9
//
//  8. Live Web Server Probing (Httpx)
//  9. TLS Certificate Analysis (tlsx) + host metadata enrichment
package wildcard_flow

import (
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/metadata"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 8 — Live Web Server Probing (Httpx)
// ─────────────────────────────────────────────────────────────

// stepHTTPProbing probes all consolidated subdomains with Httpx.
// Returns true if the scan should be cancelled.
func stepHTTPProbing(c *Ctx) bool {
	if c.State.IsStepCompleted("http_probing") {
		logger.Section("Step 8: Live Web Server Probing [RESUMED — skipping]")
		return c.cancelled()
	}
	logger.Section("Step 8: Live Web Server Probing")
	logger.SubStep("Running Httpx...")

	if err := c.Tb.RunHttpx(c.GoCtx, c.F.ConsolidatedSubs, c.F.HttpxOut); err != nil {
		c.StateMgr.MarkStepFailed(c.State, "http_probing", err)
		logger.Error("Httpx failed: %v", err)
	} else {
		if c.ScanID > 0 {
			count, _ := utils.ParseHttpxOutput(c.ScanID, c.F.HttpxOut)
			logger.Info("  Found %d live hosts", count)
		}
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
		logger.Section("Step 9: TLS Certificate Analysis (tlsx) [RESUMED — skipping]")
	} else if !c.SkipTlsx {
		logger.Section("Step 9: TLS Certificate Analysis (tlsx)")
		logger.SubStep("Running tlsx — extracting SANs and checking cert issues...")

		if err := c.Tb.RunTlsx(c.GoCtx, c.F.ConsolidatedSubs, c.F.TlsxOut); err != nil {
			c.StateMgr.MarkStepFailed(c.State, "tls_analysis", err)
			logger.Warning("tlsx failed: %v", err)
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
		logger.Section("Step 9: Skipping tlsx (--skip-tlsx)")
		c.StateMgr.MarkStepComplete(c.State, "tls_analysis")
	}

	// Host metadata enrichment (always attempted after step 9)
	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		hostTargetCount := collectLiveHostTargetsFromHttpx(c.F.HttpxOut, c.F.HttpxLiveHosts)
		if hostTargetCount > 0 {
			logger.SubStep("Collecting lightweight host metadata for ROI scoring...")
			hostTargets := loadLineSlice(c.F.HttpxLiveHosts, 250)
			if count, err := metadata.CollectHostMetadata(c.ScanID, hostTargets); err != nil {
				logger.Warning("Host metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Info("  Stored metadata for %d live hosts", count)
			}
		}
	}

	return c.cancelled()
}
