// Package company_flow implements the Company Reconnaissance Workflow.
// It mirrors the wildcard_flow architecture: the CLI (cli/company.go) is a
// thin shim that builds a RunConfig and calls Run(). All scan logic lives here.
//
// Steps:
//  1. ASN & Network Range Discovery (Metabigor)
//  2. Root Domain Discovery (Amass Intel)
//  3. Cloud Enumeration (Cloud Enum)
package company_flow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/pkg/orchestrate"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// RunConfig — supplied by cli/company.go
// ─────────────────────────────────────────────────────────────

// RunConfig holds every option the CLI passes into the workflow.
type RunConfig struct {
	Company   string
	ResultDir string
	Mode      string
	Verbose   bool
	Cfg       *config.Config

	SkipMetabigor  bool
	SkipAmassIntel bool
	SkipCloudEnum  bool
}

// ─────────────────────────────────────────────────────────────
// Ctx — shared state passed to every step function
// ─────────────────────────────────────────────────────────────

// Ctx is the shared execution context for the company scan workflow.
type Ctx struct {
	GoCtx     context.Context
	Cancel    context.CancelFunc
	ScanID    int64
	Company   string
	ResultDir string
	StartTime time.Time

	// Tool runner (steps may use r.Run directly for custom args)
	R  runner.Runner
	Tb *tools.ToolBox

	// State tracking (F18)
	StateMgr *scan.Manager
	State    *scan.State

	// Notifications
	Notifier           *notify.Notifier
	NotifyStepComplete bool

	// Step counters (updated by each step, kept for backward compat
	// with step functions that increment c.Completed/c.Failed)
	Total     int
	Completed int
	Failed    int

	// Skip flags
	SkipMetabigor  bool
	SkipAmassIntel bool
	SkipCloudEnum  bool

	// Full config (needed for amass timeout, tool overrides)
	Cfg *config.Config
}

// cancelled returns true when the parent context has been cancelled.
func (c *Ctx) cancelled() bool {
	return c.GoCtx.Err() != nil
}

// ─────────────────────────────────────────────────────────────
// Run — main entry point (called by cli/company.go)
// ─────────────────────────────────────────────────────────────

// Run executes the full Company Reconnaissance Workflow.
func Run(cfg RunConfig) error {
	startTime := time.Now()

	// ── Context & signal plumbing ────────────────────────────
	goCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	orchestrate.HandleSignals(goCtx, cancel)

	// ── Database record ──────────────────────────────────────
	configJSON, _ := json.Marshal(map[string]interface{}{
		"target":           cfg.Company,
		"skip_metabigor":   cfg.SkipMetabigor,
		"skip_amass_intel": cfg.SkipAmassIntel,
		"skip_cloud_enum":  cfg.SkipCloudEnum,
	})

	dbScan, err := database.CreateScan(cfg.Company, "company", cfg.ResultDir, string(configJSON))
	if err != nil {
		logger.Warning("Failed to create scan record: %v", err)
	}
	scanID := int64(0)
	if dbScan != nil {
		scanID = dbScan.ID
	}

	// ── Scan header & state ──────────────────────────────────
	logger.ScanHeader("Company", cfg.Company, scanID)
	logger.InitScanUI(len(scan.CompanySteps))

	stateMgr := scan.NewManager(paths.StateDir())
	scanState, _ := stateMgr.CreateState(scanID, cfg.Company, "company", cfg.ResultDir, len(scan.CompanySteps), configJSON)

	// ── Runner, ToolBox & Notifier ──────────────────────────
	infra := orchestrate.NewInfra(cfg.Mode, cfg.Verbose, cfg.Cfg)

	// ── Build shared Ctx ─────────────────────────────────────
	c := &Ctx{
		GoCtx:              goCtx,
		Cancel:             cancel,
		ScanID:             scanID,
		Company:            cfg.Company,
		ResultDir:          cfg.ResultDir,
		StartTime:          startTime,
		R:                  infra.Runner,
		Tb:                 infra.ToolBox,
		StateMgr:           stateMgr,
		State:              scanState,
		Notifier:           infra.Notifier,
		NotifyStepComplete: cfg.Cfg != nil && cfg.Cfg.Notifications.StepComplete,
		SkipMetabigor:      cfg.SkipMetabigor,
		SkipAmassIntel:     cfg.SkipAmassIntel,
		SkipCloudEnum:      cfg.SkipCloudEnum,
		Cfg:                cfg.Cfg,
	}

	// Wire notification logging (FileDebug no-ops if --log is inactive)
	if c.Notifier != nil {
		c.Notifier.LogFunc = logger.FileDebug
	}

	// ── Execute steps ────────────────────────────────────────

	if executeStep(c, 1, "metabigor", "ASN & Network Range Discovery (Metabigor)", stepMetabigor) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if executeStep(c, 2, "amass_intel", "Root Domain Discovery (Amass Intel)", stepAmassIntel) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if executeStep(c, 3, "cloud_enum", "Cloud Enumeration (Cloud Enum)", stepCloudEnum) {
		finalizeScan(c, "cancelled")
		return nil
	}

	finalizeScan(c, "completed")
	return nil
}

func executeStep(c *Ctx, stepNumber int, stepName, stepDescription string, fn func(*Ctx) bool) bool {
	completedBefore := c.Completed
	cancelled := fn(c)

	// Track state for dashboard display (F18)
	if c.Completed > completedBefore {
		// Step succeeded — mark in scan state
		if c.State != nil && c.StateMgr != nil {
			c.StateMgr.MarkStepComplete(c.State, stepName)
		}
		notifyStepCompletion(c, stepNumber, stepName, stepDescription)
	} else if c.Failed > (c.Total - c.Completed - 1) {
		// Step failed — mark in scan state
		if c.State != nil && c.StateMgr != nil {
			c.StateMgr.MarkStepFailed(c.State, stepName, fmt.Errorf("step failed"))
		}
	}

	return cancelled
}

func notifyStepCompletion(c *Ctx, stepNumber int, stepName, stepDescription string) {
	if c.Notifier == nil || !c.NotifyStepComplete {
		return
	}

	if err := c.Notifier.SendStepComplete(notify.StepComplete{
		Target:          c.Company,
		ScanID:          c.ScanID,
		ScanType:        "company",
		StepName:        stepName,
		StepDescription: stepDescription,
		StepNumber:      stepNumber,
		TotalSteps:      len(scan.CompanySteps),
		Duration:        time.Since(c.StartTime),
		FindingsCount:   countFindingsForStep(c, stepName),
		Timestamp:       time.Now(),
	}); err != nil {
		logger.Warning("Failed to send step completion notification: %v", err)
	}
}

func countFindingsForStep(c *Ctx, stepName string) int {
	countLines := func(files ...string) int {
		total := 0
		for _, file := range files {
			if count, err := utils.CountFileLines(file); err == nil {
				total += count
			}
		}
		return total
	}

	switch stepName {
	case "metabigor":
		return countLines(filepath.Join(c.ResultDir, "asn_ranges.txt"))
	case "amass_intel":
		return countLines(filepath.Join(c.ResultDir, "root_domains.txt"))
	case "cloud_enum":
		return countLines(filepath.Join(c.ResultDir, "cloud_enum.json"))
	default:
		return 0
	}
}

// ─────────────────────────────────────────────────────────────
// finalizeScan — persist summary, list output files, hints
// ─────────────────────────────────────────────────────────────

func finalizeScan(c *Ctx, status string) {
	duration := time.Since(c.StartTime)

	if c.ScanID > 0 {
		database.UpdateScanStatus(c.ScanID, status)
	}

	// Clean up state file on completion
	if status == "completed" && c.State != nil && c.StateMgr != nil {
		c.StateMgr.DeleteState(c.ScanID)
	}

	// Build stats map
	stats := map[string]string{
		"Steps completed": fmt.Sprintf("%d/%d", c.Completed, c.Total),
	}
	if c.Failed > 0 {
		stats["Failed"] = fmt.Sprintf("%d", c.Failed)
	}

	// Count non-empty output files
	entries, dirErr := os.ReadDir(c.ResultDir)
	if dirErr == nil {
		count := 0
		for _, e := range entries {
			if !e.IsDir() {
				if info, _ := e.Info(); info != nil && info.Size() > 0 {
					count++
				}
			}
		}
		if count > 0 {
			stats["Output files"] = fmt.Sprintf("%d", count)
		}
	}

	logger.ScanSummary(status, c.Company, c.ScanID, duration, stats)
	logger.Success("Results saved in: %s", c.ResultDir)

	// List output files with sizes
	if dirErr == nil {
		for _, e := range entries {
			if !e.IsDir() {
				if info, _ := e.Info(); info != nil && info.Size() > 0 {
					logger.Info("  📄 %s (%s)", e.Name(), utils.FormatSize(info.Size()))
				}
			}
		}
	}

	if c.ScanID > 0 {
		logger.NextSteps([]string{
			fmt.Sprintf("chaathan scans show %d    # View scan details", c.ScanID),
			"chaathan wildcard -d <discovered-domain>  # Run full recon on discovered domains",
		})
	}
}

// ─────────────────────────────────────────────────────────────
