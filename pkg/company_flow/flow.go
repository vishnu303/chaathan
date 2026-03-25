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
	"os/signal"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
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

	// Notifications
	Notifier           *notify.Notifier
	NotifyStepComplete bool

	// Step counters (updated by each step)
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

	// Handle Ctrl+C / SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logger.Warning("Received interrupt signal. Stopping...")
			cancel()
		case <-goCtx.Done():
		}
		signal.Stop(sigChan)
	}()

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

	// ── Scan header ──────────────────────────────────────────
	logger.ScanHeader("Company", cfg.Company, scanID)
	logger.InitScanUI(3)

	// ── Runner & ToolBox ─────────────────────────────────────
	var r runner.Runner
	if cfg.Cfg != nil && cfg.Cfg.General.MaxRetries > 0 {
		delay := time.Duration(cfg.Cfg.General.RetryDelaySec) * time.Second
		if delay == 0 {
			delay = 3 * time.Second
		}
		r = runner.NewWithRetry(cfg.Mode, cfg.Verbose, cfg.Cfg.General.MaxRetries, delay)
	} else {
		r = runner.NewWithRetry(cfg.Mode, cfg.Verbose, 1, 3*time.Second)
	}

	var toolsCfg *config.ToolsConfig
	if cfg.Cfg != nil {
		toolsCfg = &cfg.Cfg.Tools
	}
	tb := tools.New(r, toolsCfg)

	var notifier *notify.Notifier
	if cfg.Cfg != nil && cfg.Cfg.Notifications.Enabled {
		notifier = notify.New(&cfg.Cfg.Notifications)
	}

	// ── Build shared Ctx ─────────────────────────────────────
	c := &Ctx{
		GoCtx:          goCtx,
		Cancel:         cancel,
		ScanID:         scanID,
		Company:        cfg.Company,
		ResultDir:      cfg.ResultDir,
		StartTime:      startTime,
		R:              r,
		Tb:             tb,
		Notifier:       notifier,
		NotifyStepComplete: cfg.Cfg != nil && cfg.Cfg.Notifications.StepComplete,
		SkipMetabigor:  cfg.SkipMetabigor,
		SkipAmassIntel: cfg.SkipAmassIntel,
		SkipCloudEnum:  cfg.SkipCloudEnum,
		Cfg:            cfg.Cfg,
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
	if c.Completed > completedBefore {
		notifyStepCompletion(c, stepNumber, stepName, stepDescription)
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
		TotalSteps:      3,
		Duration:        time.Since(c.StartTime),
		Timestamp:       time.Now(),
	}); err != nil {
		logger.Warning("Failed to send step completion notification: %v", err)
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
