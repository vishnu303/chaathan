// Package wildcard_flow implements the Wildcard Reconnaissance Workflow.
// It is separated from the CLI layer (cli/wildcard.go) so that all scan
// logic lives outside cobra and can be tested or embedded independently.
//
// Each scan phase (passive enumeration, DNS, probing, etc.) has its own
// file. All phases share a single *Ctx that carries output paths, tool
// runners, scan state, and option flags.
package wildcard_flow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/pkg/report"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"github.com/vishnu303/chaathan-flow/pkg/scan"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

// ─────────────────────────────────────────────────────────────
// RunConfig — supplied by cli/wildcard.go
// ─────────────────────────────────────────────────────────────

// RunConfig holds every option the CLI passes into the workflow.
type RunConfig struct {
	// Core
	Domain    string
	ResultDir string
	Mode      string
	Verbose   bool
	Cfg       *config.Config

	// Optional flags
	SkipAmass         bool
	SkipNuclei        bool
	SkipNaabu         bool
	SkipCrawl         bool
	SkipSubjack       bool
	SkipDalfox        bool
	SkipUncover       bool
	SkipTlsx          bool
	SkipArjun         bool
	SkipShuffleDNS    bool
	SkipSubdomainizer bool

	// Paths / tokens
	WordlistPath    string
	DNSWordlistPath string
	ResolversPath   string
	GitHubToken     string

	// Resume
	ResumeScanID int64

	// Post-scan
	GenerateReport bool
}

// ─────────────────────────────────────────────────────────────
// Files — all output file paths (keeps step funcs clean)
// ─────────────────────────────────────────────────────────────

// Files holds every output file path used across the workflow.
type Files struct {
	SubfinderOut       string
	AssetfinderOut     string
	Sublist3rOut       string
	AmassOut           string
	GithubSubsOut      string
	WaybackOut         string
	GauOut             string
	UncoverOut         string
	ConsolidatedSubs   string
	DnsxOut            string
	ShufflednsOut      string
	HttpxOut           string
	HttpxLiveHosts     string
	TlsxOut            string
	NaabuOut           string
	KatanaOut          string
	GospiderOut        string
	LinkfinderOut      string
	SubdomainizerOut   string
	ArjunOut           string
	ArjunURLsOut       string
	AllURLsRaw         string
	AllURLsLive        string
	ROIMetadataTargets string
	FfufOut            string
	NucleiOut          string
	NucleiURLOut       string
	NucleiURLTargets   string
	NucleiGFMatches    string
	NucleiFallback     string
	SubjackOut         string
	ParamURLsFile      string
	DalfoxOut          string
}

// newFiles builds all output paths from the result directory.
// Intermediate tool outputs go into intermediate_files/; the workflow
// reads and writes these during the scan. Final product files are
// exported into final_files/ by finalizeScan after all steps complete.
func newFiles(dir string) Files {
	iDir := filepath.Join(dir, "intermediate_files")
	j := func(name string) string { return filepath.Join(iDir, name) }
	// final_files/ paths for outputs that are also consumed as pipeline inputs
	fDir := filepath.Join(dir, "final_files")
	jf := func(name string) string { return filepath.Join(fDir, name) }
	_ = jf // suppress unused warning; used below for nuclei json outputs
	return Files{
		SubfinderOut:       j("subfinder.txt"),
		AssetfinderOut:     j("assetfinder.txt"),
		Sublist3rOut:       j("sublist3r.txt"),
		AmassOut:           j("amass.txt"),
		GithubSubsOut:      j("github_subdomains.txt"),
		WaybackOut:         j("waybackurls.txt"),
		GauOut:             j("gau.txt"),
		UncoverOut:         j("uncover.json"),
		ConsolidatedSubs:   j("all_subdomains.txt"),
		DnsxOut:            j("dnsx_resolved.json"),
		ShufflednsOut:      j("shuffledns_bruteforce.txt"),
		HttpxOut:           j("httpx_live.json"),
		HttpxLiveHosts:     j("httpx_live_hosts.txt"),
		TlsxOut:            j("tlsx_certs.json"),
		NaabuOut:           j("naabu_ports.txt"),
		KatanaOut:          j("katana_urls.txt"),
		GospiderOut:        j("gospider_urls.txt"),
		LinkfinderOut:      j("linkfinder_endpoints.txt"),
		SubdomainizerOut:   j("subdomainizer_subs.txt"),
		ArjunOut:           j("arjun_params.json"),
		ArjunURLsOut:       j("arjun_urls.txt"),
		AllURLsRaw:         j("all_urls_raw.txt"),
		AllURLsLive:        j("all_urls_live.txt"),
		ROIMetadataTargets: j("roi_metadata_targets.txt"),
		FfufOut:            j("ffuf_results.json"),
		// Nuclei JSON outputs go to final_files/ — they are product files
		NucleiOut:        jf("nuclei_vulns.json"),
		NucleiURLOut:     jf("nuclei_url_vulns.json"),
		DalfoxOut:        jf("dalfox_xss.json"),
		// Nuclei working files (URL target lists) stay in intermediate_files/
		NucleiURLTargets: j("nuclei_url_targets.txt"),
		NucleiGFMatches:  j("nuclei_url_targets_gf.txt"),
		NucleiFallback:   j("nuclei_url_targets_fallback.txt"),
		SubjackOut:       j("subjack_takeovers.txt"),
		ParamURLsFile:    j("param_urls_live.txt"),
	}
}

// ─────────────────────────────────────────────────────────────
// Ctx — shared state passed to every step function
// ─────────────────────────────────────────────────────────────

// Ctx is the shared execution context for the entire scan workflow.
// Every step function receives a *Ctx instead of a long parameter list.
type Ctx struct {
	GoCtx     context.Context
	Cancel    context.CancelFunc
	SkipChan  chan struct{}
	ScanID    int64
	Domain    string
	ResultDir string
	StartTime time.Time

	// Tools & infrastructure
	Tb       *tools.ToolBox
	StateMgr *scan.Manager
	State    *scan.State
	Notifier *notify.Notifier

	// All file paths
	F Files

	// Option flags (mirrors RunConfig)
	SkipAmass         bool
	SkipNuclei        bool
	SkipNaabu         bool
	SkipCrawl         bool
	SkipSubjack       bool
	SkipDalfox        bool
	SkipUncover       bool
	SkipTlsx          bool
	SkipArjun         bool
	SkipShuffleDNS    bool
	SkipSubdomainizer bool
	WordlistPath      string
	DNSWordlistPath   string
	ResolversPath     string
	GitHubToken       string
	Verbose           bool
	GenerateReport    bool
}

// cancelled returns true when the parent context has been cancelled.
func (c *Ctx) cancelled() bool {
	return c.GoCtx.Err() != nil
}

// urlSources returns the list of URL source files (used by step 15).
func (c *Ctx) urlSources() []string {
	return []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
		c.F.LinkfinderOut,
		c.F.ArjunURLsOut,
	}
}

// ─────────────────────────────────────────────────────────────
// Run — main entry point (called by cli/wildcard.go)
// ─────────────────────────────────────────────────────────────

// Run executes the full Wildcard Reconnaissance Workflow.
// It returns a non-nil error only for fatal pre-scan failures;
// individual step failures are logged and do not abort the run.
func Run(cfg RunConfig) error {
	startTime := time.Now()

	// ── Context & signal plumbing ────────────────────────────
	goCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	skipChan := make(chan struct{}, 1)

	// Handle Ctrl+C / SIGTERM — cancel the workflow context
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logger.Warning("Received interrupt signal. Stopping...")
			cancel()
		case <-goCtx.Done():
			// context already cancelled (e.g. resume error path)
		}
		signal.Stop(sigChan)
	}()

	// Listen for 's'/'S' on stdin — skip the currently running tool
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				continue
			}
			if buf[0] == 's' || buf[0] == 'S' {
				select {
				case skipChan <- struct{}{}:
					logger.Warning("⏭ Skip requested — skipping current tool...")
				default:
					// already a skip pending; ignore
				}
			}
		}
	}()

	// ── Database record ──────────────────────────────────────
	configJSON, _ := json.Marshal(map[string]interface{}{
		"skip_amass":         cfg.SkipAmass,
		"skip_nuclei":        cfg.SkipNuclei,
		"skip_naabu":         cfg.SkipNaabu,
		"skip_crawl":         cfg.SkipCrawl,
		"skip_subjack":       cfg.SkipSubjack,
		"skip_dalfox":        cfg.SkipDalfox,
		"skip_uncover":       cfg.SkipUncover,
		"skip_tlsx":          cfg.SkipTlsx,
		"skip_arjun":         cfg.SkipArjun,
		"skip_shuffledns":    cfg.SkipShuffleDNS,
		"skip_subdomainizer": cfg.SkipSubdomainizer,
		"wordlist":           cfg.WordlistPath,
		"dns_wordlist":       cfg.DNSWordlistPath,
		"github":             cfg.GitHubToken != "",
	})

	dbScan, err := database.CreateScan(cfg.Domain, "wildcard", cfg.ResultDir, string(configJSON))
	if err != nil {
		logger.Warning("Failed to create scan record: %v", err)
	}
	scanID := int64(0)
	if dbScan != nil {
		scanID = dbScan.ID
	}

	// ── Scan header & state ──────────────────────────────────
	logger.ScanHeader("Wildcard", cfg.Domain, scanID)
	logger.InitScanUI(len(scan.WildcardSteps))

	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".chaathan", "state")
	stateMgr := scan.NewManager(stateDir)

	var scanState *scan.State
	if cfg.ResumeScanID > 0 {
		existingState, err := stateMgr.LoadState(cfg.ResumeScanID)
		if err != nil {
			return fmt.Errorf("cannot resume scan #%d: %w", cfg.ResumeScanID, err)
		}
		scanState = existingState
		scanID = cfg.ResumeScanID
		logger.Info("Resuming scan #%d (%.1f%% complete, %d/%d steps done)",
			scanID, scanState.Progress(), len(scanState.CompletedSteps), scanState.TotalSteps)
	} else {
		scanState, _ = stateMgr.CreateState(scanID, cfg.Domain, "wildcard", cfg.ResultDir, configJSON)
	}

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
	if cfg.Cfg != nil {
		tb.WithAPIKeys(&cfg.Cfg.APIKeys)
	}

	// ── Notifier ─────────────────────────────────────────────
	var notifier *notify.Notifier
	if cfg.Cfg != nil && cfg.Cfg.Notifications.Enabled {
		notifier = notify.New(&cfg.Cfg.Notifications)
	}

	// ── Ensure output subdirectories exist ───────────────────
	if err := os.MkdirAll(filepath.Join(cfg.ResultDir, "intermediate_files"), 0755); err != nil {
		return fmt.Errorf("cannot create intermediate_files dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.ResultDir, "final_files"), 0755); err != nil {
		return fmt.Errorf("cannot create final_files dir: %w", err)
	}

	// ── Build shared Ctx ─────────────────────────────────────
	c := &Ctx{
		GoCtx:             goCtx,
		Cancel:            cancel,
		SkipChan:          skipChan,
		ScanID:            scanID,
		Domain:            cfg.Domain,
		ResultDir:         cfg.ResultDir,
		StartTime:         startTime,
		Tb:                tb,
		StateMgr:          stateMgr,
		State:             scanState,
		Notifier:          notifier,
		F:                 newFiles(cfg.ResultDir),
		SkipAmass:         cfg.SkipAmass,
		SkipNuclei:        cfg.SkipNuclei,
		SkipNaabu:         cfg.SkipNaabu,
		SkipCrawl:         cfg.SkipCrawl,
		SkipSubjack:       cfg.SkipSubjack,
		SkipDalfox:        cfg.SkipDalfox,
		SkipUncover:       cfg.SkipUncover,
		SkipTlsx:          cfg.SkipTlsx,
		SkipArjun:         cfg.SkipArjun,
		SkipShuffleDNS:    cfg.SkipShuffleDNS,
		SkipSubdomainizer: cfg.SkipSubdomainizer,
		WordlistPath:      cfg.WordlistPath,
		DNSWordlistPath:   cfg.DNSWordlistPath,
		ResolversPath:     cfg.ResolversPath,
		GitHubToken:       cfg.GitHubToken,
		Verbose:           cfg.Verbose,
		GenerateReport:    cfg.GenerateReport,
	}

	logger.Info("💡 Press 's' at any time to skip the current tool")
	logger.Info("Mode: %s", cfg.Mode)

	// ── Execute all steps ────────────────────────────────────

	// ── Phase 1: Asset Discovery (Steps 1–4) ──────────────────────
	if stepPassiveEnum(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepActiveEnum(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepGitHubRecon(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepSearchEngineRecon(c) {
		finalizeScan(c, "cancelled")
		return nil
	}

	// ── Phase 2: Validation & Probing (Steps 5–9) ──────────────────
	if stepDNSConsolidation(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepDNSBruteforce(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepHTTPProbing(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepTLSAnalysis(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepPortScanning(c) {
		finalizeScan(c, "cancelled")
		return nil
	}

	// ── Phase 3: Content Discovery (Steps 10–16) ─────────────────
	// Step 10: Historical URL Discovery (Wayback/GAU) — runs here so URLs
	// are collected only for validated live hosts, not dead subdomains.
	if stepURLDiscovery(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepWebCrawling(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepJSAnalysis(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepJSSubdomains(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepParamDiscovery(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepURLConsolidation(c) {
		finalizeScan(c, "cancelled")
		return nil
	}

	// ── Phase 3 (cont.) Step 16: Directory Fuzzing ──────────────
	if stepDirFuzzing(c) {
		finalizeScan(c, "cancelled")
		return nil
	}

	// ── Phase 4: Vulnerability Scanning (Steps 17–20) ──────────
	if stepVulnScanningInfra(c) {
		finalizeScan(c, "cancelled")
		return nil
	}
	if stepVulnScanningURLs(c) {
		finalizeScan(c, "cancelled")
		return nil
	}

	// ── Phase 4 (cont.) Steps 19–20 ───────────────────────────
	if stepTakeoverDetection(c) {
		finalizeScan(c, "cancelled")
		return nil
	}

	// ── Phase 4 Step 20: XSS Scanning ──────────────────────────
	stepXSSScanning(c)

	finalizeScan(c, "completed")
	return nil
}

// ─────────────────────────────────────────────────────────────
// finalizeScan — persist summary, export, notify, report
// ─────────────────────────────────────────────────────────────

func finalizeScan(c *Ctx, status string) {
	duration := time.Since(c.StartTime)

	if c.ScanID > 0 {
		database.UpdateScanStatus(c.ScanID, status)
	}

	// Clean up state file for completed scans
	if status == "completed" && c.StateMgr != nil && c.State != nil {
		c.StateMgr.DeleteState(c.State.ScanID)
	}

	stats := make(map[string]string)
	if c.ScanID > 0 {
		dbStats, err := database.GetScanStats(c.ScanID)
		if err == nil {
			stats["Subdomains"] = fmt.Sprintf("%d (Live: %d)", dbStats.TotalSubdomains, dbStats.LiveSubdomains)
			stats["Open Ports"] = fmt.Sprintf("%d", dbStats.TotalPorts)
			stats["URLs"] = fmt.Sprintf("%d", dbStats.TotalURLs)
			stats["Endpoints"] = fmt.Sprintf("%d", dbStats.TotalEndpoints)
			for sev, count := range dbStats.Vulnerabilities {
				stats["Vuln ("+sev+")"] = fmt.Sprintf("%d", count)
			}

			if c.Notifier != nil {
				c.Notifier.SendScanComplete(notify.ScanComplete{
					Target:   c.Domain,
					ScanID:   c.ScanID,
					Duration: duration,
					Stats: map[string]int{
						"subdomains": dbStats.TotalSubdomains,
						"ports":      dbStats.TotalPorts,
						"vulns":      len(dbStats.Vulnerabilities),
					},
				})
			}
		}

		logger.ScanSummary(status, c.Domain, c.ScanID, duration, stats)
		logger.Success("Results saved in: %s", c.ResultDir)

		// Export results into final_files/
		if status == "completed" || status == "cancelled" {
			finalDir := filepath.Join(c.ResultDir, "final_files")
			logger.Info("\nExporting results to final_files/...")
			if err := utils.ExportResults(c.ScanID, finalDir); err != nil {
				logger.Warning("Failed to export some results: %v", err)
			} else {
				logger.Success("Results exported to final_files/")
			}
			if err := utils.ExportSummary(c.ScanID, finalDir, c.Domain); err != nil {
				logger.Warning("Failed to create summary: %v", err)
			}
		}

		// Generate report
		if c.GenerateReport && status == "completed" {
			logger.Info("\nGenerating report...")
			rpt, err := report.Generate(c.ScanID)
			if err == nil {
				home, _ := os.UserHomeDir()
				reportPath := filepath.Join(home, ".chaathan", "reports", fmt.Sprintf("scan_%d.md", c.ScanID))
				if err := rpt.Export(report.FormatMarkdown, reportPath); err == nil {
					logger.Success("Report saved: %s", reportPath)
				}
				localReportPath := filepath.Join(c.ResultDir, "REPORT.md")
				if err := rpt.Export(report.FormatMarkdown, localReportPath); err == nil {
					logger.Success("Report also saved: %s", localReportPath)
				}
			}
		}
	}

	if c.ScanID > 0 {
		logger.NextSteps([]string{
			fmt.Sprintf("chaathan scans show %d       # View scan details", c.ScanID),
			fmt.Sprintf("chaathan query vulns %d      # List vulnerabilities", c.ScanID),
			fmt.Sprintf("chaathan report generate %d  # Generate full report", c.ScanID),
		})
	}
}
