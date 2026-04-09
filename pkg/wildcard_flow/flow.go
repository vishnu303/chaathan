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
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/pkg/orchestrate"
	"github.com/vishnu303/chaathan-flow/pkg/paths"
	"github.com/vishnu303/chaathan-flow/pkg/report"
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
	SkipTakeovers     bool
	SkipDalfox        bool
	SkipUncover       bool
	SkipTlsx          bool
	SkipArjun         bool
	SkipShuffleDNS    bool
	SkipHakrawler     bool
	SkipFingerprint   bool

	// Paths / tokens
	WordlistPath    string
	DNSWordlistPath string
	ResolversPath   string
	GitHubToken     string

	// Control parameters
	ResumeScanID int64

	// Post-scan
	GenerateReport bool

	// Logging
	// SaveLog controls whether scan output is mirrored to a log file in
	// ~/.chaathan/logs/ (plain text, ANSI stripped). The filename is
	// generated automatically as <domain>_<scanID>_<timestamp>.log.
	SaveLog bool
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
	UncoverHostsOut    string
	ConsolidatedSubs   string
	DnsxOut            string
	ShufflednsOut      string
	HttpxOut           string
	HttpxLiveHosts     string
	TlsxOut            string
	NaabuOut           string
	KatanaOut          string
	GospiderOut        string
	GoLinkFinderOut    string
	HakrawlerOut       string
	ArjunOut           string
	ArjunURLsOut       string
	AllURLsRaw         string
	AllURLsLive        string
	JSURLsFile         string
	JSDownloadsDir     string
	JSCombinedFile     string
	GFJSMatches        string
	GFSecretsMatches   string
	GFSecretsFinal     string
	ROIMetadataTargets string
	FfufOut            string
	NucleiOut          string
	NucleiURLOut       string
	NucleiURLTargets   string
	NucleiGFMatches    string
	SubjackOut         string
	ParamURLsFile      string
	DalfoxOut          string
	HttpxTechOut       string
	NucleiWafOut       string
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
	return Files{
		SubfinderOut:       j("subfinder.txt"),
		AssetfinderOut:     j("assetfinder.txt"),
		Sublist3rOut:       j("sublist3r.txt"),
		AmassOut:           j("amass.txt"),
		GithubSubsOut:      j("github_subdomains.txt"),
		WaybackOut:         j("waybackurls.txt"),
		GauOut:             j("gau.txt"),
		UncoverOut:         j("uncover.json"),
		UncoverHostsOut:    j("uncover_hosts.txt"),
		ConsolidatedSubs:   j("all_subdomains.txt"),
		DnsxOut:            j("dnsx_resolved.json"),
		ShufflednsOut:      j("shuffledns_bruteforce.txt"),
		HttpxOut:           j("httpx_live.json"),
		HttpxLiveHosts:     j("httpx_live_hosts.txt"),
		TlsxOut:            j("tlsx_certs.json"),
		NaabuOut:           j("naabu_ports.txt"),
		KatanaOut:          j("katana_urls.txt"),
		GospiderOut:        j("gospider_urls.txt"),
		GoLinkFinderOut:    j("golinkfinder_endpoints.txt"),
		HakrawlerOut:       j("hakrawler_crawl.txt"),
		ArjunOut:           j("arjun_params.json"),
		ArjunURLsOut:       j("arjun_urls.txt"),
		AllURLsRaw:         j("all_urls_raw.txt"),
		AllURLsLive:        j("all_urls_live.txt"),
		JSURLsFile:         j("js_urls.txt"),
		JSDownloadsDir:     j("js_downloads"),
		JSCombinedFile:     j("js_combined.txt"),
		GFJSMatches:        j("gf_js_matches.txt"),
		GFSecretsMatches:   j("gf_secrets_matches.txt"),
		GFSecretsFinal:     jf("gf_secrets_findings.txt"),
		ROIMetadataTargets: j("roi_metadata_targets.txt"),
		FfufOut:            j("ffuf_results.json"),
		// Nuclei JSON outputs go to final_files/ — they are product files
		NucleiOut:        jf("nuclei_vulns.json"),
		NucleiURLOut:     jf("nuclei_url_vulns.json"),
		DalfoxOut:        jf("dalfox_xss.jsonl"),
		// Nuclei working files (URL target lists) stay in intermediate_files/
		NucleiURLTargets: j("nuclei_url_targets.txt"),
		NucleiGFMatches:  j("nuclei_url_targets_gf.txt"),
		SubjackOut:       j("subjack_takeovers.txt"),
		ParamURLsFile:    j("param_urls_live.txt"),
		HttpxTechOut:     jf("httpx_tech.json"),
		NucleiWafOut:     jf("nuclei_waf.json"),
	}
}

// ─────────────────────────────────────────────────────────────
// Ctx — shared state passed to every step function
// ─────────────────────────────────────────────────────────────

// Ctx is the shared execution context for the entire scan workflow.
// Every step function receives a *Ctx instead of a long parameter list.
//
// RunConfig is embedded so that all CLI-supplied options (skip flags,
// paths, tokens, etc.) are accessible directly via c.FieldName.
// Adding a new option to RunConfig automatically makes it available
// to every step function — no manual copy block needed.
type Ctx struct {
	RunConfig // embedded — carries all CLI options

	GoCtx     context.Context
	Cancel    context.CancelFunc
	SkipChan  chan struct{}
	ScanID    int64
	StartTime time.Time

	// Tools & infrastructure
	Tb       *tools.ToolBox
	StateMgr *scan.Manager
	State    *scan.State
	Notifier *notify.Notifier

	// All file paths
	F Files

	// Notifications
	NotifyStepComplete bool

	// WAF evasion
	Proxy string // proxy URL for collector.go (from config or CLI override)

	// Log file path (set when SaveLog is true and file opened successfully)
	LogFilePath string
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
		c.F.GoLinkFinderOut,
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

	orchestrate.HandleSignals(goCtx, cancel)

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
					// "Skip requested" is logged by runWithSkip when it receives
					// the signal, ensuring correct message ordering.
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
		"skip_takeovers":     cfg.SkipTakeovers,
		"skip_dalfox":        cfg.SkipDalfox,
		"skip_uncover":       cfg.SkipUncover,
		"skip_tlsx":          cfg.SkipTlsx,
		"skip_arjun":         cfg.SkipArjun,
		"skip_shuffledns":    cfg.SkipShuffleDNS,
		"skip_hakrawler":     cfg.SkipHakrawler,
		"skip_fingerprint":   cfg.SkipFingerprint,
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

	// ── File logging ──────────────────────────────────────
	// logFilePath is declared here so it outlives the if-block and can be
	// stored on Ctx for display in next-steps at scan end.
	var logFilePath string
	if cfg.SaveLog {
		timestamp := startTime.Format("20060102_150405")
		logFileName := fmt.Sprintf("%s_%d_%s.log", cfg.Domain, scanID, timestamp)
		logFilePath = filepath.Join(paths.LogsDir(), logFileName)
		if err := logger.InitFileLog(logFilePath); err != nil {
			logger.Warning("Could not open log file: %v", err)
			logFilePath = "" // clear so Ctx doesn't show a broken path
		} else {
			logger.WriteLogHeader(cfg.Domain, scanID, logFilePath)
			logger.Info("Scan log: %s", logFilePath)
			defer logger.CloseFileLog()
		}
	}

	// ── Scan header & state ──────────────────────────────────
	logger.ScanHeader("Wildcard", cfg.Domain, scanID)
	logger.InitScanUI(len(scan.WildcardSteps))

	stateMgr := scan.NewManager(paths.StateDir())

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
		scanState, _ = stateMgr.CreateState(scanID, cfg.Domain, "wildcard", cfg.ResultDir, len(scan.WildcardSteps), configJSON)
	}

	// ── Runner, ToolBox & Notifier ──────────────────────────
	infra := orchestrate.NewInfra(cfg.Mode, cfg.Verbose, cfg.Cfg)

	// ── Ensure output subdirectories exist ───────────────────
	if err := os.MkdirAll(filepath.Join(cfg.ResultDir, "intermediate_files"), 0755); err != nil {
		return fmt.Errorf("cannot create intermediate_files dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.ResultDir, "final_files"), 0755); err != nil {
		return fmt.Errorf("cannot create final_files dir: %w", err)
	}

	// ── Build shared Ctx ─────────────────────────────────────
	c := &Ctx{
		RunConfig:          cfg,
		GoCtx:              goCtx,
		Cancel:             cancel,
		SkipChan:           skipChan,
		ScanID:             scanID,
		StartTime:          startTime,
		Tb:                 infra.ToolBox,
		StateMgr:           stateMgr,
		State:              scanState,
		Notifier:           infra.Notifier,
		F:                  newFiles(cfg.ResultDir),
		NotifyStepComplete: cfg.Cfg != nil && cfg.Cfg.Notifications.StepComplete,
		LogFilePath:        logFilePath,
	}

	// Wire proxy from config
	if cfg.Cfg != nil && cfg.Cfg.General.Proxy != "" {
		c.Proxy = cfg.Cfg.General.Proxy
	}

	logger.Info("💡 Press 's' at any time to skip the current tool")
	logger.Info("Mode: %s", cfg.Mode)

	// ── Step registry ───────────────────────────────────────
	// Each entry maps a scan.WildcardSteps name to its implementation.
	// Order must match scan.WildcardSteps (the source of truth for
	// step names, descriptions, and resume/progress tracking).
	steps := []struct {
		name string
		fn   func(*Ctx) bool
	}{
		// Phase 1 — Asset Discovery (Steps 1–5)
		{"passive_enum", stepPassiveEnum},
		{"active_enum", stepActiveEnum},
		{"github_recon", stepGitHubRecon},
		{"search_engine_recon", stepSearchEngineRecon},
		{"js_subdomain_discovery", stepJSSubdomains},

		// Phase 2 — Validation & Probing (Steps 6–10)
		{"dns_resolution", stepDNSConsolidation},
		{"dns_bruteforce", stepDNSBruteforce},
		{"http_probing", stepHTTPProbing},
		{"tls_analysis", stepTLSAnalysis},
		{"port_scanning", stepPortScanning},

		// Phase 3 — Content Discovery (Steps 11–17)
		{"url_discovery", stepURLDiscovery},
		{"web_crawling", stepWebCrawling},
		{"js_analysis", stepJSAnalysis},
		{"param_discovery", stepParamDiscovery},
		{"url_consolidation", stepURLConsolidation},
		{"js_secret_scan", stepJSSecretScan},
		{"dir_fuzzing", stepDirFuzzing},

		// Phase 4 — Vulnerability Scanning (Steps 18–21)
		{"vuln_scanning", stepVulnScanningInfra},
		{"vuln_scanning_urls", stepVulnScanningURLs},
		{"takeover_detection", stepTakeoverDetection},
		{"xss_scanning", stepXSSScanning},

		// Phase 5 — Fingerprinting (Step 22)
		{"tech_waf_fingerprinting", stepFingerprinting},
	}

	for _, step := range steps {
		if executeStep(c, step.name, step.fn) {
			finalizeScan(c, "cancelled")
			return nil
		}
	}

	finalizeScan(c, "completed")
	return nil
}

func executeStep(c *Ctx, stepName string, fn func(*Ctx) bool) bool {
	alreadyCompleted := c.State != nil && c.State.IsStepCompleted(stepName)
	cancelled := fn(c)
	if !alreadyCompleted && c.State != nil && c.State.IsStepCompleted(stepName) {
		notifyStepCompletion(c, stepName)
	}
	return cancelled
}

func notifyStepCompletion(c *Ctx, stepName string) {
	if c.Notifier == nil || !c.NotifyStepComplete {
		return
	}

	stepNumber := 0
	stepDescription := stepName
	for i, step := range scan.WildcardSteps {
		if step.Name == stepName {
			stepNumber = i + 1
			stepDescription = step.Description
			break
		}
	}

	if err := c.Notifier.SendStepComplete(notify.StepComplete{
		Target:          c.Domain,
		ScanID:          c.ScanID,
		ScanType:        "wildcard",
		StepName:        stepName,
		StepDescription: stepDescription,
		StepNumber:      stepNumber,
		TotalSteps:      len(scan.WildcardSteps),
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
			if cnt, err := utils.CountFileLines(file); err == nil {
				total += cnt
			}
		}
		return total
	}

	switch stepName {
	case "passive_enum":
		// Rather than raw lists, the best representation of this step is often the raw results concatenated.
		// Subdomains are consolidated later, but we can count the underlying outputs.
		return countLines(c.F.SubfinderOut, c.F.AssetfinderOut, c.F.Sublist3rOut)
	case "active_enum":
		return countLines(c.F.AmassOut)
	case "github_recon":
		return countLines(c.F.GithubSubsOut)
	case "search_engine_recon":
		return countLines(c.F.UncoverOut)
	case "dns_resolution":
		return countLines(c.F.DnsxOut)
	case "dns_bruteforce":
		return countLines(c.F.ShufflednsOut)
	case "http_probing":
		return countLines(c.F.HttpxLiveHosts)
	case "tls_analysis":
		return countLines(c.F.TlsxOut)
	case "port_scanning":
		return countLines(c.F.NaabuOut)
	case "url_discovery":
		return countLines(c.F.WaybackOut, c.F.GauOut)
	case "web_crawling":
		return countLines(c.F.KatanaOut, c.F.GospiderOut)
	case "js_analysis":
		return countLines(c.F.GoLinkFinderOut)
	case "js_subdomain_discovery":
		return countLines(c.F.HakrawlerOut)
	case "param_discovery":
		return countLines(c.F.ArjunURLsOut)
	case "url_consolidation":
		return countLines(c.F.AllURLsLive)
	case "js_secret_scan":
		return countLines(c.F.GFSecretsFinal)
	case "dir_fuzzing":
		return countLines(c.F.FfufOut)
	case "vuln_scanning":
		return countLines(c.F.NucleiOut)
	case "vuln_scanning_urls":
		return countLines(c.F.NucleiURLOut)
	case "takeover_detection":
		return countLines(c.F.SubjackOut)
	case "xss_scanning":
		return countLines(c.F.DalfoxOut)
	case "tech_waf_fingerprinting":
		return countLines(c.F.NucleiWafOut)
	default:
		return 0
	}
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
				label := sev
				if label == "" {
					label = "unknown"
				}
				stats["Vuln ("+label+")"] = fmt.Sprintf("%d", count)
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
				reportPath := filepath.Join(paths.ReportsDir(), fmt.Sprintf("scan_%d.md", c.ScanID))
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
		hints := []string{
			fmt.Sprintf("chaathan scans show %d       # View scan details", c.ScanID),
			fmt.Sprintf("chaathan query vulns %d      # List vulnerabilities", c.ScanID),
			fmt.Sprintf("chaathan report generate %d  # Generate full report", c.ScanID),
		}
		if c.LogFilePath != "" {
			hints = append([]string{fmt.Sprintf("cat %s  # full scan log", c.LogFilePath)}, hints...)
		}
		logger.NextSteps(hints)
	}
}
