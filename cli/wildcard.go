package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

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

var (
	targetDomain      string
	skipAmass         bool
	skipNuclei        bool
	skipNaabu         bool
	skipCrawl         bool
	skipSubjack       bool
	skipDalfox        bool
	skipUncover       bool
	skipTlsx          bool
	skipArjun         bool
	skipShuffleDNS    bool
	skipSubdomainizer bool
	wordlistPath      string
	dnsWordlistPath   string
	resolversPath     string
	githubToken       string
	resumeScanID      int64
	generateReport    bool
	skipToolChan      chan struct{} // channel to signal "skip current tool"
)

var wildcardCmd = &cobra.Command{
	Use:     "wildcard",
	Aliases: []string{"scan"},
	Short:   "Run the Wildcard Reconnaissance Workflow",
	Long: `
Runs a comprehensive 22-step recon & vulnerability scanning workflow:

 1. Passive Enumeration (Subfinder, Assetfinder, Sublist3r) [Parallel]
 2. URL Discovery (Waybackurls, GAU) [Parallel]
 3. Active Enumeration (Amass) [Optional, --skip-amass]
 4. GitHub Subdomain Discovery [Requires GITHUB_TOKEN]
 5. Search Engine Dorking (Uncover/Shodan/Censys) [Optional, --skip-uncover]
 6. Consolidation & DNS Resolution (DNSx)
 7. Smart Subdomain Permutation (Alterx → DNSx)
 8. DNS Brute-force (ShuffleDNS/MassDNS) [Optional, --skip-shuffledns]
 9. Live Web Probing (Httpx)
10. TLS Certificate Analysis (tlsx) [Optional, --skip-tlsx]
11. Port Scanning on ALL subdomains (Naabu) [Optional, --skip-naabu]
12. Web Crawling (Katana, GoSpider) [Parallel, --skip-crawl]
13. JavaScript Analysis (LinkFinder)
14. JavaScript Subdomain Extraction (SubDomainizer) [Optional, --skip-subdomainizer]
15. HTTP Parameter Discovery (Arjun) [Optional, --skip-arjun]
16. URL Consolidation & Live Check (httpx)
17. Wordlist Generation (CeWL)
18. Directory Fuzzing (ffuf) [Requires --wordlist]
19. Vulnerability Scanning — Infra (Nuclei) [Optional, --skip-nuclei]
20. Vulnerability Scanning — URLs (Nuclei) [Optional, --skip-nuclei]
21. Subdomain Takeover Detection (Subjack) [Optional, --skip-subjack]
22. XSS Scanning (Dalfox) [Optional, --skip-dalfox]

Press 's' at any time during scanning to skip the current tool.
All results are stored in a SQLite database for querying and reporting.
`,
	Run: runWildcard,
}

func init() {
	wildcardCmd.Flags().StringVarP(&targetDomain, "domain", "d", "", "Target domain (required)")
	wildcardCmd.Flags().BoolVar(&skipAmass, "skip-amass", false, "Skip Amass (slow but thorough)")
	wildcardCmd.Flags().BoolVar(&skipNuclei, "skip-nuclei", false, "Skip Nuclei vulnerability scanning")
	wildcardCmd.Flags().BoolVar(&skipNaabu, "skip-naabu", false, "Skip Naabu port scanning")
	wildcardCmd.Flags().BoolVar(&skipCrawl, "skip-crawl", false, "Skip web crawling (Katana + GoSpider)")
	wildcardCmd.Flags().BoolVar(&skipSubjack, "skip-subjack", false, "Skip subdomain takeover detection")
	wildcardCmd.Flags().BoolVar(&skipDalfox, "skip-dalfox", false, "Skip XSS scanning (Dalfox)")
	wildcardCmd.Flags().BoolVar(&skipUncover, "skip-uncover", false, "Skip search engine dorking (Uncover)")
	wildcardCmd.Flags().BoolVar(&skipTlsx, "skip-tlsx", false, "Skip TLS certificate analysis")
	wildcardCmd.Flags().BoolVar(&skipArjun, "skip-arjun", false, "Skip Arjun parameter discovery")
	wildcardCmd.Flags().BoolVar(&skipShuffleDNS, "skip-shuffledns", false, "Skip ShuffleDNS brute-force")
	wildcardCmd.Flags().BoolVar(&skipSubdomainizer, "skip-subdomainizer", false, "Skip SubDomainizer JS subdomain extraction")
	wildcardCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Wordlist for directory fuzzing (enables ffuf)")
	wildcardCmd.Flags().StringVar(&dnsWordlistPath, "dns-wordlist", "", "Wordlist for DNS brute-force with ShuffleDNS")
	wildcardCmd.Flags().StringVar(&resolversPath, "resolvers", "", "Custom DNS resolvers file for ShuffleDNS")
	wildcardCmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub token for GitHub recon (or use GITHUB_TOKEN env)")
	wildcardCmd.Flags().Int64Var(&resumeScanID, "resume", 0, "Resume a previous scan by ID")
	wildcardCmd.Flags().BoolVar(&generateReport, "report", true, "Generate report after scan")
	wildcardCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(wildcardCmd)
}

func runWildcard(cmd *cobra.Command, args []string) {
	// Validate domain input before doing anything
	if err := utils.ValidateDomain(targetDomain); err != nil {
		logger.Error("Invalid target: %v", err)
		return
	}

	startTime := time.Now()

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize skip-tool channel
	skipToolChan = make(chan struct{}, 1)

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Warning("Received interrupt signal. Stopping...")
		cancel()
	}()

	// Listen for 's' key to skip the current tool
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				continue
			}
			if buf[0] == 's' || buf[0] == 'S' {
				select {
				case skipToolChan <- struct{}{}:
					logger.Warning("⏭ Skip requested — skipping current tool...")
				default:
					// already a skip pending
				}
			}
		}
	}()

	logger.Info("💡 Press 's' at any time to skip the current tool")

	// Check for GitHub token in env if not provided via flag
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
		if Cfg != nil {
			token := Cfg.GetAPIKey("github")
			if token != "" {
				githubToken = token
			}
		}
	}

	logger.Info("Mode: %s", Mode)

	// Setup output directory
	resultDir, err := CreateOutputDir(targetDomain)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	// Create scan record in database
	configJSON, _ := json.Marshal(map[string]interface{}{
		"skip_amass":         skipAmass,
		"skip_nuclei":        skipNuclei,
		"skip_naabu":         skipNaabu,
		"skip_crawl":         skipCrawl,
		"skip_subjack":       skipSubjack,
		"skip_dalfox":        skipDalfox,
		"skip_uncover":       skipUncover,
		"skip_tlsx":          skipTlsx,
		"skip_arjun":         skipArjun,
		"skip_shuffledns":    skipShuffleDNS,
		"skip_subdomainizer": skipSubdomainizer,
		"wordlist":           wordlistPath,
		"dns_wordlist":       dnsWordlistPath,
		"github":             githubToken != "",
	})

	dbScan, err := database.CreateScan(targetDomain, "wildcard", resultDir, string(configJSON))
	if err != nil {
		logger.Warning("Failed to create scan record: %v", err)
	}
	scanID := int64(0)
	if dbScan != nil {
		scanID = dbScan.ID
	}

	// Show modern scan header
	logger.ScanHeader("Wildcard", targetDomain, scanID)
	logger.InitScanUI(len(scan.WildcardSteps))

	// Initialize scan state manager
	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".chaathan", "state")
	stateMgr := scan.NewManager(stateDir)

	var scanState *scan.State

	// Resume support: if --resume is provided, load existing state and skip completed steps
	if resumeScanID > 0 {
		existingState, err := stateMgr.LoadState(resumeScanID)
		if err != nil {
			logger.Error("Cannot resume scan #%d: %v", resumeScanID, err)
			return
		}
		scanState = existingState
		scanID = resumeScanID
		logger.Info("Resuming scan #%d (%.1f%% complete, %d/%d steps done)",
			scanID, scanState.Progress(), len(scanState.CompletedSteps), scanState.TotalSteps)
	} else {
		scanState, _ = stateMgr.CreateState(scanID, targetDomain, "wildcard", resultDir, configJSON)
	}

	// Setup runner with retry logic from config
	var r runner.Runner
	if Cfg != nil && Cfg.General.MaxRetries > 0 {
		delay := time.Duration(Cfg.General.RetryDelaySec) * time.Second
		if delay == 0 {
			delay = 3 * time.Second
		}
		r = runner.NewWithRetry(Mode, Verbose, Cfg.General.MaxRetries, delay)
	} else {
		r = runner.NewWithRetry(Mode, Verbose, 1, 3*time.Second) // default: 1 retry
	}
	var toolsCfg *config.ToolsConfig
	if Cfg != nil {
		toolsCfg = &Cfg.Tools
	}
	tb := tools.New(r, toolsCfg)
	if Cfg != nil {
		tb.WithAPIKeys(&Cfg.APIKeys)
	}

	// Setup notifier
	var notifier *notify.Notifier
	if Cfg != nil && Cfg.Notifications.Enabled {
		notifier = notify.New(&Cfg.Notifications)
	}

	// Declare variables used across steps (needed because goto labels skip declarations)
	var wg sync.WaitGroup
	var passiveFiles []string

	// =========================================================================
	// Step 1: Passive Enumeration (Parallel)
	// =========================================================================
	if scanState.IsStepCompleted("passive_enum") {
		logger.Section("Step 1: Passive Subdomain Enumeration [RESUMED — skipping]")
		goto step2
	}
	logger.Section("Step 1: Passive Subdomain Enumeration")
	stateMgr.MarkStepComplete(scanState, "passive_enum_start")

	passiveFiles = []string{
		filepath.Join(resultDir, "subfinder.txt"),
		filepath.Join(resultDir, "assetfinder.txt"),
		filepath.Join(resultDir, "sublist3r.txt"),
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Subfinder")
		if err := tb.RunSubfinder(ctx, targetDomain, passiveFiles[0]); err != nil {
			logger.Error("Subfinder failed: %v", err)
		} else {
			logger.SubStep("[Done] Subfinder")
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, passiveFiles[0], "subfinder")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Assetfinder")
		if err := tb.RunAssetfinder(ctx, targetDomain, passiveFiles[1]); err != nil {
			logger.Error("Assetfinder failed: %v", err)
		} else {
			logger.SubStep("[Done] Assetfinder")
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, passiveFiles[1], "assetfinder")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Sublist3r")
		if err := tb.RunSublist3r(ctx, targetDomain, passiveFiles[2]); err != nil {
			if Verbose {
				logger.Warning("Sublist3r failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Sublist3r")
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, passiveFiles[2], "sublist3r")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	wg.Wait()
	stateMgr.MarkStepComplete(scanState, "passive_enum")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

step2:

	// =========================================================================
	// Step 2: URL Discovery (Parallel - Waybackurls + GAU)
	// =========================================================================
	logger.Section("Step 2: Historical URL Discovery")

	waybackOut := filepath.Join(resultDir, "waybackurls.txt")
	gauOut := filepath.Join(resultDir, "gau.txt")

	wg.Add(2)
	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Waybackurls")
		if err := tb.RunWaybackurls(ctx, targetDomain, waybackOut); err != nil {
			if Verbose {
				logger.Warning("Waybackurls failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Waybackurls")
			if scanID > 0 {
				count, _ := utils.ParseURLsFile(scanID, waybackOut, "waybackurls")
				logger.Info("  Found %d URLs", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] GAU")
		if err := tb.RunGau(ctx, targetDomain, gauOut); err != nil {
			if Verbose {
				logger.Warning("GAU failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] GAU")
			if scanID > 0 {
				count, _ := utils.ParseURLsFile(scanID, gauOut, "gau")
				logger.Info("  Found %d URLs", count)
			}
		}
	}()

	wg.Wait()
	stateMgr.MarkStepComplete(scanState, "url_discovery")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 3: Active Enumeration (Amass - Optional)
	// =========================================================================
	amassOut := filepath.Join(resultDir, "amass.txt")
	if !skipAmass {
		logger.Section("Step 3: Active Subdomain Enumeration (Amass)")
		logger.SubStep("Running Amass (this may take a while)...")
		if err := tb.RunAmass(ctx, targetDomain, amassOut); err != nil {
			logger.Error("Amass failed: %v", err)
			stateMgr.MarkStepFailed(scanState, "active_enum", err)
		} else {
			passiveFiles = append(passiveFiles, amassOut)
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, amassOut, "amass")
				logger.Info("  Found %d subdomains", count)
			}
			stateMgr.MarkStepComplete(scanState, "active_enum")
		}
	} else {
		logger.Section("Step 3: Skipping Amass (--skip-amass)")
		stateMgr.MarkStepComplete(scanState, "active_enum")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 4: GitHub Subdomain Discovery (Optional)
	// =========================================================================
	if githubToken != "" {
		logger.Section("Step 4: GitHub Subdomain Discovery")
		githubSubsOut := filepath.Join(resultDir, "github_subdomains.txt")
		logger.SubStep("Running github-subdomains...")
		if err := tb.RunGithubSubdomains(ctx, targetDomain, githubToken, githubSubsOut); err != nil {
			logger.Warning("GitHub subdomains failed: %v", err)
		} else {
			passiveFiles = append(passiveFiles, githubSubsOut)
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, githubSubsOut, "github")
				logger.Info("  Found %d subdomains", count)
			}
			logger.SubStep("[Done] GitHub Subdomains")
		}
	} else {
		logger.Section("Step 4: Skipping GitHub Recon (no token provided)")
		logger.Warning("Set GITHUB_TOKEN env var or use --github-token for GitHub recon")
	}
	stateMgr.MarkStepComplete(scanState, "github_recon")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 5: Search Engine Dorking (Uncover) — passive, no target contact
	// =========================================================================
	if !skipUncover {
		logger.Section("Step 5: Passive Search Engine Recon (Uncover)")
		uncoverOut := filepath.Join(resultDir, "uncover.json")
		logger.SubStep("Running Uncover (Shodan/Censys/Fofa)...")
		if err := tb.RunUncover(ctx, targetDomain, uncoverOut); err != nil {
			if Verbose {
				logger.Warning("Uncover failed: %v (check API keys in config)", err)
			}
		} else {
			if scanID > 0 {
				subs, ports, _ := utils.ParseUncoverOutput(scanID, uncoverOut)
				logger.Info("  Found %d hosts and %d open ports from search engines", subs, ports)
			}
		}
		stateMgr.MarkStepComplete(scanState, "search_engine_recon")
	} else {
		logger.Section("Step 5: Skipping Uncover (--skip-uncover)")
		stateMgr.MarkStepComplete(scanState, "search_engine_recon")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 6: Consolidation & DNS Resolution
	// =========================================================================
	logger.Section("Step 6: Consolidating Subdomains")
	consolidatedSubs := filepath.Join(resultDir, "all_subdomains.txt")
	if err := utils.MergeAndDeduplicate(passiveFiles, consolidatedSubs); err != nil {
		logger.Error("Failed to consolidate: %v", err)
	}
	logger.Success("Consolidated list saved to %s", consolidatedSubs)

	// DNS Resolution
	logger.SubStep("Running DNSx for resolution...")
	dnsxOut := filepath.Join(resultDir, "dnsx_resolved.json")
	if err := tb.RunDnsx(ctx, consolidatedSubs, dnsxOut); err != nil {
		logger.Error("DNSx failed: %v", err)
	}
	stateMgr.MarkStepComplete(scanState, "consolidation")
	stateMgr.MarkStepComplete(scanState, "dns_resolution")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 7: Smart Subdomain Permutation (Alterx → DNSx)
	// =========================================================================
	logger.Section("Step 7: Smart Subdomain Permutation (Alterx)")
	alterxOut := filepath.Join(resultDir, "alterx_permutations.txt")
	alterxResolvedOut := filepath.Join(resultDir, "alterx_resolved.json")
	logger.SubStep("Running Alterx to generate smart permutations...")
	if err := tb.RunAlterx(ctx, consolidatedSubs, alterxOut); err != nil {
		if Verbose {
			logger.Warning("Alterx failed: %v", err)
		}
	} else {
		permCount, _ := utils.ParseAlterxOutput(alterxOut)
		logger.Info("  Generated %d permutations, resolving with DNSx...", permCount)

		// Resolve permutations to find new valid subdomains
		if err := tb.RunDnsx(ctx, alterxOut, alterxResolvedOut); err != nil {
			logger.Warning("DNSx on permutations failed: %v", err)
		} else {
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, alterxResolvedOut, "alterx")
				logger.Info("  Found %d new subdomains via permutation", count)
			}
			// Merge new subs into consolidated list
			utils.MergeAndDeduplicate(
				[]string{consolidatedSubs, alterxResolvedOut},
				consolidatedSubs,
			)
		}
	}
	stateMgr.MarkStepComplete(scanState, "permutation")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 8: DNS Brute-force (ShuffleDNS) — dictionary-based subdomain discovery
	// =========================================================================
	if !skipShuffleDNS && dnsWordlistPath != "" {
		logger.Section("Step 8: DNS Brute-force (ShuffleDNS)")
		shufflednsOut := filepath.Join(resultDir, "shuffledns_bruteforce.txt")
		logger.SubStep("Running ShuffleDNS with wordlist: %s", dnsWordlistPath)
		if err := runWithSkip(ctx, "shuffledns", func(sCtx context.Context) error {
			return tb.RunShuffleDNS(sCtx, targetDomain, dnsWordlistPath, resolversPath, shufflednsOut)
		}); err != nil {
			if err == ErrToolSkipped {
				logger.Info("  ShuffleDNS skipped")
			} else if Verbose {
				logger.Warning("ShuffleDNS failed: %v", err)
			}
		} else {
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, shufflednsOut, "shuffledns")
				logger.Info("  Found %d subdomains via DNS brute-force", count)
			}
			// Merge brute-forced subs into consolidated list
			utils.MergeAndDeduplicate(
				[]string{consolidatedSubs, shufflednsOut},
				consolidatedSubs,
			)
		}
		stateMgr.MarkStepComplete(scanState, "dns_bruteforce")
	} else if skipShuffleDNS {
		logger.Section("Step 8: Skipping ShuffleDNS (--skip-shuffledns)")
		stateMgr.MarkStepComplete(scanState, "dns_bruteforce")
	} else {
		logger.Section("Step 8: Skipping ShuffleDNS (no --dns-wordlist provided)")
		logger.Info("Use --dns-wordlist to enable DNS brute-force")
		stateMgr.MarkStepComplete(scanState, "dns_bruteforce")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 9: Live Web Probing (Httpx)
	// =========================================================================
	logger.Section("Step 9: Live Web Server Probing")
	httpxOut := filepath.Join(resultDir, "httpx_live.json")
	logger.SubStep("Running Httpx...")
	if err := tb.RunHttpx(ctx, consolidatedSubs, httpxOut); err != nil {
		logger.Error("Httpx failed: %v", err)
	} else {
		if scanID > 0 {
			count, _ := utils.ParseHttpxOutput(scanID, httpxOut)
			logger.Info("  Found %d live hosts", count)
		}
	}
	stateMgr.MarkStepComplete(scanState, "http_probing")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 9: TLS/SSL Certificate Analysis (tlsx)
	// =========================================================================
	if !skipTlsx {
		logger.Section("Step 10: TLS Certificate Analysis (tlsx)")
		tlsxOut := filepath.Join(resultDir, "tlsx_certs.json")
		logger.SubStep("Running tlsx — extracting SANs and checking cert issues...")
		if err := tb.RunTlsx(ctx, consolidatedSubs, tlsxOut); err != nil {
			if Verbose {
				logger.Warning("tlsx failed: %v", err)
			}
		} else {
			if scanID > 0 {
				newSubs, certVulns, _ := utils.ParseTlsxOutput(scanID, tlsxOut, targetDomain)
				if newSubs > 0 {
					logger.Info("  Discovered %d new subdomains from certificate SANs", newSubs)
				}
				if certVulns > 0 {
					logger.Info("  Found %d certificate issues (expired/self-signed/mismatch)", certVulns)
				}
			}
		}
		stateMgr.MarkStepComplete(scanState, "tls_analysis")
	} else {
		logger.Section("Step 10: Skipping tlsx (--skip-tlsx)")
		stateMgr.MarkStepComplete(scanState, "tls_analysis")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 10: Port Scanning (Naabu) — scan ALL discovered subdomains
	// =========================================================================
	if !skipNaabu {
		logger.Section("Step 11: Port Scanning")
		naabuOut := filepath.Join(resultDir, "naabu_ports.txt")
		logger.SubStep("Running Naabu on all discovered subdomains...")
		if err := tb.RunNaabuList(ctx, consolidatedSubs, naabuOut); err != nil {
			logger.Error("Naabu failed: %v", err)
		} else {
			if scanID > 0 {
				count, _ := utils.ParseNaabuOutput(scanID, naabuOut)
				logger.Info("  Found %d open ports", count)
			}
		}
		stateMgr.MarkStepComplete(scanState, "port_scanning")
	} else {
		logger.Section("Step 11: Skipping Naabu (--skip-naabu)")
		stateMgr.MarkStepComplete(scanState, "port_scanning")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 11: Web Crawling (Parallel - Katana + GoSpider)
	// =========================================================================
	if !skipCrawl {
		logger.Section("Step 12: Web Crawling")
		katanaOut := filepath.Join(resultDir, "katana_urls.txt")
		gospiderOut := filepath.Join(resultDir, "gospider_urls.txt")

		wg.Add(2)
		go func() {
			defer wg.Done()
			logger.SubStep("[Start] Katana")
			if err := tb.RunKatana(ctx, "https://"+targetDomain, katanaOut); err != nil {
				logger.Warning("Katana failed: %v", err)
			} else {
				logger.SubStep("[Done] Katana")
				if scanID > 0 {
					count, _ := utils.ParseURLsFile(scanID, katanaOut, "katana")
					logger.Info("  Katana found %d URLs", count)
				}
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GoSpider")
			if err := tb.RunGoSpider(ctx, "https://"+targetDomain, gospiderOut); err != nil {
				logger.Warning("GoSpider failed: %v", err)
			} else {
				logger.SubStep("[Done] GoSpider")
				if scanID > 0 {
					count, _ := utils.ParseURLsFile(scanID, gospiderOut, "gospider")
					logger.Info("  GoSpider found %d URLs", count)
				}
			}
		}()

		wg.Wait()
		stateMgr.MarkStepComplete(scanState, "web_crawling")
	} else {
		logger.Section("Step 12: Skipping Web Crawling (--skip-crawl)")
		stateMgr.MarkStepComplete(scanState, "web_crawling")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 12: JS Analysis & Endpoint Discovery
	// =========================================================================
	logger.Section("Step 13: JavaScript Analysis")
	linkfinderOut := filepath.Join(resultDir, "linkfinder_endpoints.txt")
	logger.SubStep("Running Linkfinder...")
	if err := tb.RunLinkfinder(ctx, "https://"+targetDomain, linkfinderOut); err != nil {
		if Verbose {
			logger.Warning("Linkfinder failed: %v", err)
		}
	} else {
		if scanID > 0 {
			count, _ := utils.ParseEndpointsFile(scanID, linkfinderOut, "linkfinder")
			logger.Info("  Found %d endpoints", count)
		}
	}
	stateMgr.MarkStepComplete(scanState, "js_analysis")

	// =========================================================================
	// Step 14: JavaScript Subdomain Extraction (SubDomainizer)
	// =========================================================================
	if !skipSubdomainizer {
		logger.Section("Step 14: JavaScript Subdomain Extraction (SubDomainizer)")
		subdomainizerOut := filepath.Join(resultDir, "subdomainizer_subs.txt")
		logger.SubStep("Running SubDomainizer on https://%s...", targetDomain)
		if err := runWithSkip(ctx, "subdomainizer", func(sCtx context.Context) error {
			return tb.RunSubdomainizer(sCtx, "https://"+targetDomain, subdomainizerOut)
		}); err != nil {
			if err == ErrToolSkipped {
				logger.Info("  SubDomainizer skipped")
			} else if Verbose {
				logger.Warning("SubDomainizer failed: %v", err)
			}
		} else {
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, subdomainizerOut, "subdomainizer")
				if count > 0 {
					logger.Info("  Found %d subdomains from JavaScript analysis", count)
					// Merge JS-discovered subs into consolidated list
					utils.MergeAndDeduplicate(
						[]string{consolidatedSubs, subdomainizerOut},
						consolidatedSubs,
					)
				} else {
					logger.Info("  No new subdomains found in JavaScript")
				}
			}
		}
		stateMgr.MarkStepComplete(scanState, "js_subdomain_discovery")
	} else {
		logger.Section("Step 14: Skipping SubDomainizer (--skip-subdomainizer)")
		stateMgr.MarkStepComplete(scanState, "js_subdomain_discovery")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 15: HTTP Parameter Discovery (Arjun)
	// =========================================================================
	arjunOut := filepath.Join(resultDir, "arjun_params.json")
	if !skipArjun {
		logger.Section("Step 15: HTTP Parameter Discovery (Arjun)")
		logger.SubStep("Running Arjun on https://%s...", targetDomain)
		if err := runWithSkip(ctx, "arjun", func(sCtx context.Context) error {
			return tb.RunArjun(sCtx, "https://"+targetDomain, arjunOut)
		}); err != nil {
			if err != ErrToolSkipped {
				if Verbose {
					logger.Warning("Arjun failed: %v", err)
				}
			}
		} else {
			logger.SubStep("[Done] Arjun parameter discovery")
		}
	} else {
		logger.Section("Step 15: Skipping Arjun (--skip-arjun)")
	}
	stateMgr.MarkStepComplete(scanState, "param_discovery")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 14: URL Consolidation & Live Check
	// =========================================================================
	logger.Section("Step 16: URL Consolidation & Live Check")
	allURLsRaw := filepath.Join(resultDir, "all_urls_raw.txt")
	allURLsLive := filepath.Join(resultDir, "all_urls_live.txt")

	// Merge URLs from all URL-producing tools
	urlSources := []string{
		filepath.Join(resultDir, "waybackurls.txt"),
		filepath.Join(resultDir, "gau.txt"),
		filepath.Join(resultDir, "katana_urls.txt"),
		filepath.Join(resultDir, "gospider_urls.txt"),
		linkfinderOut,
	}

	logger.SubStep("Merging URLs from %d sources...", len(urlSources))
	if err := utils.MergeAndDeduplicate(urlSources, allURLsRaw); err != nil {
		logger.Warning("URL merge failed: %v", err)
	} else {
		rawCount, _ := utils.CountFileLines(allURLsRaw)
		logger.Info("  Merged %d unique URLs", rawCount)
	}

	// Live-check all URLs with httpx
	logger.SubStep("Running httpx to live-check all URLs...")
	if err := runWithSkip(ctx, "httpx (URL check)", func(sCtx context.Context) error {
		return tb.RunHttpxURLCheck(sCtx, allURLsRaw, allURLsLive)
	}); err != nil {
		if err != ErrToolSkipped {
			logger.Warning("URL live-check failed: %v", err)
		}
		// Fallback: use raw URLs if live-check fails
		if !utils.FileExists(allURLsLive) {
			logger.Info("  Using raw URLs as fallback")
			copyFile(allURLsRaw, allURLsLive)
		}
	} else {
		liveCount, _ := utils.CountFileLines(allURLsLive)
		logger.Success("  %d live URLs confirmed", liveCount)
	}
	stateMgr.MarkStepComplete(scanState, "url_consolidation")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 17: Directory Fuzzing (ffuf)
	// =========================================================================
	if wordlistPath != "" {
		logger.Section("Step 17: Directory Fuzzing (ffuf)")
		ffufOut := filepath.Join(resultDir, "ffuf_results.json")
		targetURL := fmt.Sprintf("https://%s/FUZZ", targetDomain)
		logger.SubStep("Running ffuf with wordlist: %s", wordlistPath)
		if err := tb.RunFfufWithFUZZ(ctx, targetURL, wordlistPath, ffufOut); err != nil {
			logger.Warning("ffuf failed: %v", err)
		} else {
			logger.SubStep("[Done] ffuf - Results: %s", ffufOut)
		}
	} else {
		logger.Section("Step 17: Skipping ffuf (no wordlist provided)")
		logger.Info("Use --wordlist to enable directory fuzzing")
	}
	stateMgr.MarkStepComplete(scanState, "dir_fuzzing")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 17: Vulnerability Scanning — Run 1: Infrastructure (Nuclei)
	// =========================================================================
	if !skipNuclei {
		logger.Section("Step 19: Vulnerability Scanning — Infra (Nuclei)")
		nucleiOut := filepath.Join(resultDir, "nuclei_vulns.json")
		logger.SubStep("Running Nuclei on discovered subdomains...")
		if err := runWithSkip(ctx, "nuclei (infra)", func(sCtx context.Context) error {
			return tb.RunNuclei(sCtx, consolidatedSubs, nucleiOut)
		}); err != nil {
			if err == ErrToolSkipped {
				logger.Info("  Nuclei infra scan skipped")
			} else {
				logger.Error("Nuclei failed: %v", err)
			}
		} else {
			if scanID > 0 {
				count, _ := utils.ParseNucleiOutput(scanID, nucleiOut)
				logger.Info("  Found %d vulnerabilities", count)

				// Send notifications for critical/high findings
				if notifier != nil && count > 0 {
					vulns, _ := database.GetVulnerabilities(scanID)
					for _, v := range vulns {
						if v.Severity == "critical" || v.Severity == "high" {
							notifier.SendFinding(notify.Finding{
								Target:      targetDomain,
								Type:        "vulnerability",
								Name:        v.Name,
								Severity:    v.Severity,
								Description: v.Description,
								URL:         v.URL,
								TemplateID:  v.TemplateID,
								Timestamp:   time.Now(),
							})
						}
					}
				}
			}
		}
	} else {
		logger.Section("Step 19: Skipping Nuclei (--skip-nuclei)")
	}
	stateMgr.MarkStepComplete(scanState, "vuln_scanning")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 18: Vulnerability Scanning — Run 2: URLs (Nuclei)
	// =========================================================================
	if !skipNuclei && utils.FileExists(allURLsLive) {
		logger.Section("Step 20: Vulnerability Scanning — URLs (Nuclei)")
		nucleiURLOut := filepath.Join(resultDir, "nuclei_url_vulns.json")
		logger.SubStep("Running Nuclei on live URLs (stricter rate, medium+ severity)...")
		if err := runWithSkip(ctx, "nuclei (URLs)", func(sCtx context.Context) error {
			return tb.RunNucleiURLs(sCtx, allURLsLive, nucleiURLOut)
		}); err != nil {
			if err == ErrToolSkipped {
				logger.Info("  Nuclei URL scan skipped")
			} else if Verbose {
				logger.Warning("Nuclei URL scan failed: %v", err)
			}
		} else {
			if scanID > 0 {
				count, _ := utils.ParseNucleiOutput(scanID, nucleiURLOut)
				logger.Info("  Found %d URL-specific vulnerabilities", count)
			}
		}
	} else if skipNuclei {
		logger.Section("Step 20: Skipping Nuclei URLs (--skip-nuclei)")
	} else {
		logger.Section("Step 20: Skipping Nuclei URLs (no live URLs available)")
	}
	stateMgr.MarkStepComplete(scanState, "vuln_scanning_urls")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 19: Subdomain Takeover Detection (Subjack)
	// =========================================================================
	if !skipSubjack {
		logger.Section("Step 21: Subdomain Takeover Detection (Subjack)")
		subjackOut := filepath.Join(resultDir, "subjack_takeovers.txt")
		logger.SubStep("Running Subjack — checking for dangling CNAMEs...")
		if err := tb.RunSubjack(ctx, consolidatedSubs, subjackOut); err != nil {
			if Verbose {
				logger.Warning("Subjack failed: %v", err)
			}
		} else {
			if scanID > 0 {
				count, _ := utils.ParseSubjackOutput(scanID, subjackOut)
				if count > 0 {
					logger.Success("  🚨 Found %d potential subdomain takeovers!", count)
					// Notify immediately — takeovers are critical
					if notifier != nil {
						vulns, _ := database.GetVulnerabilities(scanID)
						for _, v := range vulns {
							if v.TemplateID == "subdomain-takeover" {
								notifier.SendFinding(notify.Finding{
									Target:    targetDomain,
									Type:      "subdomain-takeover",
									Name:      v.Name,
									Severity:  "critical",
									URL:       v.Host,
									Timestamp: time.Now(),
								})
							}
						}
					}
				} else {
					logger.Info("  No subdomain takeovers detected")
				}
			}
		}
		stateMgr.MarkStepComplete(scanState, "takeover_detection")
	} else {
		logger.Section("Step 21: Skipping Subjack (--skip-subjack)")
		stateMgr.MarkStepComplete(scanState, "takeover_detection")
	}

	// =========================================================================
	// Step 20: XSS Scanning (Dalfox) — uses live URLs
	// =========================================================================
	if !skipDalfox {
		logger.Section("Step 22: XSS Scanning (Dalfox)")
		paramURLsFile := filepath.Join(resultDir, "param_urls_live.txt")
		dalfoxOut := filepath.Join(resultDir, "dalfox_xss.json")

		// Collect parameterized URLs from the live URLs file
		logger.SubStep("Collecting parameterized URLs from live URLs...")
		collectParamURLsFromFile(allURLsLive, paramURLsFile)

		if utils.FileExists(paramURLsFile) {
			paramCount, _ := utils.CountFileLines(paramURLsFile)
			logger.Info("  Found %d parameterized URLs to test", paramCount)
			logger.SubStep("Running Dalfox on parameterized URLs...")
			if err := runWithSkip(ctx, "dalfox", func(sCtx context.Context) error {
				return tb.RunDalfox(sCtx, paramURLsFile, dalfoxOut)
			}); err != nil {
				if err == ErrToolSkipped {
					logger.Info("  Dalfox skipped")
				} else if Verbose {
					logger.Warning("Dalfox failed: %v", err)
				}
			} else {
				if scanID > 0 {
					count, _ := utils.ParseDalfoxOutput(scanID, dalfoxOut)
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
		stateMgr.MarkStepComplete(scanState, "xss_scanning")
	} else {
		logger.Section("Step 22: Skipping Dalfox (--skip-dalfox)")
		stateMgr.MarkStepComplete(scanState, "xss_scanning")
	}

	// =========================================================================
	// Finalize
	// =========================================================================
	finalizeScan(scanID, "completed", stateMgr, scanState, notifier, startTime, resultDir)
}

// collectParamURLsFromFile filters a single URL file for parameterized URLs
// (URLs containing ?key=value). Used to extract XSS candidates from all_urls_live.txt.
func collectParamURLsFromFile(inputFile, outputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		return
	}
	defer file.Close()

	seen := make(map[string]bool)
	f, err := os.Create(outputFile)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Only include URLs with query parameters (contain ?)
		if line != "" && strings.Contains(line, "?") && strings.Contains(line, "=") {
			if !seen[line] {
				seen[line] = true
				fmt.Fprintln(f, line)
			}
		}
	}
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

func finalizeScan(scanID int64, status string, stateMgr *scan.Manager, state *scan.State, notifier *notify.Notifier, startTime time.Time, resultDir string) {
	duration := time.Since(startTime)

	// Update database
	if scanID > 0 {
		database.UpdateScanStatus(scanID, status)
	}

	// Clean up state file for completed scans
	if status == "completed" && stateMgr != nil && state != nil {
		stateMgr.DeleteState(state.ScanID)
	}

	// Print summary using modern UI
	stats := make(map[string]string)
	if scanID > 0 {
		dbStats, err := database.GetScanStats(scanID)
		if err == nil {
			stats["Subdomains"] = fmt.Sprintf("%d (Live: %d)", dbStats.TotalSubdomains, dbStats.LiveSubdomains)
			stats["Open Ports"] = fmt.Sprintf("%d", dbStats.TotalPorts)
			stats["URLs"] = fmt.Sprintf("%d", dbStats.TotalURLs)
			stats["Endpoints"] = fmt.Sprintf("%d", dbStats.TotalEndpoints)

			for sev, count := range dbStats.Vulnerabilities {
				stats["Vuln ("+sev+")"] = fmt.Sprintf("%d", count)
			}

			// Send scan complete notification
			if notifier != nil {
				notifier.SendScanComplete(notify.ScanComplete{
					Target:   targetDomain,
					ScanID:   scanID,
					Duration: duration,
					Stats: map[string]int{
						"subdomains": dbStats.TotalSubdomains,
						"ports":      dbStats.TotalPorts,
						"vulns":      len(dbStats.Vulnerabilities),
					},
				})
			}
		}

		logger.ScanSummary(status, targetDomain, scanID, duration, stats)
		logger.Success("Results saved in: %s", resultDir)

		// Export all results to text files
		if status == "completed" || status == "cancelled" {
			logger.Info("\nExporting results to text files...")
			if err := utils.ExportResults(scanID, resultDir); err != nil {
				logger.Warning("Failed to export some results: %v", err)
			} else {
				logger.Success("Results exported to text files")
			}

			// Create summary file
			if err := utils.ExportSummary(scanID, resultDir, targetDomain); err != nil {
				logger.Warning("Failed to create summary: %v", err)
			}
		}

		// Generate report
		if generateReport && status == "completed" {
			logger.Info("\nGenerating report...")
			rpt, err := report.Generate(scanID)
			if err == nil {
				home, _ := os.UserHomeDir()
				reportPath := filepath.Join(home, ".chaathan", "reports", fmt.Sprintf("scan_%d.md", scanID))
				if err := rpt.Export(report.FormatMarkdown, reportPath); err == nil {
					logger.Success("Report saved: %s", reportPath)
				}

				// Also save report in result directory
				localReportPath := filepath.Join(resultDir, "REPORT.md")
				if err := rpt.Export(report.FormatMarkdown, localReportPath); err == nil {
					logger.Success("Report also saved: %s", localReportPath)
				}
			}
		}
	}

	// Usage hints
	if scanID > 0 {
		logger.NextSteps([]string{
			fmt.Sprintf("chaathan scans show %d       # View scan details", scanID),
			fmt.Sprintf("chaathan query vulns %d      # List vulnerabilities", scanID),
			fmt.Sprintf("chaathan report generate %d  # Generate full report", scanID),
		})
	}
}

// runWithSkip runs a tool function with skip support.
// If the user presses 's' during execution, only this tool is cancelled.
// Returns nil on success, ErrToolSkipped if skipped, or the tool's error.
var ErrToolSkipped = fmt.Errorf("tool skipped by user")

func runWithSkip(ctx context.Context, toolName string, fn func(ctx context.Context) error) error {
	// Create a child context that we can cancel independently
	toolCtx, toolCancel := context.WithCancel(ctx)
	defer toolCancel()

	// Run the tool in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- fn(toolCtx)
	}()

	// Wait for either: tool completion, skip signal, or parent cancellation
	select {
	case err := <-done:
		return err
	case <-skipToolChan:
		toolCancel()
		logger.Warning("⏭ Skipped: %s", toolName)
		// Drain the done channel (tool will exit due to cancelled context)
		<-done
		return ErrToolSkipped
	case <-ctx.Done():
		toolCancel()
		<-done
		return ctx.Err()
	}
}
