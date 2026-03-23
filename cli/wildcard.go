// Package cli – Wildcard command
//
// This file is intentionally thin. It only contains the cobra command
// definition, flag wiring, and a single call into pkg/wildcard_flow.Run().
// All scan logic lives in the wildcard_flow package.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
	wf "github.com/vishnu303/chaathan-flow/pkg/wildcard_flow"
)

// ─────────────────────────────────────────────────────────────
// CLI flags (package-level for cobra binding)
// ─────────────────────────────────────────────────────────────

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
)

// ─────────────────────────────────────────────────────────────
// Cobra command
// ─────────────────────────────────────────────────────────────

var wildcardCmd = &cobra.Command{
	Use:     "wildcard",
	Aliases: []string{"scan"},
	Short:   "Run the Wildcard Reconnaissance Workflow",
	Long: `
Runs a comprehensive 20-step recon & vulnerability scanning workflow:

 1. Passive Enumeration (Subfinder, Assetfinder, Sublist3r) [Parallel]
 2. URL Discovery (Waybackurls, GAU) [Parallel]
 3. Active Enumeration (Amass) [Optional, --skip-amass]
 4. GitHub Subdomain Discovery [Requires GITHUB_TOKEN]
 5. Search Engine Dorking (Uncover/Shodan/Censys) [Optional, --skip-uncover]
 6. Consolidation & DNS Resolution (DNSx)
  7. DNS Brute-force (ShuffleDNS/MassDNS) [Optional, --skip-shuffledns]
  8. Live Web Probing (Httpx)
  9. TLS Certificate Analysis (tlsx) [Optional, --skip-tlsx]
 10. Port Scanning on ALL subdomains (Naabu) [Optional, --skip-naabu]
 11. Web Crawling (Katana, GoSpider) [Parallel, --skip-crawl]
 12. JavaScript Analysis (LinkFinder)
 13. JavaScript Subdomain Extraction (SubDomainizer) [Optional, --skip-subdomainizer]
 14. HTTP Parameter Discovery (Arjun) [Optional, --skip-arjun]
 15. URL Consolidation & Live Check (httpx)
 16. Directory Fuzzing (ffuf) [Requires --wordlist]
 17. Vulnerability Scanning — Infra (Nuclei) [Optional, --skip-nuclei]
 18. Vulnerability Scanning — URLs (Nuclei) [Optional, --skip-nuclei]
 19. Subdomain Takeover Detection (Subjack) [Optional, --skip-subjack]
 20. XSS Scanning (Dalfox) [Optional, --skip-dalfox]

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

// ─────────────────────────────────────────────────────────────
// runWildcard — cobra handler
// ─────────────────────────────────────────────────────────────

func runWildcard(cmd *cobra.Command, args []string) {
	// Validate the target domain before doing anything
	if err := utils.ValidateDomain(targetDomain); err != nil {
		logger.Error("Invalid target: %v", err)
		return
	}

	// Resolve GitHub token: --github-token flag takes priority,
	// then the API key set in the chaathan config file.
	// The OS GITHUB_TOKEN env var is intentionally not read here.
	token := githubToken
	if token == "" && Cfg != nil {
		if t := Cfg.GetAPIKey("github"); t != "" {
			token = t
		}
	}

	// Create result directory (reuses root.go helper)
	resultDir, err := CreateOutputDir(targetDomain)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	// Forward Ctrl+C / 's'-key to wildcard_flow.Run() which owns signal
	// handling and stdin listener internally.

	// Build configuration and delegate to the wildcard_flow package
	cfg := wf.RunConfig{
		Domain:            targetDomain,
		ResultDir:         resultDir,
		Mode:              Mode,
		Verbose:           Verbose,
		Cfg:               Cfg,
		SkipAmass:         skipAmass,
		SkipNuclei:        skipNuclei,
		SkipNaabu:         skipNaabu,
		SkipCrawl:         skipCrawl,
		SkipSubjack:       skipSubjack,
		SkipDalfox:        skipDalfox,
		SkipUncover:       skipUncover,
		SkipTlsx:          skipTlsx,
		SkipArjun:         skipArjun,
		SkipShuffleDNS:    skipShuffleDNS,
		SkipSubdomainizer: skipSubdomainizer,
		WordlistPath:      wordlistPath,
		DNSWordlistPath:   dnsWordlistPath,
		ResolversPath:     resolversPath,
		GitHubToken:       token,
		ResumeScanID:      resumeScanID,
		GenerateReport:    generateReport,
	}

	if err := wf.Run(cfg); err != nil {
		logger.Error("Wildcard scan failed: %v", err)
	}
}
