package cli

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	Mode       string
	OutputDir  string
	Verbose    bool
	ConfigPath string
	Cfg        *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "chaathan",
	Short: "Chaathan - Advanced Pentesting Framework CLI",
	Long: `
   _____ _                 _   _                 
  / ____| |               | | | |                
 | |    | |__   __ _  __ _| |_| |__   __ _ _ __  
 | |    | '_ \ / _' |/ _' | __| '_ \ / _' | '_ \ 
 | |____| | | | (_| | (_| | |_| | | | (_| | | | |
  \_____|_| |_|\__,_|\__,_|\__|_| |_|\__,_|_| |_|
                                                  
Chaathan is a powerful, modular CLI pentesting tool for comprehensive 
bug bounty reconnaissance and vulnerability scanning.

Workflows:
  - Wildcard Scan : 21-step domain recon & vuln assessment pipeline
  - Company Scan  : 3-step organization-level discovery (ASN, domains, cloud)

Capabilities:
  - 28+ integrated tools (subfinder, nuclei, httpx, katana, and more)
  - Passive - Search Engine Dorking (Uncover, Shodan, Censys)
  - DNS brute-force (ShuffleDNS)
  - JavaScript analysis and endpoint extraction (LinkFinder, SubDomainizer)
  - Live host detection, TLS analysis & port scanning
  - Web crawling, JS analysis & parameter discovery
  - Vulnerability scanning (Nuclei) & XSS detection (Dalfox)
  - Subdomain takeover detection (Subjack)
  - Cloud infrastructure enumeration (Cloud Enum)
  - Persistent SQLite database for all results
  - Report generation (Markdown/JSON/HTML)
  - Discord/Slack/Telegram notifications
  - Resume interrupted scans
  - Setup logging for install debugging

Modes:
  - native: Uses tools installed in your system $PATH (Recommended)
  - docker: Uses Docker containers for tool isolation

Quick Start:
  chaathan setup                     # Install all tools
  chaathan wildcard -d target.com    # Run full 21-step recon
  chaathan company -n "Company Inc"  # Run company discovery
  chaathan scans list                # View past scans
  chaathan report generate 1         # Generate report for scan #1
  chaathan tools check               # Verify tool installations
`,
	PersistentPreRun: initializeApp,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&Mode, "mode", "m", "native", "Execution mode: 'native' or 'docker'")
	rootCmd.PersistentFlags().StringVarP(&OutputDir, "output", "o", "", "Directory to store results")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&ConfigPath, "config", "", "Config file path (default: ~/.chaathan/config.yaml)")
}

func initializeApp(cmd *cobra.Command, args []string) {
	// Skip initialization for setup command
	if cmd.Name() == "setup" {
		return
	}

	// Determine config path
	cfgPath := ConfigPath
	if cfgPath == "" {
		cfgPath = config.GetDefaultConfigPath()
	}

	// Load or create config
	var err error
	Cfg, err = config.LoadOrCreate(cfgPath)
	if err != nil {
		logger.Warning("Failed to load config: %v", err)
		Cfg = config.DefaultConfig()
	}

	// Apply config values if not overridden by flags
	if OutputDir == "" {
		OutputDir = Cfg.General.OutputDir
	}
	if !Verbose && Cfg.General.Verbose {
		Verbose = true
	}
	if Mode == "native" && Cfg.General.Mode != "" {
		Mode = Cfg.General.Mode
	}

	// Initialize database
	dbPath := Cfg.General.DatabasePath
	if dbPath == "" {
		dbPath = database.GetDefaultDBPath()
	}

	if err := database.Initialize(dbPath); err != nil {
		logger.Warning("Failed to initialize database: %v", err)
		logger.Warning("Some features (history, reports) may not work.")
	}
}

func CreateOutputDir(target string) (string, error) {
	baseDir := OutputDir
	if baseDir == "" {
		home, _ := os.UserHomeDir()
		baseDir = filepath.Join(home, ".chaathan", "scans")
	}

	path := filepath.Join(baseDir, target)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	return path, nil
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s%sChaathan%s v2.0.0\n", logger.BrightCyan, logger.Bold, logger.Reset)
		fmt.Printf("%sAdvanced Pentesting Recon Framework%s\n", logger.Dim, logger.Reset)
		fmt.Printf("%s28+ tools • 21-step wildcard scan • 3-step company scan%s\n", logger.Dim, logger.Reset)
		fmt.Printf("%shttps://github.com/vishnu303/chaathan-flow%s\n", logger.Dim, logger.Reset)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
