// Package cli – Company command
//
// This file is intentionally thin. It only contains the cobra command
// definition, flag wiring, and a single call into pkg/company_flow.Run().
// All scan logic lives in the company_flow package.
package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
	cf "github.com/vishnu303/chaathan-flow/pkg/company_flow"
)

// ─────────────────────────────────────────────────────────────
// CLI flags (package-level for cobra binding)
// ─────────────────────────────────────────────────────────────

var (
	targetCompany  string
	skipCloudEnum  bool
	skipMetabigor  bool
	skipAmassIntel bool
)

// ─────────────────────────────────────────────────────────────
// Cobra command
// ─────────────────────────────────────────────────────────────

var companyCmd = &cobra.Command{
	Use:   "company",
	Short: "Run the Company Reconnaissance Workflow",
	Long: `
Runs a full organization discovery workflow:
  1. ASN & Network Range Discovery (Metabigor) [Optional, --skip-metabigor]
  2. Root Domain Discovery (Amass Intel) [Optional, --skip-amass-intel]
  3. Cloud Enumeration (Cloud Enum) [Optional, --skip-cloud-enum]

All results are stored in the database for querying and reporting.
`,
	Run: runCompany,
}

func init() {
	companyCmd.Flags().StringVarP(&targetCompany, "name", "n", "", "Target Company Name (required)")
	companyCmd.Flags().BoolVar(&skipMetabigor, "skip-metabigor", false, "Skip Metabigor ASN discovery")
	companyCmd.Flags().BoolVar(&skipAmassIntel, "skip-amass-intel", false, "Skip Amass Intel root domain discovery")
	companyCmd.Flags().BoolVar(&skipCloudEnum, "skip-cloud-enum", false, "Skip Cloud Enum cloud enumeration")
	companyCmd.MarkFlagRequired("name")
	rootCmd.AddCommand(companyCmd)
}

// ─────────────────────────────────────────────────────────────
// runCompany — cobra handler
// ─────────────────────────────────────────────────────────────

func runCompany(cmd *cobra.Command, args []string) {
	if strings.TrimSpace(targetCompany) == "" {
		logger.Error("Company name cannot be empty")
		return
	}

	resultDir, err := CreateOutputDir(targetCompany)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	if err := cf.Run(cf.RunConfig{
		Company:        targetCompany,
		ResultDir:      resultDir,
		Mode:           Mode,
		Verbose:        Verbose,
		Cfg:            Cfg,
		SkipMetabigor:  skipMetabigor,
		SkipAmassIntel: skipAmassIntel,
		SkipCloudEnum:  skipCloudEnum,
	}); err != nil {
		logger.Error("Company scan failed: %v", err)
	}
}
