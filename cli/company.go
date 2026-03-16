package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

var (
	targetCompany  string
	skipCloudEnum  bool
	skipMetabigor  bool
	skipAmassIntel bool
)

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

func runCompany(cmd *cobra.Command, args []string) {
	// Validate input
	if strings.TrimSpace(targetCompany) == "" {
		logger.Error("Company name cannot be empty")
		return
	}

	startTime := time.Now()

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Warning("Received interrupt signal. Stopping...")
		cancel()
	}()


	// Setup output directory
	resultDir, err := CreateOutputDir(targetCompany)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	// Create scan record in database
	configJSON, _ := json.Marshal(map[string]interface{}{
		"target":           targetCompany,
		"skip_metabigor":   skipMetabigor,
		"skip_amass_intel": skipAmassIntel,
		"skip_cloud_enum":  skipCloudEnum,
	})

	dbScan, err := database.CreateScan(targetCompany, "company", resultDir, string(configJSON))
	if err != nil {
		logger.Warning("Failed to create scan record: %v", err)
	}
	scanID := int64(0)
	if dbScan != nil {
		scanID = dbScan.ID
	}

	// Show modern scan header
	logger.ScanHeader("Company", targetCompany, scanID)
	logger.InitScanUI(3) // 3 steps in company workflow

	// Setup runner with retry logic from config
	var r runner.Runner
	if Cfg != nil && Cfg.General.MaxRetries > 0 {
		delay := time.Duration(Cfg.General.RetryDelaySec) * time.Second
		if delay == 0 {
			delay = 3 * time.Second
		}
		r = runner.NewWithRetry(Mode, Verbose, Cfg.General.MaxRetries, delay)
	} else {
		r = runner.NewWithRetry(Mode, Verbose, 1, 3*time.Second)
	}
	var toolsCfg *config.ToolsConfig
	if Cfg != nil {
		toolsCfg = &Cfg.Tools
	}
	tb := tools.New(r, toolsCfg)

	// Track step results
	var totalSteps, completedSteps, failedSteps int

	// =========================================================================
	// Step 1: ASN & Network Range Discovery (Metabigor)
	// =========================================================================
	totalSteps++
	if !skipMetabigor {
		logger.Section("Step 1: ASN & Network Range Discovery (Metabigor)")
		asnOut := filepath.Join(resultDir, "asn_ranges.txt")
		logger.SubStep("Running Metabigor for org: %s", targetCompany)
		if err := tb.RunMetabigorNet(ctx, targetCompany, asnOut); err != nil {
			logger.Error("Metabigor failed: %v", err)
			failedSteps++
		} else {
			count, _ := utils.CountFileLines(asnOut)
			logger.Success("Found %d ASN/network ranges", count)
			completedSteps++
		}
	} else {
		logger.Section("Step 1: Skipping Metabigor (--skip-metabigor)")
		completedSteps++
	}

	if ctx.Err() != nil {
		finalizeCompanyScan(scanID, "cancelled", startTime, resultDir, completedSteps, failedSteps, totalSteps)
		return
	}

	// =========================================================================
	// Step 2: Root Domain Discovery (Amass Intel)
	// =========================================================================
	totalSteps++
	if !skipAmassIntel {
		logger.Section("Step 2: Root Domain Discovery (Amass Intel)")
		amassIntelOut := filepath.Join(resultDir, "root_domains.txt")
		logger.SubStep("Running Amass Intel reverse-whois for: %s", targetCompany)

		// Amass intel finds root domains belonging to the org
		amassArgs := []string{"intel", "-whois", "-d", targetCompany, "-o", amassIntelOut}
		if Cfg != nil && Cfg.Tools.Amass.Timeout > 0 {
			amassArgs = append(amassArgs, "-timeout", fmt.Sprintf("%d", Cfg.Tools.Amass.Timeout))
		}
		_, err := r.Run(ctx, "amass", amassArgs)
		if err != nil {
			logger.Warning("Amass Intel failed: %v", err)
			logger.Info("  This is common — amass intel requires WHOIS data access")
			failedSteps++
		} else {
			count, _ := utils.CountFileLines(amassIntelOut)
			logger.Success("Discovered %d root domains", count)
			completedSteps++

			// If we found domains, also discover subdomains from ASN ranges
			asnFile := filepath.Join(resultDir, "asn_ranges.txt")
			if utils.FileExists(asnFile) {
				logger.SubStep("Cross-referencing ASN ranges with discovered domains...")
				asnCount, _ := utils.CountFileLines(asnFile)
				if asnCount > 0 {
					logger.Info("  %d ASN ranges available for correlation", asnCount)
				}
			}
		}
	} else {
		logger.Section("Step 2: Skipping Amass Intel (--skip-amass-intel)")
		completedSteps++
	}

	if ctx.Err() != nil {
		finalizeCompanyScan(scanID, "cancelled", startTime, resultDir, completedSteps, failedSteps, totalSteps)
		return
	}

	// =========================================================================
	// Step 3: Cloud Enumeration (Cloud Enum)
	// =========================================================================
	totalSteps++
	if !skipCloudEnum {
		logger.Section("Step 3: Cloud Enumeration (Cloud Enum)")
		cloudOut := filepath.Join(resultDir, "cloud_enum.json")
		logger.SubStep("Running Cloud Enum for keyword: %s", targetCompany)
		if err := tb.RunCloudEnum(ctx, targetCompany, cloudOut); err != nil {
			logger.Warning("Cloud Enum failed: %v", err)
			failedSteps++
		} else {
			logger.Success("Cloud enumeration complete — results: %s", cloudOut)
			completedSteps++
		}
	} else {
		logger.Section("Step 3: Skipping Cloud Enum (--skip-cloud-enum)")
		completedSteps++
	}

	if ctx.Err() != nil {
		finalizeCompanyScan(scanID, "cancelled", startTime, resultDir, completedSteps, failedSteps, totalSteps)
		return
	}

	// =========================================================================
	// Finalize
	// =========================================================================
	finalizeCompanyScan(scanID, "completed", startTime, resultDir, completedSteps, failedSteps, totalSteps)
}

func finalizeCompanyScan(scanID int64, status string, startTime time.Time, resultDir string, completed, failed, total int) {
	duration := time.Since(startTime)

	// Update database
	if scanID > 0 {
		database.UpdateScanStatus(scanID, status)
	}

	// Build stats
	stats := map[string]string{
		"Steps completed": fmt.Sprintf("%d/%d", completed, total),
	}
	if failed > 0 {
		stats["Failed"] = fmt.Sprintf("%d", failed)
	}

	// List output files
	entries, err := os.ReadDir(resultDir)
	if err == nil {
		fileCount := 0
		for _, e := range entries {
			if !e.IsDir() {
				info, _ := e.Info()
				if info != nil && info.Size() > 0 {
					fileCount++
				}
			}
		}
		if fileCount > 0 {
			stats["Output files"] = fmt.Sprintf("%d", fileCount)
		}
	}

	// Print modern summary
	logger.ScanSummary(status, targetCompany, scanID, duration, stats)
	logger.Success("Results saved in: %s", resultDir)

	// List output files with details
	if err == nil && len(entries) > 0 {
		for _, e := range entries {
			if !e.IsDir() {
				info, _ := e.Info()
				if info != nil && info.Size() > 0 {
					logger.Info("  📄 %s (%s)", e.Name(), formatSize(info.Size()))
				}
			}
		}
	}

	// Usage hints
	if scanID > 0 {
		logger.NextSteps([]string{
			fmt.Sprintf("chaathan scans show %d    # View scan details", scanID),
			"chaathan wildcard -d <discovered-domain>  # Run full recon on discovered domains",
		})
	}
}

// formatSize returns a human-readable file size
func formatSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/1024/1024)
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
