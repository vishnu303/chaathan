package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
)

func TestReportGenerationAndExport(t *testing.T) {
	// Initialize temporary database
	dbFile := filepath.Join(t.TempDir(), "test_report.db")
	if err := database.Initialize(dbFile); err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	defer func() {
		database.Close()
		os.Remove(dbFile)
	}()

	// Seed scan data
	scan, err := database.CreateScan("example.com", "wildcard", t.TempDir(), "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	// Add subdomains
	if err := database.AddSubdomain(scan.ID, "www.example.com", "test"); err != nil {
		t.Fatalf("failed to add subdomain: %v", err)
	}
	if err := database.UpdateSubdomainLive(scan.ID, "www.example.com", true, "1.2.3.4"); err != nil {
		t.Fatalf("failed to update subdomain live: %v", err)
	}

	// Add port
	if err := database.AddPort(scan.ID, "www.example.com", 443, "tcp", "https"); err != nil {
		t.Fatalf("failed to add port: %v", err)
	}

	// Add URL
	if err := database.AddURL(scan.ID, "https://www.example.com/", 200, "text/html", "Example Domain", `["wordpress"]`, "httpx"); err != nil {
		t.Fatalf("failed to add URL: %v", err)
	}

	// Add vuln
	if err := database.AddVulnerability(scan.ID, "www.example.com", "https://www.example.com/", "test-cve", "Test Vuln", "high", "A test vuln", "pattern", "evidence line"); err != nil {
		t.Fatalf("failed to add vuln: %v", err)
	}

	// Add endpoint
	if err := database.AddEndpoint(scan.ID, "https://www.example.com/api", "GET", "katana"); err != nil {
		t.Fatalf("failed to add endpoint: %v", err)
	}

	// Generate report
	rpt, err := Generate(scan.ID)
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	if rpt.Scan.Target != "example.com" {
		t.Errorf("expected target example.com, got %q", rpt.Scan.Target)
	}

	// Export formats
	formats := []ReportFormat{FormatMarkdown, FormatJSON, FormatHTML, FormatText}
	for _, fmtStr := range formats {
		outPath := filepath.Join(t.TempDir(), "report"+ExtensionFor(string(fmtStr)))
		if err := rpt.Export(fmtStr, outPath); err != nil {
			t.Errorf("failed to export format %s: %v", fmtStr, err)
		}

		// Verify file exists and is not empty
		info, err := os.Stat(outPath)
		if err != nil {
			t.Errorf("exported file not found for format %s: %v", fmtStr, err)
		} else if info.Size() == 0 {
			t.Errorf("exported file is empty for format %s", fmtStr)
		}
	}
}
