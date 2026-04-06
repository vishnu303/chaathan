package utils

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"os"
	"path/filepath"
	"strings"
)

// ExportResults exports all scan results to text files in the result directory
func ExportResults(scanID int64, resultDir string) error {
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return err
	}

	// Export subdomains
	if err := ExportSubdomains(scanID, resultDir); err != nil {
		return fmt.Errorf("export subdomains: %w", err)
	}

	// Export live subdomains
	if err := ExportLiveSubdomains(scanID, resultDir); err != nil {
		return fmt.Errorf("export live subdomains: %w", err)
	}

	// Export ports
	if err := ExportPorts(scanID, resultDir); err != nil {
		return fmt.Errorf("export ports: %w", err)
	}

	// Export URLs
	if err := ExportURLs(scanID, resultDir); err != nil {
		return fmt.Errorf("export urls: %w", err)
	}

	// Export vulnerabilities
	if err := ExportVulnerabilities(scanID, resultDir); err != nil {
		return fmt.Errorf("export vulns: %w", err)
	}

	// Export endpoints
	if err := ExportEndpoints(scanID, resultDir); err != nil {
		return fmt.Errorf("export endpoints: %w", err)
	}

	return nil
}

// ExportSubdomains exports all subdomains to a text file
func ExportSubdomains(scanID int64, resultDir string) error {
	subs, err := database.GetSubdomains(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "final_subdomains.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, s := range subs {
		fmt.Fprintln(f, s.Domain)
	}

	return nil
}

// ExportLiveSubdomains exports only live subdomains.
// Format: "domain,ip" when IP is known, otherwise just "domain".
func ExportLiveSubdomains(scanID int64, resultDir string) error {
	subs, err := database.GetLiveSubdomains(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "live_subdomains.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, s := range subs {
		if s.IPAddress != "" {
			fmt.Fprintf(f, "%s,%s\n", s.Domain, s.IPAddress)
		} else {
			fmt.Fprintln(f, s.Domain)
		}
	}

	return nil
}

// ExportPorts exports open ports.
// Format: "host:port (protocol/service)" — one file with full detail.
func ExportPorts(scanID int64, resultDir string) error {
	ports, err := database.GetPorts(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "open_ports.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, p := range ports {
		service := p.Service
		if service == "" {
			service = "unknown"
		}
		fmt.Fprintf(f, "%s:%d (%s/%s)\n", p.Host, p.Port, p.Protocol, service)
	}

	return nil
}

// ExportURLs exports discovered URLs.
// all_urls.txt — all URLs with inline status code.
// urls_200.txt  — 200 OK URLs only.
func ExportURLs(scanID int64, resultDir string) error {
	urls, err := database.GetURLs(scanID)
	if err != nil {
		return err
	}

	// All URLs with status
	path := filepath.Join(resultDir, "all_urls.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, u := range urls {
		if u.StatusCode > 0 {
			fmt.Fprintf(f, "[%d] %s\n", u.StatusCode, u.URL)
		} else {
			fmt.Fprintln(f, u.URL)
		}
	}

	// 200 OK URLs only
	path200 := filepath.Join(resultDir, "urls_200.txt")
	f200, err := os.Create(path200)
	if err != nil {
		return err
	}
	defer f200.Close()

	for _, u := range urls {
		if u.StatusCode == 200 {
			fmt.Fprintln(f200, u.URL)
		}
	}

	return nil
}

// ExportVulnerabilities exports vulnerabilities.
// vulnerabilities.txt              — all vulns in detailed block format.
// vulnerabilities_critical_high.txt — critical/high only, compact format.
func ExportVulnerabilities(scanID int64, resultDir string) error {
	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		return err
	}

	// All vulns — detailed blocks
	path := filepath.Join(resultDir, "vulnerabilities.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, v := range vulns {
		fmt.Fprintf(f, "================================================================================\n")
		fmt.Fprintf(f, "[%s] %s\n", strings.ToUpper(v.Severity), v.Name)
		fmt.Fprintf(f, "================================================================================\n")
		fmt.Fprintf(f, "Host:     %s\n", v.Host)
		if v.URL != "" {
			fmt.Fprintf(f, "URL:      %s\n", v.URL)
		}
		if v.TemplateID != "" {
			fmt.Fprintf(f, "Template: %s\n", v.TemplateID)
		}
		if v.Description != "" {
			fmt.Fprintf(f, "Description:\n%s\n", v.Description)
		}
		if v.Evidence != "" {
			fmt.Fprintf(f, "Evidence:\n%s\n", v.Evidence)
		}
		fmt.Fprintln(f)
	}

	// Critical and High only — compact
	pathCritical := filepath.Join(resultDir, "vulnerabilities_critical_high.txt")
	fCritical, err := os.Create(pathCritical)
	if err != nil {
		return err
	}
	defer fCritical.Close()

	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			fmt.Fprintf(fCritical, "[%s] %s\n", strings.ToUpper(v.Severity), v.Name)
			fmt.Fprintf(fCritical, "  Host: %s\n", v.Host)
			if v.URL != "" {
				fmt.Fprintf(fCritical, "  URL:  %s\n", v.URL)
			}
			fmt.Fprintln(fCritical)
		}
	}

	return nil
}

// ExportEndpoints exports API endpoints.
// endpoints.txt             — all endpoints with method inline.
// endpoints_interesting.txt — filtered to API, admin, auth, etc.
func ExportEndpoints(scanID int64, resultDir string) error {
	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		return err
	}

	// All endpoints with method
	path := filepath.Join(resultDir, "endpoints.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, e := range endpoints {
		if e.Method != "" {
			fmt.Fprintf(f, "%s %s\n", e.Method, e.URL)
		} else {
			fmt.Fprintln(f, e.URL)
		}
	}

	// Interesting endpoints (API, admin, etc.)
	pathInteresting := filepath.Join(resultDir, "endpoints_interesting.txt")
	fInteresting, err := os.Create(pathInteresting)
	if err != nil {
		return err
	}
	defer fInteresting.Close()

	interestingPatterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/admin", "/login", "/auth",
		"/graphql", "/rest/",
		"/upload", "/download",
		"/config", "/settings",
		"/debug", "/test",
		".json", ".xml",
		"/swagger", "/docs",
	}

	for _, e := range endpoints {
		urlLower := strings.ToLower(e.URL)
		for _, pattern := range interestingPatterns {
			if strings.Contains(urlLower, pattern) {
				if e.Method != "" {
					fmt.Fprintf(fInteresting, "%s %s\n", e.Method, e.URL)
				} else {
					fmt.Fprintln(fInteresting, e.URL)
				}
				break
			}
		}
	}

	return nil
}

// ExportSummary creates a summary text file
func ExportSummary(scanID int64, resultDir string, target string) error {
	stats, err := database.GetScanStats(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "SUMMARY.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "================================================================================")
	fmt.Fprintln(f, "                        CHAATHAN SCAN SUMMARY")
	fmt.Fprintln(f, "================================================================================")
	fmt.Fprintf(f, "\nTarget: %s\n", target)
	fmt.Fprintf(f, "Scan ID: %d\n\n", scanID)

	fmt.Fprintln(f, "STATISTICS")
	fmt.Fprintln(f, "----------")
	fmt.Fprintf(f, "Total Subdomains:    %d\n", stats.TotalSubdomains)
	fmt.Fprintf(f, "Live Subdomains:     %d\n", stats.LiveSubdomains)
	fmt.Fprintf(f, "Open Ports:          %d\n", stats.TotalPorts)
	fmt.Fprintf(f, "URLs Discovered:     %d\n", stats.TotalURLs)
	fmt.Fprintf(f, "Endpoints Found:     %d\n", stats.TotalEndpoints)

	fmt.Fprintln(f, "\nVULNERABILITIES")
	fmt.Fprintln(f, "---------------")
	totalVulns := 0
	for sev, count := range stats.Vulnerabilities {
		fmt.Fprintf(f, "%-10s: %d\n", strings.ToUpper(sev), count)
		totalVulns += count
	}
	fmt.Fprintf(f, "%-10s: %d\n", "TOTAL", totalVulns)

	fmt.Fprintln(f, "\nOUTPUT FILES  (all files are inside final_files/)")
	fmt.Fprintln(f, "------------")
	fmt.Fprintln(f, "final_subdomains.txt              - All discovered subdomains")
	fmt.Fprintln(f, "live_subdomains.txt               - Live/responsive subdomains (with IP)")
	fmt.Fprintln(f, "open_ports.txt                    - Open ports (host:port proto/service)")
	fmt.Fprintln(f, "all_urls.txt                      - All discovered URLs with status codes")
	fmt.Fprintln(f, "urls_200.txt                      - URLs returning HTTP 200 OK")
	fmt.Fprintln(f, "vulnerabilities.txt               - All vulnerabilities (detailed)")
	fmt.Fprintln(f, "vulnerabilities_critical_high.txt - Critical/High severity vulns only")
	fmt.Fprintln(f, "endpoints.txt                     - All discovered endpoints (with method)")
	fmt.Fprintln(f, "endpoints_interesting.txt         - Interesting endpoints (API, admin, etc.)")
	fmt.Fprintln(f, "gf_secrets_findings.txt           - JS secret and JS sink matches from downloaded JS")
	fmt.Fprintln(f, "nuclei_vulns.json                 - Nuclei infra scan raw output")
	fmt.Fprintln(f, "nuclei_url_vulns.json             - Nuclei URL scan raw output")
	fmt.Fprintln(f, "dalfox_xss.jsonl                  - Dalfox XSS scan structured JSONL output")
	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "Raw tool outputs are in intermediate_files/ (subfinder, gau, httpx, etc.)")

	fmt.Fprintln(f, "\n================================================================================")
	fmt.Fprintln(f, "Generated by Chaathan - https://github.com/yourusername/chaathan")
	fmt.Fprintln(f, "================================================================================")

	return nil
}
