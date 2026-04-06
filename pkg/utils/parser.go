package utils

import (
	"bufio"
	"encoding/json"
	"net"
	neturl "net/url"
	"os"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan-flow/pkg/database"
)

// ParseSubdomainsFile reads a file with one subdomain per line and adds to database
func ParseSubdomainsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	if len(domains) > 0 {
		if err := database.AddSubdomains(scanID, domains, source); err != nil {
			return 0, err
		}
	}

	return len(domains), nil
}

// HttpxResult represents a line from httpx JSON output
type HttpxResult struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	ContentType  string   `json:"content_type"`
	Technologies []string `json:"tech"`
	Host         string   `json:"host"`
	Input        string   `json:"input"`
	ResponseTime string   `json:"response_time"`
}

// ParseHttpxOutput parses httpx JSON output and stores in database
func ParseHttpxOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		tech := ""
		if len(result.Technologies) > 0 {
			techJSON, _ := json.Marshal(result.Technologies)
			tech = string(techJSON)
		}

		if err := database.AddURL(scanID, result.URL, result.StatusCode, result.ContentType, result.Title, tech, "httpx"); err != nil {
			continue
		}

		// Also mark subdomain as live
		host := result.Host
		if host == "" {
			host = result.Input
		}
		if host != "" {
			database.UpdateSubdomainLive(scanID, host, true, "")
		}

		count++
	}

	return count, scanner.Err()
}

// NucleiResult represents a line from nuclei JSON output.
// Nuclei puts name, severity, and description inside a nested "info" object.
type NucleiResult struct {
	TemplateID    string          `json:"template-id"`
	Info          NucleiResultInfo `json:"info"`
	Host          string          `json:"host"`
	MatchedAt     string          `json:"matched-at"`
	ExtractorName string          `json:"extractor-name"`
	Matcher       string          `json:"matcher-name"`
	Extracted     []string        `json:"extracted-results"`
}

// NucleiResultInfo holds the nested info fields from Nuclei's JSONL output.
type NucleiResultInfo struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// ParseNucleiOutput parses nuclei JSON output and stores in database
func ParseNucleiOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	// Increase buffer size for large lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		evidence := ""
		if len(result.Extracted) > 0 {
			evidence = strings.Join(result.Extracted, "\n")
		}

		name := result.Info.Name
		if name == "" {
			name = result.TemplateID
		}

		err := database.AddVulnerability(
			scanID,
			result.Host,
			result.MatchedAt,
			result.TemplateID,
			name,
			strings.ToLower(result.Info.Severity),
			result.Info.Description,
			result.Matcher,
			evidence,
		)
		if err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

// NaabuResult represents a line from naabu output
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// FfufResult represents a single ffuf discovery item.
type FfufResult struct {
	Input  map[string]string `json:"input"`
	URL    string            `json:"url"`
	Status int               `json:"status"`
}

// ParseNaabuOutput parses naabu output and stores in database
func ParseNaabuOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Naabu outputs in format: host:port or JSON
		var host string
		var port int

		// Try JSON first
		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			host = result.Host
			if host == "" {
				host = result.IP
			}
			port = result.Port
		} else {
			// Try host:port format
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host = parts[0]
				port, _ = strconv.Atoi(parts[1])
			}
		}

		if host != "" && port > 0 {
			if err := database.AddPort(scanID, host, port, "tcp", ""); err != nil {
				continue
			}
			count++
		}
	}

	return count, scanner.Err()
}

// ParseEndpointsFile parses a file with endpoints (one per line)
func ParseEndpointsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Determine method if present
		method := ""
		url := line

		// Some tools output "METHOD URL"
		parts := strings.Fields(line)
		if len(parts) >= 2 && isHTTPMethod(parts[0]) {
			method = parts[0]
			url = parts[1]
		}

		if err := database.AddEndpoint(scanID, url, method, source); err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

// ParseURLsFile parses a file with URLs (one per line)
func ParseURLsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if err := database.AddURL(scanID, line, 0, "", "", "", source); err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

// ParseLiveURLsFile parses httpx plain-text output where each line may be
// "https://url [STATUS_CODE]" (produced by -status-code without -json).
// Only the primary URL field (before any whitespace) is stored in the DB,
// so status suffixes never corrupt stored URLs.
func ParseLiveURLsFile(scanID int64, filePath, source string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Take only the first field — strips "[200]", "[403]", etc.
		fields := strings.Fields(line)
		url := fields[0]
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		if err := database.AddURL(scanID, url, 0, "", "", "", source); err != nil {
			continue
		}
		count++
	}

	return count, scanner.Err()
}

// ParseFfufOutput parses ffuf JSON output and stores discovered paths as both
// URLs and endpoints so later ranking/reporting can use the fuzzing data.
func ParseFfufOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var payload struct {
		Results []FfufResult `json:"results"`
	}
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return 0, err
	}

	count := 0
	for _, result := range payload.Results {
		if strings.TrimSpace(result.URL) == "" {
			continue
		}

		_ = database.AddURL(scanID, result.URL, result.Status, "", "", "", "ffuf")
		_ = database.AddEndpoint(scanID, result.URL, "GET", "ffuf")
		count++
	}

	return count, nil
}

func isHTTPMethod(s string) bool {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	s = strings.ToUpper(s)
	for _, m := range methods {
		if s == m {
			return true
		}
	}
	return false
}

// --- Phase 3: New tool parsers ---



// TlsxResult represents a line from tlsx JSON output
type TlsxResult struct {
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	SubjectCN   string   `json:"subject_cn"`
	SubjectOrg  []string `json:"subject_org"`
	SANs        []string `json:"san"`
	SubjectAN   []string `json:"subject_an"`
	Issuer      string   `json:"issuer_cn"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Expired     bool     `json:"expired"`
	SelfSigned  bool     `json:"self_signed"`
	MisMatched  bool     `json:"mismatched"`
	TLSVersion  string   `json:"tls_version"`
	CipherSuite string   `json:"cipher"`
}

// ParseTlsxOutput parses tlsx JSON output.
// Extracts SANs as new subdomains and flags expired/weak certs as vulnerabilities.
func ParseTlsxOutput(scanID int64, filePath string, targetDomain string) (newSubs int, vulns int, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	seenSANs := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result TlsxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		// Extract SANs as new subdomains. Newer tlsx JSON uses subject_an,
		// while older probe-driven output may still emit san.
		sans := result.SANs
		if len(sans) == 0 {
			sans = result.SubjectAN
		}
		for _, san := range sans {
			san = strings.TrimPrefix(san, "*.")
			if !seenSANs[san] && strings.HasSuffix(san, targetDomain) {
				seenSANs[san] = true
				database.AddSubdomains(scanID, []string{san}, "tlsx-san")
				newSubs++
			}
		}

		// Flag expired certificates
		if result.Expired {
			database.AddVulnerability(
				scanID, result.Host, "", "expired-ssl",
				"Expired SSL Certificate",
				"medium",
				"Certificate expired: "+result.NotAfter,
				"", "Issuer: "+result.Issuer,
			)
			vulns++
		}

		// Flag self-signed certificates
		if result.SelfSigned {
			database.AddVulnerability(
				scanID, result.Host, "", "self-signed-ssl",
				"Self-Signed SSL Certificate",
				"low",
				"Self-signed certificate detected",
				"", "CN: "+result.SubjectCN,
			)
			vulns++
		}

		// Flag mismatched certificates
		if result.MisMatched {
			database.AddVulnerability(
				scanID, result.Host, "", "ssl-mismatch",
				"SSL Certificate Hostname Mismatch",
				"medium",
				"Certificate CN/SAN does not match hostname",
				"", "CN: "+result.SubjectCN,
			)
			vulns++
		}

		host := normalizeHostValue(result.Host)
		if host != "" {
			weakTLS := isWeakTLSVersion(result.TLSVersion)
			_ = database.UpsertHostMetadata(scanID, database.HostMetadata{
				Host:          host,
				SSLExpired:    result.Expired,
				SSLSelfSigned: result.SelfSigned,
				SSLMismatch:   result.MisMatched,
				WeakTLS:       weakTLS,
			})
		}
	}

	return newSubs, vulns, scanner.Err()
}

// UncoverResult represents a line from uncover JSON output
type UncoverResult struct {
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// ParseUncoverOutput parses uncover JSON output and extracts subdomains/ports.
func ParseUncoverOutput(scanID int64, filePath string) (subs int, ports int, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	seenHosts := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result UncoverResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		// Add host as subdomain
		host := result.Host
		if host == "" {
			host = result.IP
		}
		if host != "" && !seenHosts[host] {
			seenHosts[host] = true
			database.AddSubdomains(scanID, []string{host}, "uncover-"+result.Source)
			subs++
		}

		// Add port if found
		if result.Port > 0 && host != "" {
			database.AddPort(scanID, host, result.Port, "tcp", "")
			ports++
		}
	}

	return subs, ports, scanner.Err()
}

// DalfoxResult represents a line from dalfox output
type DalfoxResult struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Data     string `json:"data"`
	Payload  string `json:"payload"`
	Param    string `json:"param"`
	CWE      string `json:"cwe"`
	Method   string `json:"method"`
}

// ParseDalfoxOutput parses dalfox output for XSS findings.
func ParseDalfoxOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Try JSON first
		var result DalfoxResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			targetURL := strings.TrimSpace(result.URL)
			if targetURL == "" {
				targetURL = strings.TrimSpace(result.Data)
			}
			if targetURL == "" {
				continue
			}

			severity := "medium"
			if result.Severity != "" {
				severity = strings.ToLower(result.Severity)
			}

			templateID := "xss"
			if result.Type != "" {
				templateID = "xss-" + strings.ToLower(result.Type)
			}

			name := "XSS Finding"
			if result.Type != "" && result.Param != "" {
				name = "XSS (" + result.Type + ") - Param: " + result.Param
			} else if result.Type != "" {
				name = "XSS (" + result.Type + ")"
			} else if result.Param != "" {
				name = "XSS - Param: " + result.Param
			}

			desc := "Potential XSS detected by Dalfox"
			if result.Param != "" {
				desc = "Cross-Site Scripting found via parameter: " + result.Param
			}

			var evidenceParts []string
			if result.Payload != "" {
				evidenceParts = append(evidenceParts, "Payload: "+result.Payload)
			}
			if result.Method != "" {
				evidenceParts = append(evidenceParts, "Method: "+result.Method)
			}
			if result.CWE != "" {
				evidenceParts = append(evidenceParts, "CWE: "+result.CWE)
			}

			err := database.AddVulnerability(
				scanID,
				targetURL,
				targetURL,
				templateID,
				name,
				severity,
				desc,
				"",
				strings.Join(evidenceParts, "\n"),
			)
			if err != nil {
				continue
			}
			count++
		} else if strings.Contains(line, "[POC]") || strings.Contains(line, "[V]") {
			// Text format fallback
			err := database.AddVulnerability(
				scanID, line, "", "xss",
				"XSS Finding", "medium",
				"Potential XSS detected by Dalfox",
				"", line,
			)
			if err != nil {
				continue
			}
			count++
		}
	}

	return count, scanner.Err()
}

func normalizeHostValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if strings.Contains(raw, "://") {
		if parsed, err := neturl.Parse(raw); err == nil {
			return strings.ToLower(parsed.Hostname())
		}
	}

	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(host)
	}

	return strings.ToLower(strings.Trim(raw, "[]"))
}

func isWeakTLSVersion(version string) bool {
	version = strings.ToLower(strings.TrimSpace(version))
	return strings.Contains(version, "tls10") ||
		strings.Contains(version, "tls1.0") ||
		strings.Contains(version, "tls11") ||
		strings.Contains(version, "tls1.1") ||
		strings.Contains(version, "ssl3")
}
