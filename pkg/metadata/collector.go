package metadata

import (
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/utils"
)

const (
	defaultConcurrency = 4
	maxBodyBytes       = 65536
)

// sessionCookiePrefixes are common cookie name patterns that indicate
// session or authentication cookies.
var sessionCookiePrefixes = []string{
	"session", "sess", "sid", "jsessionid", "phpsessid",
	"asp.net_sessionid", "connect.sid", "_session",
	"auth", "token", "jwt", "access_token",
}

// realUserAgents contains common, high-frequency browser User-Agent strings.
// Rotating through these prevents WAF fingerprinting that would occur with a
// static custom UA like "Chaathan-ROI-Metadata/1.0".
var realUserAgents = []string{
	// Chrome 147 on Windows 10
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	// Chrome 147 on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	// Chrome 147 on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	// Firefox 149 on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
	// Firefox 149 on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
	// Edge 147 on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
	// Safari 18 on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
}

// randomUA returns a random User-Agent from the pool.
func randomUA() string {
	return realUserAgents[rand.Intn(len(realUserAgents))]
}

type httpSignal struct {
	URL                 string
	Host                string
	HeadersJSON         string
	HasCSP              bool
	HasCacheHeaders     bool
	LoginSurface        bool
	ResponseBytes       int
	FormCount           int
	HasFileUpload       bool
	HiddenInputCount    int
	CORSWildcard        bool
	HasInsecureCookies  bool
	HasSessionCookie    bool
	HasDangerousMethods bool
}

// CollectHostMetadata fetches lightweight metadata for live host URLs and
// stores one record per host for ROI scoring.
func CollectHostMetadata(scanID int64, urls []string, proxy string) (int, error) {
	targets := dedupeByHost(urls)
	if len(targets) == 0 {
		return 0, nil
	}

	results := collectSignals(targets, proxy)
	count := 0
	for _, signal := range results {
		err := database.UpsertHostMetadata(scanID, database.HostMetadata{
			Host:                signal.Host,
			BaseURL:             signal.URL,
			HeadersJSON:         signal.HeadersJSON,
			HasCSP:              signal.HasCSP,
			HasCacheHeaders:     signal.HasCacheHeaders,
			LoginSurface:        signal.LoginSurface,
			ResponseBytes:       signal.ResponseBytes,
			CORSWildcard:        signal.CORSWildcard,
			HasInsecureCookies:  signal.HasInsecureCookies,
			HasSessionCookie:    signal.HasSessionCookie,
			HasDangerousMethods: signal.HasDangerousMethods,
		})
		if err == nil {
			count++
		}
	}

	return count, nil
}

// CollectURLMetadata fetches lightweight metadata for selected high-value URLs
// and stores per-path signals for ROI scoring.
func CollectURLMetadata(scanID int64, urls []string, proxy string) (int, error) {
	targets := dedupeByURL(urls)
	if len(targets) == 0 {
		return 0, nil
	}

	results := collectSignals(targets, proxy)
	count := 0
	for _, signal := range results {
		err := database.UpsertURLMetadata(scanID, database.URLMetadata{
			URL:              signal.URL,
			Host:             signal.Host,
			HeadersJSON:      signal.HeadersJSON,
			HasCSP:           signal.HasCSP,
			HasCacheHeaders:  signal.HasCacheHeaders,
			LoginSurface:     signal.LoginSurface,
			ResponseBytes:    signal.ResponseBytes,
			FormCount:        signal.FormCount,
			HasFileUpload:    signal.HasFileUpload,
			HiddenInputCount: signal.HiddenInputCount,
		})
		if err == nil {
			count++
		}
	}

	return count, nil
}

func collectSignals(urls []string, proxy string) []httpSignal {
	transport := &http.Transport{
		TLSClientConfig:     utils.ModernBrowserTLSConfig(),
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 2,
	}
	if proxy != "" {
		if proxyURL, err := neturl.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{
		Timeout:   12 * time.Second,
		Transport: transport,
	}

	jobs := make(chan string)
	results := make(chan httpSignal, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < defaultConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if signal, ok := fetchSignal(client, target); ok {
					results <- signal
				}
			}
		}()
	}

	go func() {
		// Rate limit: max 5 requests/sec to avoid WAF bans on targets.
		// Each URL triggers a GET + an OPTIONS request, so effective rate
		// is ~10 HTTP requests/sec across all workers.
		limiter := time.NewTicker(200 * time.Millisecond)
		defer limiter.Stop()
		for _, target := range urls {
			<-limiter.C
			jobs <- target
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	collected := make([]httpSignal, 0, len(urls))
	for result := range results {
		collected = append(collected, result)
	}

	return collected
}

func fetchSignal(client *http.Client, rawURL string) (httpSignal, bool) {
	parsed, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return httpSignal{}, false
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return httpSignal{}, false
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return httpSignal{}, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return httpSignal{}, false
	}

	headers := make(map[string]interface{}, len(resp.Header))
	for key, values := range resp.Header {
		if len(values) == 1 {
			headers[key] = values[0]
		} else {
			headers[key] = values
		}
	}
	headersJSON, _ := json.Marshal(headers)

	lowerBody := strings.ToLower(string(body))
	loginSurface := strings.Contains(lowerBody, "password") ||
		strings.Contains(lowerBody, "sign in") ||
		strings.Contains(lowerBody, "signin") ||
		strings.Contains(lowerBody, "log in") ||
		strings.Contains(lowerBody, "login") ||
		strings.Contains(lowerBody, "forgot password") ||
		strings.Contains(lowerBody, "oauth")

	hasCSP := resp.Header.Get("Content-Security-Policy") != ""
	hasCacheHeaders := resp.Header.Get("Cache-Control") != "" ||
		resp.Header.Get("ETag") != "" ||
		resp.Header.Get("Expires") != "" ||
		resp.Header.Get("Vary") != ""

	// Form and file upload detection
	formCount := strings.Count(lowerBody, "<form")
	hasFileUpload := strings.Contains(lowerBody, `type="file"`) ||
		strings.Contains(lowerBody, `type='file'`) ||
		strings.Contains(lowerBody, "type=file")
	hiddenInputCount := strings.Count(lowerBody, `type="hidden"`) +
		strings.Count(lowerBody, `type='hidden'`)

	// CORS wildcard detection
	corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
	corsWildcard := corsHeader == "*"

	// Cookie security analysis
	hasInsecureCookies, hasSessionCookie := analyzeCookies(resp.Header["Set-Cookie"])

	// OPTIONS method detection (follow-up request for dangerous methods)
	hasDangerousMethods := checkDangerousMethods(client, rawURL)

	return httpSignal{
		URL:                 rawURL,
		Host:                strings.ToLower(parsed.Hostname()),
		HeadersJSON:         string(headersJSON),
		HasCSP:              hasCSP,
		HasCacheHeaders:     hasCacheHeaders,
		LoginSurface:        loginSurface,
		ResponseBytes:       len(body),
		FormCount:           formCount,
		HasFileUpload:       hasFileUpload,
		HiddenInputCount:    hiddenInputCount,
		CORSWildcard:        corsWildcard,
		HasInsecureCookies:  hasInsecureCookies,
		HasSessionCookie:    hasSessionCookie,
		HasDangerousMethods: hasDangerousMethods,
	}, true
}

func dedupeByHost(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range urls {
		parsed, err := neturl.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if !seen[host] {
			seen[host] = true
			out = append(out, raw)
		}
	}
	return out
}

func dedupeByURL(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		out = append(out, raw)
	}
	return out
}

// analyzeCookies inspects Set-Cookie headers for missing security flags.
// Returns (hasInsecureCookies, hasSessionCookie).
func analyzeCookies(setCookies []string) (bool, bool) {
	if len(setCookies) == 0 {
		return false, false
	}

	var hasInsecure, hasSession bool

	for _, cookie := range setCookies {
		// Check if this looks like a session cookie by name
		nameEnd := strings.Index(cookie, "=")
		if nameEnd > 0 {
			name := strings.ToLower(strings.TrimSpace(cookie[:nameEnd]))
			for _, prefix := range sessionCookiePrefixes {
				if strings.Contains(name, prefix) {
					hasSession = true
					break
				}
			}
		}

		// Parse attributes after the first ';' to check security flags.
		// Only check the attribute portion, not the name=value part,
		// to avoid false positives from values containing "secure".
		parts := strings.Split(cookie, ";")
		hasSecureFlag := false
		hasHTTPOnlyFlag := false
		for _, part := range parts[1:] { // skip name=value
			attr := strings.ToLower(strings.TrimSpace(part))
			if attr == "secure" {
				hasSecureFlag = true
			}
			if attr == "httponly" {
				hasHTTPOnlyFlag = true
			}
		}
		if !hasSecureFlag || !hasHTTPOnlyFlag {
			hasInsecure = true
		}
	}

	return hasInsecure, hasSession
}

// checkDangerousMethods sends an OPTIONS request and checks if the server
// advertises PUT or DELETE in the Allow header.
func checkDangerousMethods(client *http.Client, rawURL string) bool {
	req, err := http.NewRequest("OPTIONS", rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", randomUA())

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	allow := resp.Header.Get("Allow")
	if allow == "" {
		return false
	}
	// Split on comma and check exact method names to avoid substring
	// false positives (e.g., "OUTPUT" matching "PUT").
	for _, method := range strings.Split(allow, ",") {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "PUT" || method == "DELETE" {
			return true
		}
	}
	return false
}
