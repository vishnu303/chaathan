package metadata

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/database"
)

const (
	defaultConcurrency = 4
	maxBodyBytes       = 65536
)

type httpSignal struct {
	URL             string
	Host            string
	HeadersJSON     string
	HasCSP          bool
	HasCacheHeaders bool
	LoginSurface    bool
	ResponseBytes   int
}

// CollectHostMetadata fetches lightweight metadata for live host URLs and
// stores one record per host for ROI scoring.
func CollectHostMetadata(scanID int64, urls []string) (int, error) {
	targets := dedupeByHost(urls)
	if len(targets) == 0 {
		return 0, nil
	}

	results := collectSignals(targets)
	count := 0
	for _, signal := range results {
		err := database.UpsertHostMetadata(scanID, database.HostMetadata{
			Host:            signal.Host,
			BaseURL:         signal.URL,
			HeadersJSON:     signal.HeadersJSON,
			HasCSP:          signal.HasCSP,
			HasCacheHeaders: signal.HasCacheHeaders,
			LoginSurface:    signal.LoginSurface,
			ResponseBytes:   signal.ResponseBytes,
		})
		if err == nil {
			count++
		}
	}

	return count, nil
}

// CollectURLMetadata fetches lightweight metadata for selected high-value URLs
// and stores per-path signals for ROI scoring.
func CollectURLMetadata(scanID int64, urls []string) (int, error) {
	targets := dedupeByURL(urls)
	if len(targets) == 0 {
		return 0, nil
	}

	results := collectSignals(targets)
	count := 0
	for _, signal := range results {
		err := database.UpsertURLMetadata(scanID, database.URLMetadata{
			URL:             signal.URL,
			Host:            signal.Host,
			HeadersJSON:     signal.HeadersJSON,
			HasCSP:          signal.HasCSP,
			HasCacheHeaders: signal.HasCacheHeaders,
			LoginSurface:    signal.LoginSurface,
			ResponseBytes:   signal.ResponseBytes,
		})
		if err == nil {
			count++
		}
	}

	return count, nil
}

func collectSignals(urls []string) []httpSignal {
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 2,
		},
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
		for _, target := range urls {
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
	req.Header.Set("User-Agent", "Chaathan-ROI-Metadata/1.0")
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

	return httpSignal{
		URL:             rawURL,
		Host:            strings.ToLower(parsed.Hostname()),
		HeadersJSON:     string(headersJSON),
		HasCSP:          hasCSP,
		HasCacheHeaders: hasCacheHeaders,
		LoginSurface:    loginSurface,
		ResponseBytes:   len(body),
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
