package database

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// URLROI represents a ranked target with score context.
type URLROI struct {
	URL              string         `json:"url"`
	Host             string         `json:"host"`
	StatusCode       int            `json:"status_code,omitempty"`
	Title            string         `json:"title,omitempty"`
	ContentType      string         `json:"content_type,omitempty"`
	Source           string         `json:"source,omitempty"`
	Tech             []string       `json:"tech,omitempty"`
	Score            int            `json:"score"`
	Reasons          []string       `json:"reasons"`
	EndpointCount    int            `json:"endpoint_count"`
	KatanaCount      int            `json:"katana_count"`
	GoSpiderCount    int            `json:"gospider_count"`
	LinkFinderCount  int            `json:"linkfinder_count"`
	FfufCount        int            `json:"ffuf_count"`
	OpenPortCount    int            `json:"open_port_count"`
	ExactVulnCounts  map[string]int `json:"exact_vuln_counts,omitempty"`
	HostVulnCounts   map[string]int `json:"host_vuln_counts,omitempty"`
	IsParameterized  bool           `json:"is_parameterized"`
	InterestingTerms []string       `json:"interesting_terms,omitempty"`
}

type endpointStats struct {
	Total    int
	BySource map[string]int
}

type mergedMetadata struct {
	HasHostData      bool
	HasURLData       bool
	HasCSP           bool
	HasCacheHeaders  bool
	LoginSurface     bool
	SSLExpired       bool
	SSLSelfSigned    bool
	SSLMismatch      bool
	WeakTLS          bool
}

// GetRankedURLs computes ROI scores from persisted scan data without requiring
// extra storage, so existing scans can be ranked immediately.
func GetRankedURLs(scanID int64, limit int) ([]URLROI, error) {
	urls, err := GetURLs(scanID)
	if err != nil {
		return nil, err
	}

	endpoints, err := GetEndpoints(scanID)
	if err != nil {
		return nil, err
	}

	vulns, err := GetVulnerabilities(scanID)
	if err != nil {
		return nil, err
	}

	ports, err := GetPorts(scanID)
	if err != nil {
		return nil, err
	}

	hostMetadata, err := GetHostMetadata(scanID)
	if err != nil {
		return nil, err
	}

	urlMetadata, err := GetURLMetadata(scanID)
	if err != nil {
		return nil, err
	}

	hostMetadataMap := make(map[string]HostMetadata, len(hostMetadata))
	for _, meta := range hostMetadata {
		hostMetadataMap[strings.ToLower(strings.TrimSpace(meta.Host))] = meta
	}

	urlMetadataMap := make(map[string]URLMetadata, len(urlMetadata))
	for _, meta := range urlMetadata {
		urlMetadataMap[normalizeComparableURL(meta.URL)] = meta
	}

	endpointsByHost := make(map[string]*endpointStats)
	for _, ep := range endpoints {
		host := extractHost(ep.URL)
		if host == "" {
			continue
		}
		stats := endpointsByHost[host]
		if stats == nil {
			stats = &endpointStats{BySource: make(map[string]int)}
			endpointsByHost[host] = stats
		}
		stats.Total++
		stats.BySource[strings.ToLower(strings.TrimSpace(ep.Source))]++
	}

	exactVulnsByURL := make(map[string]map[string]int)
	hostVulnsByHost := make(map[string]map[string]int)
	for _, vuln := range vulns {
		sev := normalizeSeverity(vuln.Severity)
		if sev == "" {
			sev = "info"
		}

		if vuln.URL != "" {
			normURL := normalizeComparableURL(vuln.URL)
			if normURL != "" {
				if exactVulnsByURL[normURL] == nil {
					exactVulnsByURL[normURL] = make(map[string]int)
				}
				exactVulnsByURL[normURL][sev]++
			}
		}

		host := extractHost(vuln.URL)
		if host == "" {
			host = extractHost(vuln.Host)
		}
		if host != "" {
			if hostVulnsByHost[host] == nil {
				hostVulnsByHost[host] = make(map[string]int)
			}
			hostVulnsByHost[host][sev]++
		}
	}

	portsByHost := make(map[string]int)
	for _, p := range ports {
		host := strings.ToLower(strings.TrimSpace(p.Host))
		if host == "" {
			continue
		}
		portsByHost[host]++
	}

	results := make([]URLROI, 0, len(urls))
	for _, u := range urls {
		host := extractHost(u.URL)
		techs := parseTechList(u.Tech)
		endpointData := endpointsByHost[host]
		exactCounts := cloneStringIntMap(exactVulnsByURL[normalizeComparableURL(u.URL)])
		hostCounts := subtractSeverityMaps(hostVulnsByHost[host], exactCounts)
		meta := mergeMetadata(urlMetadataMap[normalizeComparableURL(u.URL)], hostMetadataMap[host])

		roi := URLROI{
			URL:             u.URL,
			Host:            host,
			StatusCode:      u.StatusCode,
			Title:           u.Title,
			ContentType:     u.ContentType,
			Source:          u.Source,
			Tech:            techs,
			Score:           50,
			Reasons:         []string{"baseline score"},
			ExactVulnCounts: exactCounts,
			HostVulnCounts:  hostCounts,
		}

		addPoints := func(points int, reason string) {
			if points <= 0 {
				return
			}
			roi.Score += points
			roi.Reasons = append(roi.Reasons, fmt.Sprintf("+%d %s", points, reason))
		}

		switch {
		case u.StatusCode == 200:
			addPoints(20, "200 OK live application")
		case u.StatusCode == 401 || u.StatusCode == 403:
			addPoints(16, fmt.Sprintf("%d protected surface", u.StatusCode))
		case u.StatusCode >= 300 && u.StatusCode < 400:
			addPoints(8, "redirecting surface")
		case u.StatusCode >= 500 && u.StatusCode < 600:
			addPoints(12, "server error behavior")
		case u.StatusCode > 0:
			addPoints(4, fmt.Sprintf("responds with status %d", u.StatusCode))
		}

		if len(techs) > 0 {
			addPoints(minInt(18, len(techs)*3), fmt.Sprintf("%d technologies detected", len(techs)))
		}

		if endpointData != nil {
			roi.EndpointCount = endpointData.Total
			roi.KatanaCount = endpointData.BySource["katana"]
			roi.GoSpiderCount = endpointData.BySource["gospider"]
			roi.LinkFinderCount = endpointData.BySource["linkfinder"]
			roi.FfufCount = endpointData.BySource["ffuf"]

			addPoints(minInt(20, endpointData.Total), fmt.Sprintf("%d discovered endpoints on host", endpointData.Total))
			if roi.FfufCount > 0 {
				addPoints(minInt(16, roi.FfufCount*4), fmt.Sprintf("%d ffuf hits", roi.FfufCount))
			}
			if roi.LinkFinderCount > 0 {
				addPoints(minInt(12, roi.LinkFinderCount*3), fmt.Sprintf("%d JS-extracted endpoints", roi.LinkFinderCount))
			}
			crawlCount := roi.KatanaCount + roi.GoSpiderCount
			if crawlCount > 0 {
				addPoints(minInt(14, crawlCount*2), fmt.Sprintf("%d crawler-discovered endpoints", crawlCount))
			}
		}

		roi.OpenPortCount = portsByHost[host]
		if roi.OpenPortCount > 0 {
			addPoints(minInt(10, roi.OpenPortCount*2), fmt.Sprintf("%d open ports on host", roi.OpenPortCount))
		}

		exactPoints, exactSummary := severityScore(exactCounts, true)
		if exactPoints > 0 {
			addPoints(exactPoints, "exact URL vulnerabilities: "+exactSummary)
		}

		hostPoints, hostSummary := severityScore(hostCounts, false)
		if hostPoints > 0 {
			addPoints(hostPoints, "host vulnerabilities: "+hostSummary)
		}

		if strings.Contains(u.URL, "?") && strings.Contains(u.URL, "=") {
			roi.IsParameterized = true
			addPoints(15, "parameterized URL")
		}

		keywords := extractInterestingKeywords(u.URL + " " + u.Title)
		if len(keywords) > 0 {
			roi.InterestingTerms = keywords
			addPoints(minInt(18, len(keywords)*4), "interesting keywords: "+strings.Join(keywords, ", "))
		}

		if isHistoricalSource(u.Source) {
			addPoints(4, fmt.Sprintf("discovered via historical source %s", u.Source))
		}

		if isCrawlerSource(u.Source) {
			addPoints(5, fmt.Sprintf("discovered via crawler %s", u.Source))
		}

		if strings.Contains(strings.ToLower(u.ContentType), "json") {
			addPoints(8, "JSON response surface")
		}

		if meta.HasHostData || meta.HasURLData {
			if !meta.HasCSP {
				if meta.HasURLData {
					addPoints(10, "selected URL metadata shows missing CSP")
				} else {
					addPoints(8, "host metadata shows missing CSP")
				}
			}
			if meta.HasCacheHeaders {
				addPoints(6, "cache-related headers exposed")
			}
			if meta.LoginSurface {
				addPoints(12, "authentication or login surface detected")
			}
			if meta.SSLExpired {
				addPoints(14, "expired SSL certificate")
			}
			if meta.SSLSelfSigned {
				addPoints(10, "self-signed SSL certificate")
			}
			if meta.SSLMismatch {
				addPoints(12, "SSL hostname mismatch")
			}
			if meta.WeakTLS {
				addPoints(10, "weak TLS version detected")
			}
		}

		results = append(results, roi)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].EndpointCount != results[j].EndpointCount {
			return results[i].EndpointCount > results[j].EndpointCount
		}
		return results[i].URL < results[j].URL
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

func parseTechList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var techs []string
	if err := json.Unmarshal([]byte(raw), &techs); err == nil {
		return dedupeStrings(techs)
	}

	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			techs = append(techs, p)
		}
	}
	return dedupeStrings(techs)
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.TrimSpace(host)
}

func normalizeComparableURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return strings.TrimRight(strings.ToLower(raw), "/")
	}
	parsed.Fragment = ""
	s := strings.ToLower(parsed.String())
	return strings.TrimRight(s, "/")
}

func normalizeSeverity(sev string) string {
	return strings.ToLower(strings.TrimSpace(sev))
}

func cloneStringIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func subtractSeverityMaps(total, exact map[string]int) map[string]int {
	if len(total) == 0 {
		return map[string]int{}
	}
	out := cloneStringIntMap(total)
	for sev, count := range exact {
		out[sev] -= count
		if out[sev] < 0 {
			out[sev] = 0
		}
	}
	return out
}

func severityScore(counts map[string]int, exact bool) (int, string) {
	if len(counts) == 0 {
		return 0, ""
	}

	weights := map[string]int{
		"critical": 100,
		"high":     60,
		"medium":   35,
		"low":      15,
		"info":     5,
	}
	if !exact {
		weights = map[string]int{
			"critical": 45,
			"high":     28,
			"medium":   16,
			"low":      8,
			"info":     3,
		}
	}

	order := []string{"critical", "high", "medium", "low", "info"}
	total := 0
	var parts []string
	for _, sev := range order {
		count := counts[sev]
		if count <= 0 {
			continue
		}
		total += count * weights[sev]
		parts = append(parts, fmt.Sprintf("%d %s", count, sev))
	}
	return total, strings.Join(parts, ", ")
}

func extractInterestingKeywords(text string) []string {
	keywords := []string{
		"admin", "login", "signin", "auth", "oauth", "callback", "redirect",
		"token", "api", "graphql", "internal", "debug", "staging", "dev",
		"upload", "webhook", "config",
	}

	text = strings.ToLower(text)
	var matches []string
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			matches = append(matches, keyword)
		}
	}
	return dedupeStrings(matches)
}

func isHistoricalSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return source == "waybackurls" || source == "gau"
}

func isCrawlerSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return source == "katana" || source == "gospider"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mergeMetadata(urlMeta URLMetadata, hostMeta HostMetadata) mergedMetadata {
	return mergedMetadata{
		HasHostData:     hostMeta.Host != "",
		HasURLData:      urlMeta.URL != "",
		HasCSP:          urlMeta.HasCSP || hostMeta.HasCSP,
		HasCacheHeaders: urlMeta.HasCacheHeaders || hostMeta.HasCacheHeaders,
		LoginSurface:    urlMeta.LoginSurface || hostMeta.LoginSurface,
		SSLExpired:      hostMeta.SSLExpired,
		SSLSelfSigned:   hostMeta.SSLSelfSigned,
		SSLMismatch:     hostMeta.SSLMismatch,
		WeakTLS:         hostMeta.WeakTLS,
	}
}
