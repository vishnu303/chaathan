package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
)

// ToolBox wraps the runner and provides methods to invoke external recon tools.
// It reads per-tool settings (threads, timeouts, rate limits) from the config
// so users can tune behavior via config.yaml instead of recompiling.
type ToolBox struct {
	Runner     runner.Runner
	Config     *config.ToolsConfig
	General    *config.GeneralConfig    // WAF evasion settings (UA rotation, proxy, etc.)
	RateLimits *config.RateLimitConfig  // Global rate-limit override
	APIKeys    *config.APIKeysConfig
}

// New creates a ToolBox. If cfg is nil, sensible defaults are used.
func New(r runner.Runner, cfg ...*config.ToolsConfig) *ToolBox {
	tb := &ToolBox{Runner: r}
	if len(cfg) > 0 && cfg[0] != nil {
		tb.Config = cfg[0]
	}
	return tb
}

// WithGeneral attaches general config to the ToolBox (WAF evasion, etc.).
func (t *ToolBox) WithGeneral(gen *config.GeneralConfig) *ToolBox {
	t.General = gen
	return t
}

// WithRateLimits attaches rate-limit config to the ToolBox.
func (t *ToolBox) WithRateLimits(rl *config.RateLimitConfig) *ToolBox {
	t.RateLimits = rl
	return t
}

// WithAPIKeys attaches API key config to the ToolBox (used by uncover, etc).
func (t *ToolBox) WithAPIKeys(keys *config.APIKeysConfig) *ToolBox {
	t.APIKeys = keys
	return t
}

// --- User-Agent rotation pool ---

// realUserAgents contains common, high-frequency browser User-Agent strings.
// Rotating through these prevents WAF fingerprinting from static tool UAs
// like "httpx - Open-source project" or "Nuclei - Open-source project".
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

// uaEnabled returns true when UA rotation is active.
func (t *ToolBox) uaEnabled() bool {
	return t.General != nil && (t.General.UARotation || t.General.UserAgent != "")
}

// getUA returns the User-Agent to use: fixed override or random from pool.
func (t *ToolBox) getUA() string {
	if t.General != nil && t.General.UserAgent != "" {
		return t.General.UserAgent
	}
	return randomUA()
}

// appendUAHeader appends a -H "User-Agent: ..." flag pair for tools that
// accept the -H syntax (httpx, nuclei, katana, ffuf).
func (t *ToolBox) appendUAHeader(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	return append(args, "-H", "User-Agent: "+t.getUA())
}

// appendDalfoxUA appends --header "User-Agent: ..." for dalfox.
func (t *ToolBox) appendDalfoxUA(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	return append(args, "--header", "User-Agent: "+t.getUA())
}

// appendGoSpiderUA appends --user-agent "..." for gospider.
func (t *ToolBox) appendGoSpiderUA(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	return append(args, "--user-agent", t.getUA())
}

// appendArjunUA appends --headers '{"User-Agent":"..."}' for arjun.
func (t *ToolBox) appendArjunUA(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	headers := map[string]string{"User-Agent": t.getUA()}
	headersJSON, _ := json.Marshal(headers)
	return append(args, "--headers", string(headersJSON))
}

// --- Proxy helpers ---

// proxy returns the configured proxy URL, or "" if none.
func (t *ToolBox) proxy() string {
	if t.General != nil && t.General.Proxy != "" {
		return t.General.Proxy
	}
	return ""
}

// appendProxy appends the tool-specific proxy flag when a proxy is configured.
func (t *ToolBox) appendProxy(args []string, flagName string) []string {
	if p := t.proxy(); p != "" {
		return append(args, flagName, p)
	}
	return args
}

// --- Rate-limit helpers ---

// globalRPS returns the global rate limit override, or 0 if none.
func (t *ToolBox) globalRPS() int {
	if t.RateLimits != nil && t.RateLimits.GlobalRPS > 0 {
		return t.RateLimits.GlobalRPS
	}
	return 0
}

// effectiveRate returns the lower of globalRPS and perToolRate (ceiling logic).
// When globalRPS is 0 (unset), the per-tool rate is used as-is.
func (t *ToolBox) effectiveRate(perToolRate int) int {
	if grl := t.globalRPS(); grl > 0 && grl < perToolRate {
		return grl
	}
	return perToolRate
}

// --- helpers to read config with fallback defaults ---

func (t *ToolBox) subfinderThreads() int {
	if t.Config != nil && t.Config.Subfinder.Threads > 0 {
		return t.Config.Subfinder.Threads
	}
	return 30
}

func (t *ToolBox) subfinderTimeout() int {
	if t.Config != nil && t.Config.Subfinder.Timeout > 0 {
		return t.Config.Subfinder.Timeout
	}
	return 30
}

func (t *ToolBox) httpxThreads() int {
	if t.Config != nil && t.Config.Httpx.Threads > 0 {
		return t.Config.Httpx.Threads
	}
	return 50
}

func (t *ToolBox) httpxTimeout() int {
	if t.Config != nil && t.Config.Httpx.Timeout > 0 {
		return t.Config.Httpx.Timeout
	}
	return 10
}

func (t *ToolBox) httpxPorts() string {
	if t.Config != nil && len(t.Config.Httpx.Ports) > 0 {
		return strings.Join(t.Config.Httpx.Ports, ",")
	}
	return "80,443,8080,8443,8081,8000,8008,8888"
}

func (t *ToolBox) naabuThreads() int {
	if t.Config != nil && t.Config.Naabu.Threads > 0 {
		return t.Config.Naabu.Threads
	}
	return 25
}

func (t *ToolBox) naabuRate() int {
	if t.Config != nil && t.Config.Naabu.Rate > 0 {
		return t.Config.Naabu.Rate
	}
	return 1000
}

func (t *ToolBox) naabuPorts() string {
	if t.Config != nil && t.Config.Naabu.Ports != "" {
		return t.Config.Naabu.Ports
	}
	return "" // empty means use -top-ports 1000 flag
}

func (t *ToolBox) naabuTopPorts() int {
	// Default to top 1000 ports when no explicit port list is set
	if t.Config != nil && t.Config.Naabu.Ports != "" {
		return 0 // explicit port list set, don't use -top-ports
	}
	return 1000
}

func (t *ToolBox) nucleiConcurrency() int {
	if t.Config != nil && t.Config.Nuclei.Concurrency > 0 {
		return t.Config.Nuclei.Concurrency
	}
	return 25
}

func (t *ToolBox) nucleiRateLimit() int {
	if t.Config != nil && t.Config.Nuclei.RateLimit > 0 {
		return t.Config.Nuclei.RateLimit
	}
	return 150
}

func (t *ToolBox) nucleiExcludeTags() []string {
	if t.Config != nil && len(t.Config.Nuclei.ExcludeTags) > 0 {
		return t.Config.Nuclei.ExcludeTags
	}
	return []string{"dos", "fuzz"}
}

func (t *ToolBox) nucleiSeverity() []string {
	if t.Config != nil && len(t.Config.Nuclei.Severity) > 0 {
		return t.Config.Nuclei.Severity
	}
	return nil // default: all severities
}

func (t *ToolBox) nucleiInfraTags() []string {
	return []string{"cves", "exposures", "misconfiguration", "takeovers", "ssl"}
}

func (t *ToolBox) nucleiURLTags() []string {
	return []string{"xss", "sqli", "ssrf", "lfi", "rce", "redirect", "exposures"}
}

func (t *ToolBox) ffufThreads() int {
	if t.Config != nil && t.Config.Ffuf.Threads > 0 {
		return t.Config.Ffuf.Threads
	}
	return 50
}

func (t *ToolBox) ffufTimeout() int {
	if t.Config != nil && t.Config.Ffuf.Timeout > 0 {
		return t.Config.Ffuf.Timeout
	}
	return 10
}

func (t *ToolBox) ffufMatchCodes() string {
	if t.Config != nil && len(t.Config.Ffuf.MatchCodes) > 0 {
		var codes []string
		for _, c := range t.Config.Ffuf.MatchCodes {
			codes = append(codes, strconv.Itoa(c))
		}
		return strings.Join(codes, ",")
	}
	return "200,201,204,301,302,307,401,403,405,500"
}

// --- Passive Enumeration ---

func (t *ToolBox) RunSubfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{
		"-d", domain,
		"-silent",
		"-t", strconv.Itoa(t.subfinderThreads()),
		"-timeout", strconv.Itoa(t.subfinderTimeout()),
		"-o", outputFile,
	}
	_, err := t.Runner.Run(ctx, "subfinder", args)
	return err
}

func (t *ToolBox) RunAssetfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{"--subs-only", domain}
	output, err := t.Runner.Run(ctx, "assetfinder", args)
	if err != nil {
		// On skip/cancel: save whatever partial output landed in the stdout buffer.
		if ctx.Err() != nil && strings.TrimSpace(output) != "" {
			_ = writeToFile(outputFile, output)
		}
		return err
	}
	return writeToFile(outputFile, output)
}

func (t *ToolBox) RunSublist3r(ctx context.Context, domain string, outputFile string) error {
	args := []string{"-d", domain, "-t", "50", "-v", "-o", outputFile}
	_, err := t.Runner.Run(ctx, "sublist3r", args)
	return err
}

// --- Active Enumeration ---

func (t *ToolBox) RunAmass(ctx context.Context, domain string, outputFile string) error {
	args := []string{"enum", "-active", "-alts", "-d", domain, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, "amass", args)
	return err
}

func (t *ToolBox) RunGau(ctx context.Context, domain string, outputFile string) error {
	args := []string{domain, "--providers", "wayback", "--subs", "--o", outputFile}
	_, err := t.Runner.Run(ctx, "gau", args)
	return err
}

// --- DNS & Brute Force ---

func (t *ToolBox) RunDnsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{"-l", inputFile, "-a", "-aaaa", "-cname", "-mx", "-txt", "-resp", "-json", "-o", outputFile}
	_, err := t.Runner.Run(ctx, "dnsx", args)
	return err
}

// --- Live Probing ---

func (t *ToolBox) RunHttpx(ctx context.Context, domainsFile string, outputFile string) error {
	args := []string{
		"-l", domainsFile,
		"-ports", t.httpxPorts(),
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-tech-detect", "-title", "-status-code", "-json",
		"-o", outputFile,
	}
	if t.Config != nil && t.Config.Httpx.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-http-proxy")
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunNaabu port-scans a single host.
func (t *ToolBox) RunNaabu(ctx context.Context, host string, outputFile string) error {
	args := []string{
		"-host", host,
		"-rate", strconv.Itoa(t.effectiveRate(t.naabuRate())),
		"-c", strconv.Itoa(t.naabuThreads()),
		"-o", outputFile,
	}
	// Use explicit port list if configured, otherwise use -top-ports
	if ports := t.naabuPorts(); ports != "" {
		if strings.ToLower(ports) == "top" || strings.ToLower(ports) == "top-100" {
			args = append(args, "-top-ports", "100")
		} else if strings.ToLower(ports) == "top-1000" {
			args = append(args, "-top-ports", "1000")
		} else if strings.ToLower(ports) == "full" || strings.ToLower(ports) == "-" {
			args = append(args, "-p", "-")
		} else {
			args = append(args, "-p", ports)
		}
	} else {
		args = append(args, "-top-ports", strconv.Itoa(t.naabuTopPorts()))
	}
	args = t.appendProxy(args, "-proxy")
	_, err := t.Runner.Run(ctx, "naabu", args)
	return err
}

// RunNaabuList port-scans all hosts from a file (the correct way for recon).
func (t *ToolBox) RunNaabuList(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-rate", strconv.Itoa(t.effectiveRate(t.naabuRate())),
		"-c", strconv.Itoa(t.naabuThreads()),
		"-o", outputFile,
	}
	// Use explicit port list if configured, otherwise use -top-ports
	if ports := t.naabuPorts(); ports != "" {
		if strings.ToLower(ports) == "top" || strings.ToLower(ports) == "top-100" {
			args = append(args, "-top-ports", "100")
		} else if strings.ToLower(ports) == "top-1000" {
			args = append(args, "-top-ports", "1000")
		} else if strings.ToLower(ports) == "full" || strings.ToLower(ports) == "-" {
			args = append(args, "-p", "-")
		} else {
			args = append(args, "-p", ports)
		}
	} else {
		args = append(args, "-top-ports", strconv.Itoa(t.naabuTopPorts()))
	}
	args = t.appendProxy(args, "-proxy")
	_, err := t.Runner.Run(ctx, "naabu", args)
	return err
}

// --- Web Crawling & Fuzzing ---

func (t *ToolBox) RunGoSpider(ctx context.Context, url string, outputFile string) error {
	args := []string{"-s", url, "-o", outputFile, "-c", "10", "-d", "3"}
	args = t.appendGoSpiderUA(args)
	args = t.appendProxy(args, "--proxy")
	_, err := t.Runner.Run(ctx, "gospider", args)
	return err
}

func (t *ToolBox) RunKatana(ctx context.Context, url string, outputFile string) error {
	args := []string{"-u", url, "-o", outputFile, "-jc"}
	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-proxy")
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "katana", args)
	return err
}

func (t *ToolBox) RunFfuf(ctx context.Context, url string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", t.ffufMatchCodes(),
		"-o", outputFile,
		"-of", "json",
		"-t", strconv.Itoa(t.ffufThreads()),
		"-timeout", strconv.Itoa(t.ffufTimeout()),
	}
	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-x")
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "ffuf", args)
	return err
}

// RunFfufWithFUZZ runs ffuf with a FUZZ placeholder in the URL
func (t *ToolBox) RunFfufWithFUZZ(ctx context.Context, baseURL string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	// Ensure FUZZ is in URL
	url := baseURL
	if !strings.Contains(url, "FUZZ") {
		url = baseURL + "/FUZZ"
	}
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", t.ffufMatchCodes(),
		"-o", outputFile,
		"-of", "json",
		"-t", strconv.Itoa(t.ffufThreads()),
		"-timeout", strconv.Itoa(t.ffufTimeout()),
	}
	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-x")
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "ffuf", args)
	return err
}

// --- Vulnerability Scanning ---

func (t *ToolBox) RunNuclei(ctx context.Context, targetsFile string, outputFile string) error {
	rateLimit := t.effectiveRate(t.nucleiRateLimit())
	args := []string{
		"-l", targetsFile,
		"-c", strconv.Itoa(t.nucleiConcurrency()),
		"-rl", strconv.Itoa(rateLimit),
		"-tags", strings.Join(t.nucleiInfraTags(), ","),
		"-jsonl",
		"-o", outputFile,
	}

	// Apply exclude tags from config
	excludeTags := t.nucleiExcludeTags()
	if len(excludeTags) > 0 {
		args = append(args, "-etags", strings.Join(excludeTags, ","))
	}

	// Apply severity filter from config
	severity := t.nucleiSeverity()
	if len(severity) > 0 {
		args = append(args, "-severity", strings.Join(severity, ","))
	}

	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-proxy")
	_, err := t.Runner.Run(ctx, "nuclei", args)
	return err
}

// --- Cloud & Org ---

func (t *ToolBox) RunMetabigorNet(ctx context.Context, org string, outputFile string) error {
	args := []string{"net", "--org", "-v", org}
	output, err := t.Runner.Run(ctx, "metabigor", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

func (t *ToolBox) RunCloudEnum(ctx context.Context, keyword string, outputFile string) error {
	args := []string{"-k", keyword, "-f", "json", "-l", outputFile}
	_, err := t.Runner.Run(ctx, "cloud_enum", args)
	return err
}

func (t *ToolBox) RunSubdomainizer(ctx context.Context, url string, outputFile string) error {
	args := []string{"-u", url, "-o", outputFile}
	_, err := t.Runner.Run(ctx, "subdomainizer", args)
	return err
}

// --- URL Discovery ---

// RunWaybackurls fetches historical URLs from Wayback Machine
func (t *ToolBox) RunWaybackurls(ctx context.Context, domain string, outputFile string) error {
	args := []string{domain}
	output, err := t.Runner.Run(ctx, "waybackurls", args)
	if err != nil {
		// On skip/cancel: save whatever partial output landed in the stdout buffer.
		if ctx.Err() != nil && strings.TrimSpace(output) != "" {
			_ = writeToFile(outputFile, output)
		}
		return err
	}
	return writeToFile(outputFile, output)
}

// RunLinkfinder extracts endpoints from JavaScript files
func (t *ToolBox) RunLinkfinder(ctx context.Context, url string, outputFile string) error {
	args := []string{"-i", url, "-o", "cli"}
	output, err := t.Runner.Run(ctx, "linkfinder", args)
	if err != nil {
		// On skip/cancel: save whatever partial output landed in the stdout buffer.
		if ctx.Err() != nil && strings.TrimSpace(output) != "" {
			_ = writeToFile(outputFile, output)
		}
		return err
	}
	return writeToFile(outputFile, output)
}

// RunLinkfinderOnFile runs linkfinder on a local JS file
func (t *ToolBox) RunLinkfinderOnFile(ctx context.Context, jsFile string, outputFile string) error {
	args := []string{"-i", jsFile, "-o", "cli"}
	output, err := t.Runner.Run(ctx, "linkfinder", args)
	if err != nil {
		// On skip/cancel: save whatever partial output landed in the stdout buffer.
		if ctx.Err() != nil && strings.TrimSpace(output) != "" {
			_ = writeToFile(outputFile, output)
		}
		return err
	}
	return writeToFile(outputFile, output)
}

// RunArjun discovers hidden HTTP parameters on a URL
func (t *ToolBox) RunArjun(ctx context.Context, url string, outputFile string) error {
	args := []string{"-u", url, "-oJ", outputFile, "--stable"}
	args = t.appendArjunUA(args)
	_, err := t.Runner.Run(ctx, "arjun", args)
	return err
}

// RunArjunFromFile discovers hidden HTTP parameters from a file of URLs
func (t *ToolBox) RunArjunFromFile(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{"-i", inputFile, "-oJ", outputFile, "--stable"}
	args = t.appendArjunUA(args)
	_, err := t.Runner.Run(ctx, "arjun", args)
	return err
}

// RunHttpxURLCheck live-checks a list of URLs (not subdomains) and outputs only live URLs
func (t *ToolBox) RunHttpxURLCheck(ctx context.Context, urlsFile string, outputFile string) error {
	args := []string{
		"-l", urlsFile,
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-status-code",
		"-no-fallback",
		"-o", outputFile,
	}
	if t.Config != nil && t.Config.Httpx.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-http-proxy")
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunHttpxFetchJS downloads JS responses into downloadDir using conservative
// concurrency so the workflow can scan local copies for secrets with low noise.
func (t *ToolBox) RunHttpxFetchJS(ctx context.Context, urlsFile string, downloadDir string) error {
	threads := 10
	timeout := 5
	if t.Config != nil && t.Config.Httpx.Threads > 0 {
		threads = t.Config.Httpx.Threads / 5
		if threads < 5 {
			threads = 5
		}
		if threads > 15 {
			threads = 15
		}
	}

	args := []string{
		"-l", urlsFile,
		"-sr",
		"-srd", downloadDir,
		"-threads", strconv.Itoa(threads),
		"-timeout", strconv.Itoa(timeout),
		"-silent",
		"-no-fallback",
	}
	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-http-proxy")
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunNucleiURLs runs nuclei on specific URLs with stricter rate limits.
// Used for path-specific vulnerability scanning (separate from infra scanning).
func (t *ToolBox) RunNucleiURLs(ctx context.Context, urlsFile string, outputFile string) error {
	// Use half the normal rate limit for URL scanning to reduce noise
	rateLimit := t.nucleiRateLimit() / 2
	if rateLimit < 25 {
		rateLimit = 25
	}
	rateLimit = t.effectiveRate(rateLimit) // apply global ceiling
	concurrency := t.nucleiConcurrency() / 2
	if concurrency < 5 {
		concurrency = 5
	}

	args := []string{
		"-l", urlsFile,
		"-c", strconv.Itoa(concurrency),
		"-rl", strconv.Itoa(rateLimit),
		"-tags", strings.Join(t.nucleiURLTags(), ","),
		"-severity", "critical,high,medium",
		"-jsonl",
		"-o", outputFile,
	}

	// Apply exclude tags from config
	excludeTags := t.nucleiExcludeTags()
	if len(excludeTags) > 0 {
		args = append(args, "-etags", strings.Join(excludeTags, ","))
	}

	args = t.appendUAHeader(args)
	args = t.appendProxy(args, "-proxy")
	_, err := t.Runner.Run(ctx, "nuclei", args)
	return err
}

// RunGFPattern filters an input file with a single gf pattern and writes matches.
//
// INTENTIONAL RUNNER BYPASS: gf is a local text-filtering utility that reads
// JSON pattern definitions from the host's ~/.gf/ directory. It does NOT make
// network requests and is not available as a Docker image. Running it through
// t.Runner.Run() would fail in Docker mode because the container wouldn't have
// access to the host's ~/.gf/ patterns. Therefore this function uses
// exec.CommandContext directly. This is a deliberate design choice, not a bug.
//
// Implications:
//   - gf always runs natively regardless of the runner mode (native/docker)
//   - Retry logic from the Runner is not applied (gf is a pure text filter — retries are meaningless)
//   - Verbose logging from the Runner is not applied (gf output is captured into the output file)
func (t *ToolBox) RunGFPattern(ctx context.Context, pattern string, inputFile string, outputFile string) error {
	if pattern == "" {
		return fmt.Errorf("gf requires a pattern name")
	}
	if inputFile == "" {
		return fmt.Errorf("gf requires an input file")
	}

	cmd := exec.CommandContext(ctx, "gf", pattern, inputFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%v: %s", err, stderr.String())
		}
		return err
	}
	return writeToFile(outputFile, stdout.String())
}

// --- GitHub Reconnaissance ---

// RunGithubEndpoints searches GitHub for exposed endpoints/secrets
func (t *ToolBox) RunGithubEndpoints(ctx context.Context, domain string, githubToken string, outputFile string) error {
	if githubToken == "" {
		return fmt.Errorf("github-endpoints requires a GitHub token (set GITHUB_TOKEN env var)")
	}
	args := []string{"-d", domain}
	output, err := t.Runner.Run(ctx, "github-endpoints", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

// RunGithubSubdomains searches GitHub for subdomains
func (t *ToolBox) RunGithubSubdomains(ctx context.Context, domain string, githubToken string, outputFile string) error {
	if githubToken == "" {
		return fmt.Errorf("github-subdomains requires a GitHub token")
	}
	args := []string{"-d", domain, "-t", githubToken, "-o", outputFile}
	_, err := t.Runner.Run(ctx, "github-subdomains", args)
	return err
}

// --- DNS Brute-force ---

// RunShuffleDNS performs DNS brute-forcing using shuffledns (massdns wrapper).
// It takes a domain, a wordlist for brute-forcing, and an optional resolvers file.
func (t *ToolBox) RunShuffleDNS(ctx context.Context, domain string, wordlist string, resolversFile string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("shuffledns requires a wordlist path")
	}
	args := []string{
		"-d", domain,
		"-w", wordlist,
		"-o", outputFile,
		"-silent",
	}
	if resolversFile != "" {
		args = append(args, "-r", resolversFile)
	}
	// Check for massdns in PATH and use it
	args = append(args, "-type", "bruteforce")
	_, err := t.Runner.Run(ctx, "shuffledns", args)
	return err
}

// RunShuffleDNSResolve uses shuffledns to resolve a list of subdomains (resolve mode).
func (t *ToolBox) RunShuffleDNSResolve(ctx context.Context, inputFile string, resolversFile string, outputFile string) error {
	args := []string{
		"-list", inputFile,
		"-o", outputFile,
		"-silent",
	}
	if resolversFile != "" {
		args = append(args, "-r", resolversFile)
	}
	_, err := t.Runner.Run(ctx, "shuffledns", args)
	return err
}

// --- Subdomain Takeover ---

// RunSubjack checks discovered subdomains for potential subdomain takeover vulnerabilities
// by looking for dangling CNAME records pointing to claimable services.
// The -c flag points to fingerprints.json. Since `go install` places it in the
// module cache rather than GOPATH/src, we locate it dynamically and pass -c.
func (t *ToolBox) RunSubjack(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-w", inputFile,
		"-o", outputFile,
		"-ssl",
		"-t", "50",
		"-timeout", "30",
		"-a",
	}
	if fp := findSubjackFingerprints(); fp != "" {
		args = append(args, "-c", fp)
	}
	_, err := t.Runner.Run(ctx, "subjack", args)
	return err
}

// findSubjackFingerprints searches common locations for subjack's fingerprints.json.
func findSubjackFingerprints() string {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}

	// Check module cache (where `go install` puts it)
	modDir := filepath.Join(gopath, "pkg", "mod", "github.com", "haccer")
	if entries, err := os.ReadDir(modDir); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "subjack@") {
				fp := filepath.Join(modDir, e.Name(), "fingerprints.json")
				if _, err := os.Stat(fp); err == nil {
					return fp
				}
			}
		}
	}

	// Fallback: legacy GOPATH/src location
	legacy := filepath.Join(gopath, "src", "github.com", "haccer", "subjack", "fingerprints.json")
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}

	return ""
}

// --- XSS Scanning ---

// RunDalfox scans URLs with parameters for XSS vulnerabilities.
// Takes a list of parameterized URLs and tests for reflected/stored XSS.
func (t *ToolBox) RunDalfox(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"file", inputFile,
		"-o", outputFile,
		"--silence",
		"--no-color",
		"--output-all",
	}
	args = t.appendDalfoxUA(args)
	args = t.appendProxy(args, "--proxy")
	if rps := t.globalRPS(); rps > 0 {
		delayMs := 1000 / rps
		if delayMs < 1 {
			delayMs = 1
		}
		args = append(args, "--delay", strconv.Itoa(delayMs))
	}
	_, err := t.Runner.Run(ctx, "dalfox", args)
	return err
}

// RunDalfoxURL scans a single URL for XSS.
func (t *ToolBox) RunDalfoxURL(ctx context.Context, targetURL string, outputFile string) error {
	args := []string{
		"url", targetURL,
		"-o", outputFile,
		"--silence",
		"--no-color",
	}
	args = t.appendDalfoxUA(args)
	args = t.appendProxy(args, "--proxy")
	if rps := t.globalRPS(); rps > 0 {
		delayMs := 1000 / rps
		if delayMs < 1 {
			delayMs = 1
		}
		args = append(args, "--delay", strconv.Itoa(delayMs))
	}
	_, err := t.Runner.Run(ctx, "dalfox", args)
	return err
}

// --- TLS/SSL Analysis ---

// RunTlsx grabs TLS certificate information from live hosts.
// Extracts SANs (extra subdomains), expiry info, and cipher details.
// NOTE: -resp-only is only valid with -san/-cn alone; omit it when using -so/-ex.
func (t *ToolBox) RunTlsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-json",
		"-san", "-cn", // Request SANs and Common Name (do not mix with -so or -ex)
		"-c", "50",
	}
	_, err := t.Runner.Run(ctx, "tlsx", args)
	return err
}

// RunTlsxHost checks TLS for a single host.
func (t *ToolBox) RunTlsxHost(ctx context.Context, host string, outputFile string) error {
	args := []string{
		"-u", host,
		"-o", outputFile,
		"-json",
		"-san", "-cn",
	}
	_, err := t.Runner.Run(ctx, "tlsx", args)
	return err
}

// --- Passive Search Engine Recon ---

// RunUncover queries search engines (Shodan, Censys, Fofa, etc.) for exposed assets.
// 100% passive — no packets sent to the target.
// Returns ErrNoAPIKeys if no API keys are configured for any engine.
func (t *ToolBox) RunUncover(ctx context.Context, domain string, outputFile string) error {
	engines := t.uncoverEngines()
	if len(engines) == 0 {
		return fmt.Errorf("no uncover API keys configured — set shodan/censys/fofa keys in config.yaml")
	}

	args := []string{
		"-q", domain,
		"-o", outputFile,
		"-json",
		"-silent",
		"-e", strings.Join(engines, ","),
	}

	_, err := t.Runner.Run(ctx, "uncover", args)
	return err
}

// uncoverEngines returns only the engines for which API keys are configured.
// If no keys are set, returns an empty slice so RunUncover can skip gracefully.
func (t *ToolBox) uncoverEngines() []string {
	if t.APIKeys == nil {
		return nil
	}
	var engines []string
	if t.APIKeys.Shodan != "" {
		engines = append(engines, "shodan")
	}
	if t.APIKeys.Censys != "" || (t.APIKeys.CensysID != "" && t.APIKeys.CensysSecret != "") {
		engines = append(engines, "censys")
	}
	if t.APIKeys.Fofa != "" {
		engines = append(engines, "fofa")
	}
	return engines
}

// Helper
func writeToFile(path string, content string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
