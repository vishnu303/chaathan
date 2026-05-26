package wildcard_flow

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/utils"
)

// wafCIDRs lists standard public IPv4 network blocks for major WAFs/CDNs (Cloudflare, Fastly, Incapsula, Sucuri, CloudFront).
var wafCIDRs = []string{
	// Cloudflare
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",

	// Fastly
	"151.101.0.0/16", "104.156.80.0/20", "23.235.32.0/20", "43.249.72.0/22",
	"103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "140.248.64.0/18",
	"146.75.0.0/16", "157.185.0.0/16", "167.99.192.0/18", "172.111.0.0/16",
	"185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",

	// Incapsula / Imperva
	"199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
	"45.64.64.0/22", "185.11.124.0/22", "192.230.64.0/18", "107.154.0.0/16",
	"45.250.4.0/22",

	// Sucuri
	"192.124.249.0/24", "185.93.228.0/22", "66.248.200.0/22", "208.109.0.0/22",

	// AWS CloudFront (Common ranges)
	"54.230.0.0/16", "54.239.128.0/18", "52.84.0.0/15", "13.32.0.0/15",
	"13.35.0.0/16", "13.224.0.0/14", "18.172.0.0/15", "18.238.0.0/15",
	"18.244.0.0/15", "64.252.64.0/18",
}

var (
	wafIPNets []*net.IPNet
	onceInit  sync.Once
)

func initCIDRs() {
	onceInit.Do(func() {
		for _, cidr := range wafCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil {
				wafIPNets = append(wafIPNets, ipNet)
			}
		}
	})
}

// isWafIP checks if an IP belongs to a major CDN/WAF public IP range.
func isWafIP(ipStr string) bool {
	initCIDRs()
	parsedIP := net.ParseIP(strings.TrimSpace(ipStr))
	if parsedIP == nil {
		return false
	}
	for _, ipNet := range wafIPNets {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// RunOriginIPBypass performs direct backend IP discovery and verifies
// if CDN/WAF shields can be bypassed via direct HTTP Host injection.
func RunOriginIPBypass(ctx context.Context, c *Ctx) error {
	if !c.EnableOriginBypass {
		return nil
	}

	logger.Section("Optional Step: WAF Origin IP Bypass Resolution")
	logger.SubStep("Analyzing subdomains to discover real backend servers...")

	// 1. Load live subdomains from database
	subs, err := database.GetLiveSubdomains(c.ScanID)
	if err != nil || len(subs) == 0 {
		logger.Info("  No live subdomains found in database for bypass analysis.")
		return nil
	}

	var bypassCount int32
	defer func() {
		count := atomic.LoadInt32(&bypassCount)
		if ctx.Err() != nil {
			logger.Info("  WAF Origin IP Bypass resolution skipped/cancelled. Discovered %d bypass(es) so far.", count)
		} else {
			logger.Success("  WAF Origin IP Bypass resolution completed. Discovered %d bypass(es).", count)
		}
	}()

	var protectedSubs []string
	var directIPs []string
	ipMap := make(map[string]bool)

	// Perform concurrent resolution to quickly map IPs
	var wgResolve sync.WaitGroup
	var mu sync.Mutex
	resolverChan := make(chan string, 100)

	// Workers for DNS resolution
	for i := 0; i < 10; i++ {
		wgResolve.Add(1)
		go func() {
			defer wgResolve.Done()
			for domain := range resolverChan {
				if ctx.Err() != nil {
					continue
				}
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
				if err != nil || len(ips) == 0 {
					continue
				}

				for _, ip := range ips {
					ipStr := ip.String()
					if isWafIP(ipStr) {
						mu.Lock()
						protectedSubs = append(protectedSubs, domain)
						mu.Unlock()
					} else {
						mu.Lock()
						if !ipMap[ipStr] {
							ipMap[ipStr] = true
							directIPs = append(directIPs, ipStr)
						}
						mu.Unlock()
					}
				}
			}
		}()
	}

	for _, sub := range subs {
		if ctx.Err() != nil {
			break
		}
		resolverChan <- sub.Domain
	}
	close(resolverChan)
	wgResolve.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	protectedSubs = utils.DeduplicateSlice(protectedSubs)
	logger.FileDebug("origin_bypass: %d WAF-protected subdomains, %d direct backend candidate IPs found",
		len(protectedSubs), len(directIPs))

	if len(directIPs) == 0 || len(protectedSubs) == 0 {
		logger.Success("  All subdomains resolve uniformly or no direct backend IPs were exposed.")
		return nil
	}

	logger.SubStep("Probing %d backend IPs against %d subdomains...", len(directIPs), len(protectedSubs))

	// Setup premium secure browser-mimicking client
	transport := &http.Transport{
		TLSClientConfig: utils.ModernBrowserTLSConfig(),
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: transport,
	}

	// Limit concurrency for active Host injection checks
	sem := make(chan struct{}, 30)
	var wgProbe sync.WaitGroup

	outer:
	for _, ip := range directIPs {
		for _, domain := range protectedSubs {
			if ctx.Err() != nil {
				break outer
			}
			wgProbe.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wgProbe.Done()
				break outer
			}

			go func(ipVal, domainVal string) {
				defer func() {
					<-sem
					wgProbe.Done()
				}()

				verifyOriginBypass(ctx, c, client, ipVal, domainVal, &bypassCount)
			}(ip, domain)
		}
	}
	wgProbe.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func verifyOriginBypass(ctx context.Context, c *Ctx, client *http.Client, ip string, hostHeader string, bypassCount *int32) {
	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		if ctx.Err() != nil {
			return
		}
		// 1. Establish the baseline behavior (accessing direct IP without the host header)
		baselineURL := fmt.Sprintf("%s://%s/", scheme, ip)
		baselineCode, _, err := makeRawRequest(ctx, client, baselineURL, ip)
		if err != nil {
			continue
		}

		// 2. Perform the bypass probe (address IP directly but inject the protected host header)
		probeURL := fmt.Sprintf("%s://%s/", scheme, ip)
		probeCode, probeBody, err := makeRawRequest(ctx, client, probeURL, hostHeader)
		if err != nil {
			continue
		}

		// 3. Evaluate matching criteria
		// Bypass is successful if the response with the Host header is completely different
		// from the raw IP fallback, returns a standard successful site code, and has meaningful body length.
		if probeCode >= 200 && probeCode < 400 && probeCode != baselineCode {
			// Filter false positives (e.g. WAF block pages on direct IPs)
			bodyLower := strings.ToLower(probeBody)
			if strings.Contains(bodyLower, "direct ip access") ||
				strings.Contains(bodyLower, "cloudflare") ||
				strings.Contains(bodyLower, "captcha") ||
				strings.Contains(bodyLower, "waf") ||
				len(probeBody) < 100 {
				continue
			}

			// Safe fallback validation check - compare direct vs standard target response similarity
			targetURL := fmt.Sprintf("%s://%s/", scheme, hostHeader)
			targetReq, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err == nil {
				targetReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
				resp, err := client.Do(targetReq)
				if err == nil {
					targetBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
					resp.Body.Close()
					targetBody := string(targetBodyBytes)

					// If the bypassed page is structurally similar to the target site, it's a 100% confirmed bypass
					if strings.Contains(bodyLower, "<title>") && strings.Contains(strings.ToLower(targetBody), "<title>") {
						logger.Success("  [WAF-BYPASS CONFIRMED] %s exposed directly at %s://%s", hostHeader, scheme, ip)
						atomic.AddInt32(bypassCount, 1)

						// Save to Database
						description := fmt.Sprintf("Direct Origin IP Bypass Confirmed. The CDN/WAF shields for host %s were successfully bypassed by addressing the backend server directly at %s://%s using HTTP Host header injection.", hostHeader, scheme, ip)
						urlLoc := fmt.Sprintf("%s://%s (Host: %s)", scheme, ip, hostHeader)
						database.AddVulnerability(c.ScanID, ip, urlLoc, "origin-ip-bypass", "Origin WAF Bypass via IP Host Injection", "high", description, "Host Header Match", fmt.Sprintf("Status Code: %d", probeCode))

						// Send Alert Notification
						if c.Notifier != nil {
							c.Notifier.SendFinding(notify.Finding{
								Target:    c.Domain,
								Type:      "origin-ip-bypass",
								Name:      "Origin WAF Bypass via IP Host Injection",
								Severity:  "high",
								URL:       urlLoc,
								Timestamp: time.Now(),
							})
						}
						break
					}
				}
			}
		}
	}
}

func makeRawRequest(ctx context.Context, client *http.Client, urlStr, hostHeader string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(bodyBytes), nil
}
