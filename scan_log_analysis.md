# Scan Log Analysis — `facebook.com` Wildcard Scan

**Scan**: facebook.com · ID 1 · 21m00s · 2026-06-17T19:15:30Z

## Summary Stats

| Metric | Value |
|--------|-------|
| Subdomains discovered | 52,849 |
| Live hosts (httpx) | 110 → 34 in DB |
| Open ports | 0 |
| URLs collected | 4,738 |
| Endpoints (GoLinkFinder) | 6 → 3 stored |
| Vulnerabilities | 0 |
| Steps skipped by user | ~15 of 23 |

---

## Issue 1 — GoLinkFinder Serial Timeout Storm (Critical)

**Symptom**: Step 14 spent **~4 minutes** hammering unreachable hosts with 10-second timeouts + retries, producing a wall of `TOOL ERROR` noise. It ran GoLinkFinder on hosts like `http://0-edge-chat.facebook.com:8000`, `http://01.eze1.facebook.com:8888`, etc. — most of which are either unreachable or don't resolve.

**Root cause**: [stepJSAnalysis](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go#L268-L335) loads up to 50 hosts from `httpx_live_hosts.txt` and runs GoLinkFinder **serially** on each one. Since httpx probed 6 ports per host (80,443,8080,8443,8000,8888), the live hosts file includes entries on non-standard ports that GoLinkFinder can't reach. Each failure triggers a retry (1 retry × 10s timeout = 20s per host), and with 50 hosts that's potentially **16+ minutes** of wasted time.

**Fix**:
1. **Filter to ports 80/443 only** (or deduplicate by hostname, preferring 443 > 80 > others) before feeding to GoLinkFinder
2. **Run GoLinkFinder with concurrency** (e.g. 5-10 goroutines) instead of serial iteration
3. **Add a per-host timeout** of 15s (total, not just HTTP) to prevent any single host from blocking the pipeline
4. Consider: GoLinkFinder only makes sense on hosts serving HTML/JS — skip hosts that returned non-2xx or non-HTML content types from httpx

> [!IMPORTANT]
> This is the biggest bang-for-buck fix. A target with 100+ live hosts on 6 ports = 600 serial GoLinkFinder invocations, each with retries. On a large target this step alone could take **hours**.

**Affected**: [content_discovery.go:L277-L307](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go#L277-L307)

---

## Issue 2 — GoLinkFinder Scheme Mismatch on TLS Ports

**Symptom**: GoLinkFinder is called with `http://0.facebook.com:8443` — but port 8443 is conventionally HTTPS. The tool times out because it's speaking plaintext HTTP to an HTTPS listener.

**Root cause**: The scheme-prefix logic at [L290-L292](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go#L290-L292) only checks if the host already has a scheme; it doesn't correct mismatches. `httpx_live_hosts.txt` comes from `collectLiveHostTargetsFromHttpx()` which preserves the original scheme+port from httpx's JSONL `url` field — but GoLinkFinder just uses whatever's there.

**Fix**: Since the urls from httpx already include the correct scheme (httpx negotiates TLS), the `httpx_live_hosts.txt` entries should already be correct. The real issue is that the fallback for bare hostnames at L290-292 doesn't intelligently set scheme per port. If entries do arrive as bare `host:port` pairs, map TLS ports (443, 8443) → `https://`, others → `http://`.

**Affected**: [content_discovery.go:L289-L292](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go#L289-L292)

---

## Issue 3 — Redundant Proxy Re-Scraping Per Phase

**Symptom**: Proxy scraping + mubeng validation ran **5 times** during the scan (phases 0–4), scraping ~16k proxies each time and user had to skip validation each time. Total time wasted: ~8 minutes of proxy validation that was always skipped.

**Observed pattern**:
- Phase 0: 16,055 proxies → 344 validated (skipped)
- Phase 2: 16,188 proxies → 412 validated (skipped)
- Phase 3: 16,250 proxies → 354 validated (skipped)
- Phase 4: 16,365 proxies → 148 validated (skipped)
- Phase 5: 16,365 proxies → 41 validated (skipped)

The proxy pool degrades each phase (344 → 41 validated) which suggests many proxies from earlier scrapes died, but the re-scrape found essentially the same list.

**Suggested improvement**: Consider:
1. Only re-scrape proxies if the pool drops below a configurable threshold (e.g. 50 proxies)
2. Re-use the existing validated pool for subsequent phases rather than re-validating from scratch
3. Add a `--proxy-refresh-threshold` flag to control this behavior

**Affected**: [proxy_scraping.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/proxy_scraping.go)

---

## Issue 4 — Missing seclists Wordlists Silently Skip 3 Steps

**Symptom**: Three steps were completely skipped due to missing wordlists:
- Step 8 (ShuffleDNS): `subdomains-top1million-5000.txt` not found
- Step 15 (ffuf): `common.txt` not found
- Step 16 (Arjun): `burp-parameter-names.txt` not found (fell back to built-in)

**Impact**: No DNS brute-forcing and no directory fuzzing ran at all. For a target like facebook.com this is a significant loss — DNS brute-forcing often discovers subdomains that passive sources miss.

**Suggested improvement**: 
1. **Pre-flight check at scan start**: Validate all configured wordlist paths before starting the scan and warn the user upfront that N steps will be skipped
2. **`chaathan setup` enhancement**: Include seclists installation in the setup command
3. **Bundle minimal wordlists**: Ship small built-in wordlists (e.g. top-1000 DNS, top-500 dirs) as fallbacks

---

## Issue 5 — Arjun Upstream Crash

**Symptom**: Arjun crashes with `AttributeError: 'str' object has no attribute 'status_code'` — this is a known upstream bug in Arjun where it receives an error string instead of a response object.

**Impact**: Step 16 produced 0 parameterized URLs → Step 21 (DAST) and Step 22 (XSS) both skipped because there were no parameterized URLs to scan.

**Suggested improvement**: This is an upstream Arjun bug, but Chaathan should:
1. Log a more actionable message: "Arjun has a known compatibility issue — consider upgrading or using an alternative"
2. Consider falling back to `paramspider` as an alternative parameter discovery tool

---

## Issue 6 — Thin DAST/XSS Results from Cascading Skips

**Symptom**: Steps 21 (Nuclei DAST) and 22 (Dalfox XSS) both immediately skipped because there were 0 parameterized URLs in the 36 live URLs.

**Root cause cascade**:
1. httpx was skipped (Step 10) → only 110 partial results
2. URL live-check (Step 17) was skipped → fallback to raw URLs
3. Arjun crashed (Step 16) → 0 parameterized URLs
4. No ffuf results (Step 15) → no discovered endpoints
5. Result: 36 live URLs, 0 with query params → DAST/XSS completely skipped

**Suggested improvement**: Even when Arjun fails, extract parameterized URLs from the historical URL sources (waybackurls/gau already found 4,505 URLs — many likely have query parameters). The `CollectScopedURLs` function already does this filtering but only from `all_urls_live.txt`, which was populated from the fallback path.

---

## Issue 7 — GoLinkFinder `defer os.Remove` Inside Loop

**Symptom**: Not visible in log but present in code — a minor resource leak.

**Root cause**: At [L296](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go#L296), `defer os.Remove(tmpOut)` is inside a `for` loop, so all defers stack up and only execute when the outer function returns. For 50 hosts this means 50 temp files exist simultaneously on disk until the entire step finishes.

**Fix**: Replace `defer os.Remove(tmpOut)` with an explicit `os.Remove(tmpOut)` at the end of each loop iteration, or wrap each iteration in an anonymous function so `defer` fires per-iteration.

**Affected**: [content_discovery.go:L296](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/content_discovery.go#L296)

---

## Overall Assessment

The scan completed in 21 minutes but produced very thin results (0 vulnerabilities, 3 endpoints, 0 ports) because the user skipped most long-running tools. The **GoLinkFinder serial timeout storm** is the most impactful fix — it's the only step that was so noisy the user had to skip it. The proxy re-scraping redundancy is also significant UX friction.

### Recommended Priority

| Priority | Issue | Effort |
|----------|-------|--------|
| 🔴 P0 | Issue 1 — GoLinkFinder concurrency + host filtering | Medium |
| 🟡 P1 | Issue 3 — Proxy pool reuse across phases | Medium |
| 🟡 P1 | Issue 7 — defer leak in loop | Trivial |
| 🟢 P2 | Issue 2 — Scheme mismatch fix | Small |
| 🟢 P2 | Issue 4 — Pre-flight wordlist check | Small |
| 🟢 P2 | Issue 6 — Parameterized URL extraction fallback | Medium |
| ⚪ P3 | Issue 5 — Arjun upstream workaround | Small |

**Which issues would you like me to fix?**
