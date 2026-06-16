# Implementation Plan: Fix WAF Blindspot in Proxy Checking

This plan outlines how to address the proxy validation WAF blindspot. Currently, `mubeng --check` only verifies if a proxy is alive by checking against `https://ipinfo.io/json`. It does not verify if the proxy is blocked by the target domain's Web Application Firewall (WAF) or CDN (e.g., Cloudflare, Akamai).

We will introduce a secondary, lightweight validation step that checks the pre-filtered proxies directly against the target domain before saving them to the proxy pool.

---

## User Review Required

> [!IMPORTANT]
> **Checking Concurrency and Load**:
> The secondary check will send a single, concurrent request to the target domain through each pre-filtered proxy. If there are 100 live proxies, we will send ~100 requests. We will throttle this concurrency (e.g., max 20 concurrent checks at a time) to avoid triggering rate-limiting or security alerts on the target domain.

---

## Proposed Changes

We will modify `pkg/proxy_scraping/scraping.go` to implement a custom, concurrent checker function.

### [Component: Proxy Scraping]

#### [MODIFY] [scraping.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/proxy_scraping/scraping.go)
* Add a `filterByTargetDomain` helper function.
* Execute a baseline check directly to the target domain without a proxy to establish a reference status code.
* Use a worker pool with bounded concurrency (e.g., 20) and a short timeout (5 seconds) to test each proxy.
* A proxy will be considered **valid** if:
  1. It can connect to `https://<target-domain>`.
  2. The response status code matches the baseline or is `< 400`.
  3. The response headers and body do not contain signatures of WAF block pages (e.g., `cf-ray`, `cloudflare`, `Access Denied`, `CAPTCHA`).
* Call this helper in `RunHarvest` right after `mubeng` completes its check.

---

## Verification Plan

### Automated Tests
We will verify that the project still compiles and tests pass:
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

### Manual Verification
* Run a domain recon scan with `--auto-proxy` on a target and observe the output to see if target validation runs and filters out dead/blocked proxies:
  ```bash
  wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan wildcard run target.com --auto-proxy"
  ```
