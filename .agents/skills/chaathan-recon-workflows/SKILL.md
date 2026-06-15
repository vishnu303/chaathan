---
name: chaathan-recon-workflows
description: Use when modifying scan pipeline behavior — wildcard/company workflow steps, output files, scan progression, skip flags, resume, and interactions with reports, database, or notifications.
---

# Chaathan Recon Workflows

## When to use

Activate this skill when the task touches recon pipeline behavior rather than generic CLI plumbing.

## Workflow architecture

### Wildcard flow (`pkg/wildcard_flow/`)

- `RunConfig` — boundary from CLI into workflow code (all CLI options).
  - Includes `SaveLog bool` — when true, mirrors full scan output to `~/.chaathan/logs/<domain>_<scanID>_<timestamp>.log` (plain text, ANSI stripped). File path stored in `Ctx.LogFilePath` and shown in next-steps hints after the scan.
- `Files` — canonical artifact paths for the run (`intermediate_files/` and `final_files/`).
- `Ctx` — shared execution state embedding `RunConfig`: tools, scan state, notifier, paths.
- Each step lives in a phase-aligned file.

### Company flow (`pkg/company_flow/`)

Same pattern, simpler: 3 steps, each in its own file (`asn_discovery.go`, `domain_discovery.go`, `cloud_enum.go`).

## 6-Phase wildcard workflow (23 steps)

```
Phase 0 — Proxy Scraping       (Step 1)      in: domain         out: proxy_pool.txt + mubeng server
Phase 1 — Asset Discovery     (Steps 2–6)   in: domain         out: all_subdomains.txt
Phase 2 — Validation           (Steps 7–11)  in: subdomains     out: live_hosts.txt
Phase 3 — Content Discovery    (Steps 12–18) in: live hosts     out: all_urls_live.txt
Phase 4 — Vulnerability Scan   (Steps 19–22) in: hosts + URLs   out: DB findings
Phase 5 — Fingerprinting       (Step 23)     in: live hosts     out: Tech/WAF JSON
```

### Phase 0 — Proxy Scraping (`proxy_scraping.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 1 | `proxy_scraping` | proxy-scraper-checker + mubeng | `--auto-proxy`; skipped if `--proxy` set |

**How it works:**
1. `proxy-scraper-checker` scrapes 100+ public proxy sources and validates each against `https://<target-domain>` (10-min default timeout).
2. Valid proxies are sorted by speed and written to `proxy_pool.txt`.
3. `mubeng` starts as a background rotating proxy on `127.0.0.1:<random-port>` — every request uses a different exit IP (round-robin/random).
4. `c.Proxy` and `c.Cfg.General.Proxy` are set to the mubeng local address, so all existing `appendProxy()` plumbing picks it up with zero changes to tool wrappers.
5. mubeng auto-removes dead proxies (`--remove-on-error`) and retries with next proxy on failure (`--rotate-on-error`).
6. mubeng is killed in `finalizeScan()` on scan completion or cancellation.

**Failure mode:** Non-fatal — if tools are missing or no proxies found, the scan continues without proxy.

### Phase 1 — Asset Discovery (`asset_discovery.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 2 | `passive_enum` | Subfinder, Assetfinder, Sublist3r (parallel) | — |
| 3 | `active_enum` | Amass | `--skip-amass` |
| 4 | `github_recon` | github-subdomains | needs `--github-token` |
| 5 | `search_engine_recon` | Uncover | `--skip-uncover` |
| 6 | `js_subdomain_discovery` | Hakrawler | `--skip-hakrawler` |

### Phase 2 — Validation (`validation.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 7 | `dns_resolution` | DNSx | consolidation; early-returns on merge failure |
| 8 | `dns_bruteforce` | ShuffleDNS | `--skip-shuffledns` |
| 9 | `http_probing` | Httpx | live host probing; triggers optional `RunOriginIPBypass` if `--origin-bypass` is enabled |
| 10 | `tls_analysis` | tlsx | `--skip-tlsx`; calls `metadata.CollectHostMetadata` after success |
| 11 | `port_scanning` | Naabu | `--skip-naabu` |

### Phase 3 — Content Discovery (`content_discovery.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 12 | `url_discovery` | Waybackurls + GAU (parallel) | **runs here, not Phase 1** |
| 13 | `web_crawling` | Katana + GoSpider (parallel) | `--skip-crawl` |
| 14 | `js_analysis` | LinkFinder | — |
| 15 | `param_discovery` | Arjun | `--skip-arjun` |
| 16 | `url_consolidation` | Httpx | live check + ROI metadata enrichment |
| 17 | `js_secret_scan` | gf + JS download | downloads JS files, runs gf patterns |
| 18 | `dir_fuzzing` | ffuf | needs `--wordlist` |

### Phase 4 — Vulnerability Scanning (`vulnerability_scanning.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 19 | `vuln_scanning` | Nuclei (two passes) | `--skip-nuclei`; Pass A: `-as` automatic scan (tech-targeted CVEs via Wappalyzer), Pass B: misconfig/exposure templates (tech-agnostic) |
| 20 | `vuln_scanning_urls` | Nuclei (DAST) | `--skip-nuclei`; uses `-dast` fuzzing mode with real attack payloads; input scope-filtered + deduped |
| 21 | `takeover_detection` | Nuclei (takeover templates) | `--skip-takeovers`; input CNAME-filtered from DNSx output (falls back to all subs) |
| 22 | `xss_scanning` | Dalfox | `--skip-dalfox`; input scope-filtered, deduped by path, capped at `dalfox.max_urls` (default 500) |

### Phase 5 — Fingerprinting (`fingerprinting.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 23 | `tech_waf_fingerprinting` | Httpx, Nuclei | `--skip-fingerprint`; runs last to avoid early WAF blocks |

### Company flow (3 steps)

| Step | Tool | Skip flag |
|------|------|-----------|
| 1 | Metabigor (ASN) | `--skip-metabigor` |
| 2 | Amass Intel (domains) | `--skip-amass-intel` |
| 3 | Cloud Enum | `--skip-cloud-enum` |

## Critical invariants

### Cancellation contract
Every step function must return `c.cancelled()` — never hard-code `return false`. This ensures Ctrl+C propagates through `executeStep` in `flow.go` and triggers `finalizeScan("cancelled")`. Resume early-returns must also return `c.cancelled()`.

### Error vs completion
When a step calls `MarkStepFailed`, do **not** call `MarkStepComplete` afterward — it clears the failure. Either return early after failure, or call `MarkStepComplete` only in the success branch.

### State keys
Resume state uses **string-based** keys (e.g. `"url_discovery"`, `"web_crawling"`), not step numbers. Renumbering logger labels does NOT break resume.

### Step registry alignment
`WildcardSteps` in `pkg/scan/scan.go` must match the step order in `flow.go`. `scan.CreateState` accepts `len(scan.WildcardSteps)` as `totalSteps`.

### Process Group Isolation (PGID)
For external commands that bypass the standard runner framework (such as `RunHakrawler` or `RunGFPattern` in `pkg/tools/tools.go`), always ensure they are group-isolated by setting `Setpgid: true` inside the system attributes (`SysProcAttr`). On context cancellation, skip signals, or timeouts, target the entire process group negative PID (`-Pid`) with `syscall.SIGKILL` to cleanly tear down child processes.

## When editing steps

1. Confirm which artifact files the step reads and writes.
2. Check which later steps depend on those files.
3. Check whether DB, reports, exports, or notifications consume the data.
4. Preserve cancellation, skip, and resume behavior.

## Safe extension patterns

**New workflow option:**
1. Add CLI flag → 2. Add to `RunConfig` → 3. Mirror onto `Ctx` if needed → 4. Apply in step file → 5. Update config/scan metadata if it affects reproducibility.

**New workflow artifact:**
1. Add path to `Files` → 2. Write in one step only → 3. Update downstream readers → 4. Verify report/export/query when file is missing or empty.

## Playbook Extensions (Evasion & Coverage)

### 1. Authenticated Session Fuzzing
*   **CLI Flags**: `--cookie`, `--header` / `-H`, and `--token` (sends standard Bearer tokens).
*   **Propagation Flow**: Configured globally in the context `wf.RunConfig` $\rightarrow$ initialized inside `infra.ToolBox.WithCustomAuth` $\rightarrow$ injected into the arguments of tool execution commands inside `pkg/tools/tools.go` and `pkg/tools/vulnerability_engine.go` (including Httpx, Katana, ffuf, Nuclei, and Dalfox).

### 2. Universal WAF/CDN Origin IP Bypass
*   **Trigger Switch**: `--origin-bypass`. Runs right after Step 8 HTTP probing.
*   **Detection Strategy**: Partitions resolved subdomains into WAF-protected (using a precompiled CIDR database for Cloudflare, Fastly, Incapsula, Sucuri, and AWS CloudFront) vs Direct candidate IPs.
*   **Host-Injection Checks**: Addresses candidate IPs directly, forcing connection negotiation using browser-spoofed TLS configurations, while passing the protected subdomain as a raw TCP `Host` header (`req.Host = hostHeader`).
*   **Storage & Routing**: Confirmed bypasses are saved as **High** severity vulnerabilities in the SQLite DB and dispatched as alert notifications.

## Phase 4 tool methods and output files

| Method | Nuclei Mode | Output File | Used By Step |
|--------|-------------|-------------|------|
| `RunNucleiSmartCVE` | `-as` (automatic scan) | `nuclei_vulns.json` | Step 18 Pass A |
| `RunNucleiMisconfig` | tags: exposure,default-login,misconfig,unauth | `nuclei_misconfig.json` | Step 18 Pass B |
| `RunNucleiDAST` | `-dast` (fuzzing) | `nuclei_dast.json` | Step 19 |
| `RunNucleiTakeovers` | tags: takeover | `subjack_out.json` | Step 20 |
| `RunDalfox` | — | `dalfox_xss.jsonl` | Step 21 |

All Nuclei methods include anti-hang flags: `-retries 0`, `-interactsh-disable` (when `disable_oob` config is true), `-stats -stats-interval 30`, `-max-host-error 3`, and `runner.WithTimeout(nuclei.max_timeout_min)`.

### Config fields for Phase 4

| Config path | Type | Default | Effect |
|---|---|---|---|
| `tools.nuclei.disable_oob` | bool | `true` | Disables Interactsh OOB checks (prevents hangs) |
| `tools.nuclei.max_timeout_min` | int | `300` | Hard process timeout per Nuclei run (minutes) |
| `tools.nuclei.dast_aggression` | string | `"low"` | DAST fuzzing payload count (low/medium/high) |
| `tools.dalfox.max_urls` | int | `500` | Cap parameterized URLs fed to Dalfox |
| `tools.dalfox.skip_third_party` | bool | `true` | Filter 3rd-party domains from Dalfox/DAST input |
| `general.ua_rotation` | bool | `true` | Rotate real browser UAs (default on to bypass WAFs) |

### Input filtering helpers (in `helpers.go`)

- `filterCNAMESubdomains` — reads DNSx JSONL, extracts CNAME-bearing subs for takeover scanning
- `collectScopedURLs` — filters URLs by scope, static extension, junk domains, deduplicates by path, caps at limit using $O(1)$-memory stream-filtering
- `collectScopedParamURLs` — wraps `collectScopedURLs` with Dalfox config cap

### High-Performance URL Stream Pipeline ($O(1)$ Memory)

High-volume subdomain crawls generate $100,000+$ targets. To avoid VPS RAM exhaustion:
1. **Line-by-Line Streaming**: Read target files line-by-line via `bufio.Scanner` to avoid loading massive arrays into memory.
2. **Endpoint Deduplication**: Deduplicate URLs by their path key (`pathKey()`), storing only one high-ROI urlItem variant per unique path.
3. **Bounded Min-Heap Priority Queue**: When capping targets (`maxURLs > 0`), maintain a strict $O(N)$ min-heap using the `"container/heap"` package. Evict low-priority URLs dynamically when higher-scoring endpoints are crawled.
4. **Customizable Heuristics**: Junk domains, static extensions, high-value markers, and interesting parameters are dynamically loaded from `config.Cfg.Heuristics` with embedded backwards-compatible fallback lists.

## Validation

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

If developing on Windows, use WSL with the installed Go path for all commands:
```bash
wsl /usr/local/go/bin/go test ./...
wsl /usr/local/go/bin/go vet ./...
wsl /usr/local/go/bin/go build -buildvcs=false -o chaathan .
```

Then inspect for: compile errors from struct changes, missing skip flag propagation, stale step counts, artifact filename mismatches, downstream readers assuming non-empty files.

## Avoid

- Do not rename result files without updating all downstream consumers.
- Do not add cross-step coupling between unrelated steps.
- Do not move `url_discovery` back to Phase 1 — Wayback/GAU must run after live hosts are known.
- Do not return hard-coded `false` from step functions.
- Do not call `MarkStepComplete` after `MarkStepFailed` in the same error path.
