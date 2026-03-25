# GF Pattern Upgrade & JS Secret Scan

Replaces the hand-rolled inline gf pattern blobs with the upstream
coffinxp/GFpattren pack, upgrades Step 18 URL filtering to use only
Tier 1 vuln-URL patterns, and inserts a brand-new **Step 16 — JS Secret Scan**
that downloads JS files via httpx and runs JS/secret gf patterns on their content.

> [!IMPORTANT]
> Step numbering shifts: old Steps 16–20 become 17–21.
> Only the **log labels** change — state keys are string-based and untouched.
> Resume behavior is fully preserved.

> [!IMPORTANT]
> **Rate-limiting strategy**: the JS download step uses a capped URL list
> (default max 200 JS files), low concurrency (10 threads), and a 5 s timeout
> per request — all tunable via config. This keeps the IP footprint minimal.

---

## Proposed Changes

---

### Part A — Setup: Replace inline patterns with git clone

#### [MODIFY] [gf_patterns.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/setup/gf_patterns.go)

Replace the ~90-line hand-rolled JSON map with a lean `git clone` flow:

1. Check `git` is available (`exec.LookPath("git")`).
2. Clone `https://github.com/coffinxp/GFpattren` into a temp dir
   (`os.MkdirTemp`).
3. `os.ReadDir` the clone and copy every `*.json` file into `~/.gf/`.
   - Skip files that already exist in `~/.gf/` (idempotent / no overwrite by default).
4. `os.RemoveAll` the temp clone dir.
5. Report `ItemOK` with count of newly installed patterns;
   `ItemInfo` if all already present; `ItemFail` on hard errors.

**No more inline pattern blobs — upstream is the single source of truth.**

---

### Part B — Step 18: Dynamic Tier 1 URL filtering (no fallback)

#### [MODIFY] [helpers.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/helpers.go)

**[collectGFTargetURLs](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/helpers.go#268-293)** — replace hardcoded 8-name slice:

```go
// OLD — hardcoded list
patterns := []string{"ssrf", "redirect", "lfi", "sqli", "xss", "rce", "idor", "debug_logic"}

// NEW — Tier 1 allowlist, intersected with what is actually in ~/.gf/
tier1 := map[string]bool{
    "xss": true, "sqli": true, "sqli-error": true,
    "lfi": true, "ssrf": true, "redirect": true,
    "rce": true, "rce-2": true, "idor": true,
    "debug_logic": true, "debug-pages": true, "ssti": true,
    "cors": true, "interestingparams": true,
    "interestingEXT": true, "endpoints": true,
    "s3-buckets": true, "img-traversal": true,
    "jwt": true, "http-auth": true,
}
// read ~/.gf/*.json → only run patterns present in both tier1 AND ~/.gf/
```

**[isGFUsable](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/helpers.go#298-317)** — unchanged (still checks binary + non-empty `~/.gf/`).

#### [MODIFY] [vulnerability_scanning.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/vulnerability_scanning.go)

Step 18 ([stepVulnScanningURLs](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/vulnerability_scanning.go#75-134)):

- **Remove** [collectHighValueURLsFromFile](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/helpers.go#237-267) fallback entirely.
- **Remove** `NucleiFallback` file merge from `MergeAndDeduplicate`.
- **Remove** `NucleiFallback` from [Files](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#75-110) (or leave field but stop writing it).
- If `gfCount == 0` → log "gf found no matches; skipping Nuclei URL scan" and skip nuclei.
- Update step label comments: `Step 18` (was `Step 18`, label stays — see renumbering note below).
- Update log strings: `"gf + fallback high-value paths"` → `"gf-matched URLs"`.

---

### Part C — New Step 16: JS Secret Scan

#### [MODIFY] [tools.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go)

Add one new method **`RunHttpxFetchJS`**:

```go
// RunHttpxFetchJS downloads JS file content from a list of URLs.
// Responses are stored in downloadDir (one file per URL via httpx -sr -srd).
// Uses low concurrency and a conservative timeout to avoid IP rate-limiting.
func (t *ToolBox) RunHttpxFetchJS(ctx context.Context, urlsFile, downloadDir string) error {
    threads := 10           // low — avoids triggering WAF/rate-limit
    timeout := 5            // seconds per request
    if t.Config != nil && t.Config.Httpx.Threads > 0 {
        threads = t.Config.Httpx.Threads / 5  // cap at 1/5 of normal httpx threads
        if threads < 5 { threads = 5 }
        if threads > 15 { threads = 15 }      // hard ceiling
    }
    args := []string{
        "-l", urlsFile,
        "-sr",                        // store response body
        "-srd", downloadDir,          // store response directory
        "-threads", strconv.Itoa(threads),
        "-timeout", strconv.Itoa(timeout),
        "-silent",
        "-no-fallback",
    }
    _, err := t.Runner.Run(ctx, "httpx", args)
    return err
}
```

**Rate-limiting rationale**: 1/5 of normal httpx threads (default = 50 → 10 here),
5 s timeout, `-silent` suppresses noise. This keeps JS fetching polite without
needing a separate tool.

#### [MODIFY] [flow.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go)

**[Files](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#75-110) struct** — add new fields:

```go
JSURLsFile       string   // js URLs filtered from all_urls_live.txt
JSDownloadsDir   string   // dir where httpx -srd stores JS bodies
JSCombinedFile   string   // concatenation of all downloaded JS bodies
GFJSMatches      string   // gf JS-pattern matches
GFSecretsMatches string   // gf secret-pattern matches
GFSecretsFinal   string   // merged findings → final_files/
```

**[newFiles](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#111-160)** — assign paths:

```go
JSURLsFile:       j("js_urls.txt"),
JSDownloadsDir:   j("js_downloads"),        // intermediate dir
JSCombinedFile:   j("js_combined.txt"),
GFJSMatches:      j("gf_js_matches.txt"),
GFSecretsMatches: j("gf_secrets_matches.txt"),
GFSecretsFinal:   jf("gf_secrets_findings.txt"),  // → final_files/
```

**[Run](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#226-489) function** — insert after [stepURLConsolidation](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/content_discovery.go#268-324), before [stepDirFuzzing](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/content_discovery.go#329-364):

```go
if stepJSSecretScan(c) {
    finalizeScan(c, "cancelled")
    return nil
}
```

#### [MODIFY] [content_discovery.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/content_discovery.go)

Add **`stepJSSecretScan`** (new Step 16, ffuf becomes Step 17):

```
Step 16: JS Secret Scan (gf JS + Secrets)
```

Full logic:

1. **Resume guard**: [IsStepCompleted("js_secret_scan")](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/scan/scan.go#188-197).
2. **Filter JS URLs** from `all_urls_live.txt`:
   - Collect lines ending in `.js` (case-insensitive, strip query strings for check).
   - Cap at **200 URLs** (configurable in a const `maxJSDownloads = 200`) to avoid
     excessive HTTP traffic and rate-limiting.
   - Write to `JSURLsFile`.
   - If 0 JS URLs → log and mark complete, return.
3. **Download JS content** via `c.Tb.RunHttpxFetchJS(ctx, JSURLsFile, JSDownloadsDir)`.
   - `os.MkdirAll(JSDownloadsDir, 0755)` before the call.
   - On error → log warning, proceed to concatenation anyway in case partial files exist.
4. **Concatenate** all files in `JSDownloadsDir` into `JSCombinedFile`.
   - Walk dir, append each file's content with a `\n` separator.
   - If combined file is empty → log "no JS content retrieved" and mark complete, return.
5. **Run gf JS patterns** (against `JSCombinedFile`):
   - JS/code allowlist:
     `js-sinks`, `js-interesting`, `domxss`, `execs`,
     `php-sinks`, `php-sources`, `php-codeexec`, `php-commandexec`
   - Only run patterns actually installed in `~/.gf/` (intersect with `ReadDir`).
   - Write per-pattern tmp files → merge to `GFJSMatches`.
6. **Run gf secret patterns** (against `JSCombinedFile`):
   - Secrets allowlist:
     `api-keys`, `aws-keys`, `aws-secret-key`, `aws-s3_secrets`,
     `firebase`, `github`, `jwt`, `secrets`, `truffle`,
     `slack-token`, `twilio-key`, `stripe-keys_secrets`, `crypto`
   - Same dynamic intersection approach.
   - Write per-pattern tmp files → merge to `GFSecretsMatches`.
7. **Merge** both match files → `GFSecretsFinal` (in `final_files/`).
8. Log count of total findings. Mark step complete.

**Key rate-limiting / safety decisions in this step:**
- Cap: max 200 JS URLs (avoids massive download bursts).
- httpx: ≤15 threads, 5 s timeout, `-silent`.
- `gf` runs sequentially, not in parallel (CPU-only, no network impact).
- Downloads go into `intermediate_files/js_downloads/` — not uploaded anywhere.

#### [MODIFY] [scan.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/scan/scan.go)

Insert into `WildcardSteps` after `url_consolidation`, before `dir_fuzzing`:

```go
{Name: "js_secret_scan", Description: "JS File Secret Scan (gf)", Required: false, Tool: "httpx,gf"},
```

This keeps `TotalSteps` accurate for progress tracking and resume.

#### Step label renumbering in [vulnerability_scanning.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/vulnerability_scanning.go) (log strings only)

| Old log label | New log label | State key (unchanged) |
|---|---|---|
| `Step 17:` | `Step 18:` | `vuln_scanning` |
| `Step 18:` | `Step 19:` | `vuln_scanning_urls` |
| `Step 19:` | `Step 20:` | `takeover_detection` |
| `Step 20:` | `Step 21:` | `xss_scanning` |

And [stepDirFuzzing](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/content_discovery.go#329-364) in [content_discovery.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/content_discovery.go):
- `Step 16:` → `Step 17:` (label only, state key `dir_fuzzing` unchanged).

---

## Final Step Map

| Step | Phase | Name | State key |
|---|---|---|---|
| 1–4 | Asset Discovery | (unchanged) | — |
| 5–9 | Validation | (unchanged) | — |
| 10 | Content | Historical URL Discovery | `url_discovery` |
| 11 | Content | Web Crawling | `web_crawling` |
| 12 | Content | JavaScript Analysis (LinkFinder) | `js_analysis` |
| 13 | Content | JavaScript Subdomain Extraction | `js_subdomain_discovery` |
| 14 | Content | HTTP Parameter Discovery (Arjun) | `param_discovery` |
| 15 | Content | URL Consolidation & Live Check | `url_consolidation` |
| **16 (new)** | **Content** | **JS Secret Scan (gf JS + Secrets)** | **`js_secret_scan`** |
| 17 | Content | Directory Fuzzing (ffuf) | `dir_fuzzing` |
| 18 | Vuln | Nuclei Infra | `vuln_scanning` |
| 19 | Vuln | Nuclei URLs (gf Tier 1) | `vuln_scanning_urls` |
| 20 | Vuln | Subdomain Takeover (Subjack) | `takeover_detection` |
| 21 | Vuln | XSS Scanning (Dalfox) | `xss_scanning` |

---

## Verification Plan

### Automated

No existing test files found in the repo. Run these standard checks:

```bash
# From: /media/vishnu/Local Disk/Project Files/chaathan-flow
go vet ./...
go build -buildvcs=false -o chaathan .
go test ./...
```

All three must pass with zero errors.

### CLI smoke checks (after build)

```bash
# 1. Verify help text still works
./chaathan wildcard --help

# 2. Verify setup help (gf section)
./chaathan setup --help

# 3. Verify tools check still lists gf
./chaathan tools check

# 4. Verify step count is now 21
./chaathan scans list   # (after a scan, check TotalSteps = 21)
```

### Manual setup verification

```bash
# Run setup and confirm gf patterns install from GitHub
./chaathan setup

# After setup, confirm ~/.gf/ has coffinxp patterns including js-sinks.json
ls ~/.gf/ | grep -E "js-sinks|api-keys|ssrf|xss"
```

### Manual workflow verification

Run a scan against a safe test target (e.g. `testphp.vulnweb.com`) with
skip flags to reach Step 16 quickly:

```bash
./chaathan wildcard -d testphp.vulnweb.com \
  --skip-amass --skip-shuffledns --skip-tlsx \
  --skip-naabu --skip-arjun --skip-subdomainizer
```

Confirm:
- Step 16 log appears: `Step 16: JS Secret Scan`
- `intermediate_files/js_urls.txt` is created
- `intermediate_files/js_downloads/` directory is created (may be empty on dry target)
- `final_files/gf_secrets_findings.txt` is created (may be empty)
- Step 17 ([ffuf](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go#149-155)) and Step 19 (`Nuclei URLs`) still run correctly
- No fallback URL filter message appears in Step 19
