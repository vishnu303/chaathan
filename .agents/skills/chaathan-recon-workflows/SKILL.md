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
- `Files` — canonical artifact paths for the run (`intermediate_files/` and `final_files/`).
- `Ctx` — shared execution state embedding `RunConfig`: tools, scan state, notifier, paths.
- Each step lives in a phase-aligned file.

### Company flow (`pkg/company_flow/`)

Same pattern, simpler: 3 steps, each in its own file (`asn_discovery.go`, `domain_discovery.go`, `cloud_enum.go`).

## 4-Phase wildcard workflow (21 steps)

```
Phase 1 — Asset Discovery     (Steps 1–5)   in: domain         out: all_subdomains.txt
Phase 2 — Validation           (Steps 6–10)  in: subdomains     out: live_hosts.txt
Phase 3 — Content Discovery    (Steps 11–17) in: live hosts     out: all_urls_live.txt
Phase 4 — Vulnerability Scan   (Steps 18–21) in: hosts + URLs   out: DB findings
```

### Phase 1 — Asset Discovery (`asset_discovery.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 1 | `passive_enum` | Subfinder, Assetfinder, Sublist3r (parallel) | — |
| 2 | `active_enum` | Amass | `--skip-amass` |
| 3 | `github_recon` | github-subdomains | needs `--github-token` |
| 4 | `search_engine_recon` | Uncover | `--skip-uncover` |
| 5 | `js_subdomain_discovery` | SubDomainizer | `--skip-subdomainizer` |

### Phase 2 — Validation (`validation.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 6 | `dns_resolution` | DNSx | consolidation; early-returns on merge failure |
| 7 | `dns_bruteforce` | ShuffleDNS | `--skip-shuffledns` |
| 8 | `http_probing` | Httpx | live host probing |
| 9 | `tls_analysis` | tlsx | `--skip-tlsx`; calls `metadata.CollectHostMetadata` after success |
| 10 | `port_scanning` | Naabu | `--skip-naabu` |

### Phase 3 — Content Discovery (`content_discovery.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 11 | `url_discovery` | Waybackurls + GAU (parallel) | **runs here, not Phase 1** |
| 12 | `web_crawling` | Katana + GoSpider (parallel) | `--skip-crawl` |
| 13 | `js_analysis` | LinkFinder | — |
| 14 | `param_discovery` | Arjun | `--skip-arjun` |
| 15 | `url_consolidation` | Httpx | live check + ROI metadata enrichment |
| 16 | `js_secret_scan` | gf + JS download | downloads JS files, runs gf patterns |
| 17 | `dir_fuzzing` | ffuf | needs `--wordlist` |

### Phase 4 — Vulnerability Scanning (`vulnerability_scanning.go`)

| Step | Name | Tool(s) | Notes |
|------|------|---------|-------|
| 18 | `vuln_scanning` | Nuclei (infra) | `--skip-nuclei` |
| 19 | `vuln_scanning_urls` | Nuclei (URLs + gf) | `--skip-nuclei` |
| 20 | `takeover_detection` | Subjack | `--skip-subjack` |
| 21 | `xss_scanning` | Dalfox | `--skip-dalfox` |

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

## Validation

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

Then inspect for: compile errors from struct changes, missing skip flag propagation, stale step counts, artifact filename mismatches, downstream readers assuming non-empty files.

## Avoid

- Do not rename result files without updating all downstream consumers.
- Do not add cross-step coupling between unrelated steps.
- Do not move `url_discovery` back to Phase 1 — Wayback/GAU must run after live hosts are known.
- Do not return hard-coded `false` from step functions.
- Do not call `MarkStepComplete` after `MarkStepFailed` in the same error path.
