---
name: chaathan-recon-workflows
description: Use when modifying Chaathan scan pipeline behavior, including wildcard/company workflow steps, output files, scan progression, skip flags, resume behavior, and interactions with reports, database records, or notifications.
---

# Chaathan Recon Workflows

Use this skill when the task touches recon pipeline behavior rather than generic CLI plumbing.

## Workflow architecture

Wildcard flow is centered in `pkg/wildcard_flow/flow.go`.

- `RunConfig` is the boundary from CLI into workflow code.
- `Files` defines the canonical artifact paths for the run.
- `Ctx` carries shared execution state, tool access, flags, and paths.
- Each step lives in a phase-aligned file: `asset_discovery.go`, `validation.go`, `content_discovery.go`, or `vulnerability_scanning.go`.

Company flow mirrors the same pattern in `pkg/company_flow/flow.go`, but is simpler and step-driven.

## 4-Phase wildcard workflow structure

The 21-step wildcard workflow is organised into 4 explicit phases. Each phase has a clean input and a clean output.

```
PHASE 1 — ASSET DISCOVERY (Steps 1–5)      input: domain         output: all_subdomains.txt
PHASE 2 — VALIDATION (Steps 6–10)          input: subs           output: live_hosts.txt
PHASE 3 — CONTENT DISCOVERY (Steps 11–17)  input: live hosts      output: all_urls_live.txt
PHASE 4 — VULNERABILITY SCANNING (18–21)   input: live hosts+URLs output: DB findings
```

### Phase 1 — Asset Discovery (Steps 1–5)
File: `asset_discovery.go`

| Step | Tool |
|------|------|
| 1 | Subfinder, Assetfinder, Sublist3r (parallel) |
| 2 | Amass (optional) |
| 3 | GitHub subdomain discovery (token required) |
| 4 | Uncover / Shodan / Censys (optional) |
| 5 | SubDomainizer JS subdomain extraction (optional) |

> **Wayback/GAU do NOT run here.** They run in Phase 3 after live hosts are known.

### Phase 2 — Validation (Steps 6–10)
Files: `validation.go`

| Step | Tool | Notes |
|------|------|-------|
| 6 | DNSx | consolidation; early-returns on merge failure |
| 7 | ShuffleDNS | optional |
| 8 | Httpx | live host probing |
| 9 | tlsx | optional; **calls `metadata.CollectHostMetadata` after success** |
| 10 | Naabu | optional |

`CollectHostMetadata` is called in `stepTLSAnalysis` (which runs right after httpx). It is not dead code. The call is in `validation.go` after `stepHTTPProbing` completes.

### Phase 3 — Content Discovery (Steps 11–17)
Files: `content_discovery.go`

| Step | Tool | Notes |
|------|------|-------|
| 11 | Waybackurls + GAU (parallel) | **runs here, not Phase 1** |
| 12 | Katana + GoSpider (parallel) | optional |
| 13 | LinkFinder | |
| 14 | Arjun | optional |
| 15 | URL consolidation + live check | + ROI metadata enrichment |
| 16 | gf JS + Secrets scan | downloads JS files, runs gf patterns |
| 17 | ffuf | requires --wordlist |

### Phase 4 — Vulnerability Scanning (Steps 18–21)
File: `vulnerability_scanning.go`

| Step | Tool |
|------|------|
| 18 | Nuclei (infra) |
| 19 | Nuclei (URLs + gf) |
| 20 | Subjack |
| 21 | Dalfox |

## When editing steps

1. Confirm which artifact files the step reads and writes.
2. Check which later steps depend on those files.
3. Check whether the database, report generation, exports, or notifications consume the new data.
4. Preserve cancellation, skip, and resume behavior.

## Cancellation contract

Every step function must return `c.cancelled()` — never hard-code `return false`. This ensures Ctrl+C propagates through the `executeStep` wrapper in `flow.go` and triggers `finalizeScan("cancelled")`. The resume path (`IsStepCompleted` early returns) must also return `c.cancelled()`, not `false`.

## Error vs completion semantics

When a step calls `MarkStepFailed`, it should **not** unconditionally call `MarkStepComplete` afterward — `MarkStepComplete` clears prior failures from the state (scan.go `MarkStepComplete` filters `FailedSteps`). Either:
- Return early after `MarkStepFailed` (used for fatal sub-step failures like consolidation), or
- Call `MarkStepComplete` only in the success branch.

## Invariants to preserve

- Step failures should generally log and continue unless the design explicitly treats them as fatal.
- Skip flags must remain consistent between CLI flags, `RunConfig`, `Ctx`, and step execution.
- Output filenames should stay stable unless you update all downstream consumers.
- Resume behavior must not rerun completed work unnecessarily or leave partial state ambiguous.
  - State keys are **string-based** (e.g. `"url_discovery"`, `"web_crawling"`), not step numbers.
  - Renumbering logger labels does NOT break resume. Only the log output changes.
- Scan summaries should still reflect completed/failed/skipped behavior correctly.
- Long-running tools should respect context cancellation and existing runner patterns.
- The `WildcardSteps` slice in `pkg/scan/scan.go` must match the execution order in `flow.go`.
- `scan.CreateState` accepts a `totalSteps int` parameter — pass `len(scan.WildcardSteps)` for wildcard scans.

## Files commonly involved together

- `cli/wildcard.go`
- `pkg/wildcard_flow/flow.go`
- `pkg/wildcard_flow/*.go`
- `pkg/scan/scan.go`
- `pkg/database/*.go`
- `pkg/report/report.go`
- `pkg/notify/notify.go`

For company flow changes, replace the wildcard files above with:

- `cli/company.go`
- `pkg/company_flow/*.go`

## Safe extension pattern

For a new workflow option:

1. Add the CLI flag in the owning Cobra command.
2. Add the field to `RunConfig`.
3. Mirror it onto workflow `Ctx` if needed during execution.
4. Apply it in the relevant step file.
5. Update persisted config or scan metadata if the option affects reproducibility.

For a new workflow artifact:

1. Add the canonical path in `Files`.
2. Write the artifact in one step only.
3. Update downstream readers explicitly.
4. Verify report/export/query behavior still works when the file is missing or empty.

## Validation focus

After workflow edits, prefer these checks:

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

Then inspect the affected flow for:

- compile-time breakage from struct field additions
- missing skip flag propagation
- stale step counts or help text
- artifact filename mismatches
- downstream readers assuming non-empty files
- cancellation propagation (every step must return `c.cancelled()`)

## Avoid

- Do not silently rename result files.
- Do not add new scan-state coupling across unrelated steps unless necessary.
- Do not let a convenience refactor obscure the sequence of security tools in the workflow.
- Do not move `stepURLDiscovery` back to Phase 1 — Wayback/GAU must run after live hosts are known.
- Do not hard-return `false` from step functions — always use `c.cancelled()`.
- Do not call `MarkStepComplete` after `MarkStepFailed` in the same error path.
