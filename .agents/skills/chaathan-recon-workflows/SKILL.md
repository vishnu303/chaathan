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
- Each step lives in a dedicated file such as `dns.go`, `probing.go`, `vuln.go`, `xss.go`, or `crawl.go`.

Company flow mirrors the same pattern in `pkg/company_flow/flow.go`, but is simpler and step-driven.

## When editing steps

1. Confirm which artifact files the step reads and writes.
2. Check which later steps depend on those files.
3. Check whether the database, report generation, exports, or notifications consume the new data.
4. Preserve cancellation, skip, and resume behavior.

## Invariants to preserve

- Step failures should generally log and continue unless the design explicitly treats them as fatal.
- Skip flags must remain consistent between CLI flags, `RunConfig`, `Ctx`, and step execution.
- Output filenames should stay stable unless you update all downstream consumers.
- Resume behavior must not rerun completed work unnecessarily or leave partial state ambiguous.
- Scan summaries should still reflect completed/failed/skipped behavior correctly.
- Long-running tools should respect context cancellation and existing runner patterns.

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

## Avoid

- Do not silently rename result files.
- Do not add new scan-state coupling across unrelated steps unless necessary.
- Do not let a convenience refactor obscure the sequence of security tools in the workflow.
