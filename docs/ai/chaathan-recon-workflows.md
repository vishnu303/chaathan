# Chaathan Recon Workflows Playbook

Use this playbook when modifying wildcard or company scan behavior.

## Workflow architecture

Wildcard flow is centered in `pkg/wildcard_flow/flow.go`.

- `RunConfig` is the boundary from CLI into workflow code.
- `Files` defines canonical artifact paths for a run.
- `Ctx` carries shared execution state, tool access, flags, and paths.
- Each step lives in a dedicated file such as `dns.go`, `probing.go`, `vuln.go`, `xss.go`, or `crawl.go`.

Company flow mirrors the same pattern in `pkg/company_flow/flow.go`.

## When editing steps

1. Confirm which artifact files the step reads and writes.
2. Check which later steps depend on those files.
3. Check whether the database, report generation, exports, or notifications consume the new data.
4. Preserve cancellation, skip, and resume behavior.

## Invariants

- Step failures should usually log and continue unless explicitly designed as fatal.
- Skip flags must stay consistent between CLI flags, `RunConfig`, `Ctx`, and step execution.
- Output filenames should stay stable unless all downstream consumers are updated.
- Resume behavior must not rerun completed work unnecessarily or leave partial state ambiguous.
- Long-running tools should respect context cancellation and existing runner patterns.

## Validation

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

Then inspect for:

- missing skip flag propagation
- stale step counts or help text
- artifact filename mismatches
- downstream readers assuming non-empty files
