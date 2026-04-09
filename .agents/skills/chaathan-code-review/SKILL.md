---
name: chaathan-code-review
description: Use when reviewing changes in the Chaathan repository. Focuses on behavioral regressions, cross-layer propagation bugs, and orchestration-specific risks.
---

# Chaathan Code Review

## When to use

Activate this skill when reviewing a diff or PR — not when implementing.

## Priority order

Review for breakage in this order:
1. Scan execution and step sequencing
2. CLI compatibility (flags, help text, argument validation)
3. Database persistence and downstream queries
4. Report/export correctness across all formats
5. Setup and tool availability checks
6. Cancellation, resume, and skip semantics
7. Notification delivery

## Review surfaces

| Layer | Watch for |
|-------|-----------|
| `cli/` | Wrong flags, mismatched help text, duplicated logic, poor validation |
| `pkg/wildcard_flow/`, `pkg/company_flow/` | Bad step ordering, broken artifact deps, lost cancel/skip handling |
| `pkg/orchestrate/` | Signal handling regressions, infra bootstrap changes |
| `pkg/database/` | Schema/query mismatches, unstable uniqueness, ranking regressions |
| `pkg/report/` + `cli/query.go` | Stale presentation after data-model changes |
| `pkg/setup/` + `pkg/tools/` | Install/runtime mismatches for external deps |
| `pkg/metadata/` | Missing metadata fields breaking ROI or reports |

## Regression patterns specific to this repo

- CLI flag added but not copied into `RunConfig` or workflow `Ctx`
- Workflow artifact renamed without updating downstream consumers
- DB model changed without schema update or migration-safe fallback
- Report field added in one format but missing from others
- ROI score changed without updating `Reasons`
- Setup installs a tool but `tools check` or runtime still disagrees
- Step counts/help text drift from actual workflow (22 steps, 5 phases)
- Step function returns hard-coded `false` instead of `c.cancelled()`
- `MarkStepComplete` called after `MarkStepFailed` in same error path
- Resume path (`IsStepCompleted` early return) returns `false` instead of `c.cancelled()`
- Notification fields out of sync with scan stats

## Review output style

Lead with concrete findings ordered by severity. For each finding:
- Affected file and line
- What breaks or could regress
- Why it matters in this codebase

Keep summaries brief. If no findings, state that explicitly with residual risks noted.

## Validation cues

**Strong evidence:** `go test ./...`, `go vet ./...`, successful build, direct inspection of affected flow and all downstream readers.

**Weak evidence:** README examples only, reasoning from one layer without checking the rest.

## Avoid

- Do not review this repo as a pure library — most risk is in end-to-end orchestration.
- Do not focus on style unless it affects correctness or maintainability.
- Do not miss propagation bugs across CLI → workflow → DB → report → notification layers.
