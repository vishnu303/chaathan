---
name: chaathan-code-review
description: Use when reviewing changes in the Chaathan repository. Focus on behavioral regressions, workflow breakage, database/report/query inconsistencies, setup risks, and missing validation for this CLI pentesting framework.
---

# Chaathan Code Review

Use this skill when the user asks for a review rather than an implementation.

## Review priorities

Prioritize findings that could break:

- scan execution or step sequencing
- CLI compatibility or help/flag behavior
- database persistence and downstream queries
- report/export correctness
- setup/tool availability checks
- cancellation, resume, or skip semantics

This repository is orchestration-heavy. Small-looking changes often break behavior across multiple layers.

## Main review surfaces

- `cli/`: wrong flags, mismatched help text, duplicated logic, poor argument validation
- `pkg/wildcard_flow/` and `pkg/company_flow/`: bad step ordering, broken artifact dependencies, lost cancellation/skip handling
- `pkg/database/`: schema/query mismatches, unstable uniqueness assumptions, ranking regressions
- `pkg/report/` and `cli/query.go`: stale presentation after data-model changes
- `pkg/setup/` and `pkg/tools/`: install/runtime mismatches for external dependencies

## What to look for first

1. Does the change break an existing command path?
2. Does it add a field or artifact without updating all readers?
3. Does it change output semantics without updating JSON/human-readable modes consistently?
4. Does it depend on an external tool or file path that may not exist?
5. Does it widen fatal failure behavior in a workflow that used to log and continue?

## Repo-specific regression patterns

- CLI flag added but not copied into `RunConfig` or workflow `Ctx`
- workflow artifact renamed without updating downstream consumers
- database model changed without schema update or migration-safe fallback
- report field added in one format but missing from others
- ROI score changed without updating `Reasons`
- setup logic installs a tool but `tools check` or runtime invocation still disagrees
- user-facing step counts/help text drift from actual workflow implementation

## Review output style

Lead with concrete findings ordered by severity.

For each finding include:

- affected file and line
- what breaks or could regress
- why it matters in this codebase
- the missing validation if relevant

Keep summaries brief. If there are no findings, state that explicitly and mention residual risks or untested surfaces.

## Useful validation cues

Strong evidence for confidence:

- `go test ./...`
- `go vet ./...`
- successful build
- direct inspection of affected command path and downstream readers

Weak evidence:

- README examples only
- reasoning from one layer without checking the rest of the flow

## Avoid

- Do not review this repo as if it were a pure library. Most risk is in end-to-end orchestration.
- Do not focus mainly on style unless it affects correctness or maintainability materially.
- Do not miss propagation bugs across CLI, workflow, DB, report, and setup layers.
