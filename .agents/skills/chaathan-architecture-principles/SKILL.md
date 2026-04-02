---
name: chaathan-architecture-principles
description: Use when making structural decisions in the Chaathan repository or when a task risks crossing package boundaries. Codifies ownership boundaries, extension patterns, and architectural invariants.
---

# Chaathan Architecture Principles

## When to use

Activate this skill when deciding where code should live, how to introduce new behavior, or whether a change fits the project's structure.

## Package ownership map

| Concern | Owner | Never put this in |
|---------|-------|--------------------|
| Command UX, flags, arg parsing | `cli/` | workflow logic, SQL |
| Wildcard scan orchestration | `pkg/wildcard_flow/` | `cli/`, other workflows |
| Company scan orchestration | `pkg/company_flow/` | `cli/`, other workflows |
| Signal handling, infra bootstrap | `pkg/orchestrate/` | `cli/`, workflow files |
| Tool execution, retry, docker | `pkg/runner/` | `cli/`, setup |
| Tool registry, wrappers | `pkg/tools/` | `cli/` |
| Persistence, queries, ROI | `pkg/database/` | `cli/`, report templates |
| Report assembly, format export | `pkg/report/` | `cli/`, database |
| Scan state, resume, step defs | `pkg/scan/` | `cli/` |
| External tool installation | `pkg/setup/` | runtime scan code |
| YAML config loading | `pkg/config/` | `cli/` beyond flag wiring |
| Host metadata (CSP, headers) | `pkg/metadata/` | report, CLI |
| Scope filtering | `pkg/scope/` | database, CLI |
| Notifications | `pkg/notify/` | `cli/` |
| Terminal output, colors | `pkg/logger/` | — |
| Spinners, progress bars | `pkg/progress/` | — |
| `~/.chaathan` directory paths | `pkg/paths/` | hardcoded paths elsewhere |
| File I/O, parsers, helpers | `pkg/utils/` | — |

## Core principles

### Thin CLI, thick packages
`cli/` parses args, exposes flags, and calls package entrypoints. No business logic in Cobra handlers.

### Workflows own workflow state
Wildcard and company scans each have a `RunConfig` and `Ctx`. Add fields to those structs instead of threading long parameter lists through step functions.

### Persisted data is a product interface
DB models, result files, and JSON output feed queries, ROI ranking, reports, exports, scan diffing, and notifications. If a data shape changes, inspect all readers.

### External tools remain external
Chaathan orchestrates third-party recon utilities. Prefer clear setup/install paths, predictable invocation, and actionable error messages. Never silently replace external-tool behavior with in-process logic.

### Fail soft in scans, fail loud at boundaries
Within multi-step scans, individual tool failures log and continue. At command boundaries, bad input or broken setup returns explicit errors.

### Stable artifact contracts
Workflow steps communicate through canonical output files and DB rows. Add artifact paths centrally in `Files`. Write artifacts in one step. Update downstream readers deliberately.

## Decision checklist

Before editing, ask:
1. Which package owns this behavior today?
2. Will this change affect stored artifacts or JSON output?
3. Does this need to be available to reports, queries, or resume logic?
4. Is the new code introducing cross-package duplication?
5. Can the same goal be met by extending existing structs and helpers?

## Preferred extension patterns

- **New CLI option:** `cli/` flag → `RunConfig` field → workflow/report/database owner
- **New scan artifact:** `Files` path → producing step → downstream DB/report/query consumers
- **New ranking signal:** persisted metadata → ROI computation → query/report output
- **New setup dependency:** `pkg/setup/` install/check → `pkg/tools/` invocation → workflow usage

## Wrong-place signals

- SQL appears in `cli/`
- Cobra handlers know file layouts or step internals
- Workflow code formats user-facing tables directly
- Report templates compute business logic
- Setup code owns runtime scan behavior
- One feature requires edits in many packages with no single canonical owner

## Anti-patterns

- Do not use architecture discussions as an excuse for speculative rewrites.
- Do not collapse package boundaries for short-term convenience.
- Do not add abstractions before the repository has a concrete second use for them.
- Do not broaden scope into a repo-wide refactor unless the task demands it.
