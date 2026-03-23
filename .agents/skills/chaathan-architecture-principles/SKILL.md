---
name: chaathan-architecture-principles
description: Use when making structural decisions in the Chaathan repository or when a task risks crossing package boundaries. This skill codifies the project’s architecture principles, ownership boundaries, and preferred extension paths.
---

# Chaathan Architecture Principles

Use this skill when deciding where code should live, how new behavior should be introduced, or whether a refactor fits the repository’s existing structure.

## Core principles

### Thin CLI, thick packages

- `cli/` should parse args, expose flags, and call package entrypoints.
- Business logic, scan orchestration, persistence, and report generation belong in `pkg/`.

Do not let Cobra handlers accumulate workflow logic.

### Workflows own workflow state

- Wildcard and company scans each have a dedicated `RunConfig` and `Ctx`.
- Shared execution state should be added to those structs rather than passed through long ad hoc argument lists.

### One canonical owner per concern

- command UX: `cli/`
- scan orchestration: `pkg/wildcard_flow/`, `pkg/company_flow/`
- tool execution and wrappers: `pkg/tools/`, `pkg/runner/`
- persistence and ranking: `pkg/database/`
- reports: `pkg/report/`
- external tool setup: `pkg/setup/`
- small reusable helpers: `pkg/utils/`

When adding behavior, find the canonical owner and extend it there.

### Persisted data is a product interface

Database models, result files, and JSON output are not incidental internals. They feed:

- query commands
- ROI ranking
- reports
- exports
- scan history and diffing

If a data shape changes, inspect all readers.

### External tools remain external

Chaathan is an orchestrator around third-party recon utilities. Prefer:

- clear setup/install paths
- predictable runtime invocation
- actionable missing-tool errors

Do not silently replace external-tool behavior with partial in-process logic unless explicitly asked.

### Fail soft inside scans, fail loud at boundaries

- Within multi-step scans, individual tool failures often should log and continue.
- At command boundaries, unsupported input, invalid output formats, or broken setup should return explicit errors.

Keep this distinction clear.

### Stable artifact contracts

Workflow steps communicate through canonical output files and persisted DB rows.

- Add artifact paths centrally.
- Write artifacts in a single clear owner.
- Update downstream readers deliberately.

Avoid hidden coupling through scattered file-name assumptions.

### Prefer extension over incidental refactor

When making a functional change:

1. extend the existing command
2. extend the existing config or context structs
3. extend the owning workflow/report/database module

Do not broaden scope into a repository-wide refactor unless the task demands it.

## Architectural decision checks

Before editing, ask:

1. Which package owns this behavior today?
2. Will this change affect stored artifacts or JSON output?
3. Does this need to be available to reports, queries, or resume logic?
4. Is the new code introducing cross-package duplication?
5. Can the same goal be met by extending existing structs and helpers?

## Signals that a change is going in the wrong place

- SQL appears in `cli/`
- Cobra commands begin to know file layouts or workflow step internals
- workflow code starts formatting user-facing tables directly
- report templates start computing business logic
- setup code starts owning runtime scan behavior
- one feature requires edits in many packages because no single owner was chosen

## Preferred implementation patterns

- New CLI option:
  `cli/` flag -> `RunConfig` -> workflow/report/database owner
- New scan artifact:
  canonical file path -> producing step -> downstream DB/report/query consumers
- New ranking signal:
  persisted metadata -> ROI computation -> query/report output
- New setup dependency:
  `pkg/setup/` install/check -> `pkg/tools/` invocation -> workflow usage

## Avoid

- Do not use architecture discussions as an excuse for speculative rewrites.
- Do not collapse package boundaries for short-term convenience.
- Do not add abstractions before the repository has a concrete second use for them.
