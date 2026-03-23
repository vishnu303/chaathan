# Chaathan Architecture Principles

Use this playbook for structural decisions or when a task risks crossing package boundaries.

## Core principles

### Thin CLI, thick packages

- `cli/` should parse args, expose flags, and call package entrypoints.
- Business logic, scan orchestration, persistence, and report generation belong in `pkg/`.

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

### Persisted data is a product interface

Database models, result files, and JSON output feed queries, ROI ranking, reports, exports, and scan history. If a data shape changes, inspect all readers.

### External tools remain external

Chaathan is an orchestrator around third-party recon utilities. Prefer clear setup paths, predictable invocation, and actionable missing-tool errors.

### Fail soft inside scans, fail loud at boundaries

- Within multi-step scans, individual tool failures often should log and continue.
- At command boundaries, unsupported input or broken setup should return explicit errors.

### Stable artifact contracts

Workflow steps communicate through canonical output files and persisted DB rows. Add artifact paths centrally and update downstream readers deliberately.

### Prefer extension over incidental refactor

When making a functional change:

1. extend the existing command
2. extend the existing config or context structs
3. extend the owning workflow, report, database, or setup module

Do not broaden scope into a repo-wide refactor unless the task demands it.
