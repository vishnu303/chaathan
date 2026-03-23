# Chaathan Agent Guide

This repository contains Codex-specific skills under `.codex/skills/`, but the project guidance below is written to be usable by any code agent that can read repository files.

Use this file as the primary entrypoint for non-Codex agents.

## Repository overview

Chaathan is a Go CLI pentesting orchestration framework.

- `main.go` starts the Cobra CLI.
- `cli/` owns commands, flags, and argument parsing.
- `pkg/wildcard_flow/` owns the wildcard/domain recon workflow.
- `pkg/company_flow/` owns the company recon workflow.
- `pkg/database/` owns persistence and ROI ranking.
- `pkg/report/` owns report generation.
- `pkg/setup/` owns external tool installation and checks.
- `pkg/tools/` and `pkg/runner/` own external command execution.

## Core architecture rules

- Keep CLI handlers thin. Business logic belongs in `pkg/`.
- Keep scan orchestration in workflow packages, not in Cobra commands.
- Keep SQL, persistence, and ROI logic in `pkg/database/`.
- Keep report rendering in `pkg/report/`.
- Keep setup and installation logic in `pkg/setup/`.
- Treat persisted DB rows, output artifacts, and JSON output as stable product interfaces.
- Prefer extending existing structs like `RunConfig`, `Ctx`, and `Files` instead of creating ad hoc parameter chains.

## Validation baseline

Use the smallest relevant checks first:

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

If a change affects CLI behavior, also inspect the relevant help text.

## Cross-agent playbooks

Read the playbook that matches the task:

- [Development](docs/ai/chaathan-dev.md)
- [Recon Workflows](docs/ai/chaathan-recon-workflows.md)
- [Tooling And Setup](docs/ai/chaathan-tooling-setup.md)
- [Reporting And Query](docs/ai/chaathan-reporting-query.md)
- [Code Review](docs/ai/chaathan-code-review.md)
- [Architecture Principles](docs/ai/chaathan-architecture-principles.md)

## Agent-specific notes

- Codex can use `.codex/skills/`.
- Any agent can read `AGENTS.md` and `docs/ai/*.md`.
- If an agent supports repository instruction files with a different name, mirror or reference this file rather than inventing a second conflicting source of truth.
