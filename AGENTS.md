# Chaathan Agent Guide

Chaathan is a Go CLI pentesting orchestration framework.

Use this file as the primary entrypoint for any code agent.

## Repository overview

- `main.go` — starts the Cobra CLI.
- `cli/` — commands, flags, and argument parsing.
- `pkg/wildcard_flow/` — wildcard/domain recon workflow.
- `pkg/company_flow/` — company recon workflow.
- `pkg/database/` — persistence and ROI ranking.
- `pkg/report/` — report generation.
- `pkg/setup/` — external tool installation and checks.
- `pkg/tools/` and `pkg/runner/` — external command execution.
- `pkg/scan/` — scan lifecycle management.
- `pkg/scope/` — scope parsing and filtering.
- `pkg/config/` — configuration loading.
- `pkg/logger/` — structured logging.
- `pkg/notify/` — notifications.
- `pkg/progress/` — progress tracking.
- `pkg/metadata/` — scan metadata.
- `pkg/utils/` — shared utilities.

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

## Agent-specific notes

- Antigravity IDE and Codex agents: deep-dive skills are in `.agents/skills/`.
- Other agents (Cursor, Claude, etc.): read this file and the relevant skill `SKILL.md` directly from `.agents/skills/<skill-name>/SKILL.md`.
- Do not invent a second source of truth — mirror or reference this file for other agent config formats.
