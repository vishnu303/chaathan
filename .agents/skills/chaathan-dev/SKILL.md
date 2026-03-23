---
name: chaathan-dev
description: Use when making code changes in the Chaathan repository, especially for CLI commands, Go package wiring, build/test flows, or repository-specific development tasks. This skill helps navigate command entrypoints, workflow boundaries, and safe validation for this project.
---

# Chaathan Dev

Use this skill for normal development work in this repository.

## Repository shape

- `main.go` starts the Cobra CLI.
- `cli/` contains command definitions and argument parsing.
- `pkg/wildcard_flow/` contains the 20+ step domain recon workflow.
- `pkg/company_flow/` contains the 3-step company recon workflow.
- `pkg/database/` stores scan metadata and query/report support data.
- `pkg/report/` formats reports.
- `pkg/setup/` installs and verifies external tools.
- `pkg/tools/` and `pkg/runner/` abstract tool execution.

Keep CLI flag parsing in `cli/`. Put scan logic in `pkg/..._flow/` packages, not in Cobra handlers.

## Default working pattern

1. Read the relevant Cobra command in `cli/` first.
2. Follow the call into the owning package in `pkg/`.
3. Change the narrowest layer that actually owns the behavior.
4. Verify with targeted Go commands before broadening scope.

## Project-specific rules

- Prefer extending existing workflow context structs (`RunConfig`, `Ctx`, `Files`) instead of threading long parameter lists through step functions.
- Preserve the current separation between:
  - CLI parsing in `cli/`
  - workflow orchestration in `pkg/wildcard_flow/` or `pkg/company_flow/`
  - storage/reporting in `pkg/database/` and `pkg/report/`
- Treat external security tools as host dependencies. Do not replace them with in-process implementations unless explicitly asked.
- Be careful with user-visible counts and labels. The README and CLI help currently mention both 20-step and 21-step wildcard wording in different places; avoid making that inconsistency worse unless you are fixing it deliberately.
- Database updates and generated files are part of the product behavior. If a scan step changes outputs, check downstream query/report/export code.

## Validation

Start with the smallest relevant checks:

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

Use targeted execution when helpful:

```bash
go test ./pkg/...
go test ./cli/...
```

If you change CLI wiring, also inspect:

- `chaathan --help`
- the affected subcommand help text
- README command examples if behavior changed

## Common edit routes

- New flag or command behavior:
  Read the matching file in `cli/`, then update the owning package in `pkg/`.
- Wildcard scan change:
  Start in `cli/wildcard.go`, then `pkg/wildcard_flow/flow.go`, then the relevant step file.
- Company scan change:
  Start in `cli/company.go`, then `pkg/company_flow/flow.go`.
- Query/report/export change:
  Inspect `cli/query.go`, `cli/report.go`, `cli/export.go` plus `pkg/database/`, `pkg/report/`, and `pkg/utils/export.go`.
- Tool installation/setup change:
  Inspect `cli/setup.go`, `pkg/setup/`, and `pkg/tools/tools.go`.

## Avoid

- Do not hardcode machine-specific paths except where the project already intentionally uses them, such as install defaults or user home directories.
- Do not introduce destructive cleanup of user scan data unless the task explicitly concerns deletion behavior.
- Do not move business logic into README examples or shell scripts when it belongs in Go code.
