# Chaathan Development Playbook

Use this playbook for normal code changes in this repository.

## Repository shape

- `main.go` starts the Cobra CLI.
- `cli/` contains command definitions and argument parsing.
- `pkg/wildcard_flow/` contains the domain recon workflow.
- `pkg/company_flow/` contains the company recon workflow.
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
- Preserve the current separation between CLI parsing, workflow orchestration, storage, reporting, and setup.
- Treat external security tools as host dependencies. Do not replace them with in-process implementations unless explicitly asked.
- If a scan step changes outputs, inspect downstream query, report, export, and database behavior.

## Validation

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

If you change CLI wiring, also inspect:

- `chaathan --help`
- the affected subcommand help text
- README command examples if behavior changed
