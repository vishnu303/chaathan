---
name: chaathan-dev
description: Use when making code changes in the Chaathan repository — CLI commands, Go package wiring, build/test flows, or any development task. Provides navigation patterns and project-specific rules.
---

# Chaathan Dev

## When to use

Activate this skill for any normal development work in this repository.

## Repository shape

```
main.go              → paths.Init(), defer database.Close(), cli.Execute()
cli/                 → Cobra commands, flag parsing, delegates to pkg/
pkg/wildcard_flow/   → 23-step domain recon (6 files: proxy_scraping, asset_discovery, validation,
                       content_discovery, vulnerability_scanning, fingerprinting)
pkg/company_flow/    → 3-step company recon (asn_discovery, domain_discovery, cloud_enum)
pkg/orchestrate/     → signal handling, infra bootstrap (runner + toolbox + notifier)
pkg/database/        → SQLite persistence, queries, ROI ranking, metadata storage
pkg/report/          → report assembly and multi-format export (md/json/html/txt)
pkg/scan/            → scan state, resume, WildcardSteps/CompanySteps definitions
pkg/setup/           → external tool installation (go_tools, python_tools, massdns, gf_patterns, proxy_tools)
pkg/tools/           → tool registry (30 tools) and runtime wrappers
pkg/proxy_scraping/   → automated proxy scraping (proxy-scraper-checker) + IP rotation (mubeng)
pkg/runner/          → command execution, retry, docker mode, timeout, UA/proxy injection
pkg/config/          → YAML config loading, defaults, rate limits
pkg/metadata/        → host metadata collection (CSP, headers, tech fingerprints)
pkg/scope/           → in/out-of-scope filtering, IP exclusion
pkg/notify/          → Discord, Slack, Telegram, webhook notifications
pkg/logger/          → styled terminal output, colors, scan UI headers
pkg/progress/        → spinners and progress bars
pkg/paths/           → centralised ~/.chaathan directory paths
utils/               → file I/O, parsers, export helpers, validation, formatting
```

## Default working pattern

1. Read the relevant Cobra command in `cli/` first.
2. Follow the call into the owning package in `pkg/`.
3. Change the narrowest layer that owns the behavior.
4. Verify with targeted Go commands before broadening scope.

## Common edit routes

| Task | Start at | Then check |
|------|----------|------------|
| New flag or command | `cli/*.go` | owning `pkg/` package |
| Wildcard scan change | `cli/wildcard.go` | `pkg/wildcard_flow/flow.go` → phase file |
| Company scan change | `cli/company.go` | `pkg/company_flow/flow.go` |
| Query/report/export | `cli/query.go`, `cli/report.go` | `pkg/database/`, `pkg/report/`, `utils/` |
| Tool install/setup | `cli/setup.go` | `pkg/setup/`, `pkg/tools/registry.go` |
| Notification change | — | `pkg/notify/`, `pkg/wildcard_flow/flow.go` |
| Config change | `cli/config.go` | `pkg/config/config.go` |

## Project-specific rules

- Extend `RunConfig`, `Ctx`, or `Files` structs — never thread long parameter lists.
- Keep CLI → workflow → storage separation strict.
- External tools are host dependencies; do not replace with in-process logic.
- Keep user-visible counts accurate: 22 steps across 5 phases for wildcard, 3 steps for company.
- Every step function must return `c.cancelled()`, never `return false`.
- Never call `MarkStepComplete` after `MarkStepFailed` in the same error path. Use `c.markStepCompleteIfNoFailure(stepName)` on step exit to ensure state consistency.
- Start steps with `if resume, skip := c.resumeOrSkip(stepName, stepHeader); skip { return resume }` to standardize skip/resume checks and step logging headers.
- `WildcardSteps` in `pkg/scan/scan.go` must match execution order in `flow.go`.
- `SaveLog` (`--log` flag) mirrors scan output to `~/.chaathan/logs/<domain>_<scanID>_<timestamp>.log`. The log path is stored on `Ctx.LogFilePath` and shown in next-steps hints. Any new logging option follows the same pattern: add to `RunConfig`, open file in `Run()`, store path on `Ctx`.

## Validation

```bash
go test ./...       # all tests
go vet ./...        # static analysis
go build -buildvcs=false -o chaathan .  # build check
```

If developing on Windows, run WSL commands by changing to the `/mnt/c/Users/vishn/desktop/chaathan` directory for optimal I/O (using interactive shell `-i` to source your Go environment):
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."       # all tests
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go vet ./..."        # static analysis
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."  # build check
```

If CLI wiring changed:
```bash
./chaathan --help
./chaathan <subcommand> --help
# On Windows, use WSL: wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && ./chaathan --help"
```

## Avoid

- Do not hardcode machine-specific paths (except intentional defaults like `~/` or `/usr/local/bin`).
- Do not introduce destructive cleanup of user scan data unless the task explicitly concerns deletion.
- Do not move business logic into README examples or shell scripts.
