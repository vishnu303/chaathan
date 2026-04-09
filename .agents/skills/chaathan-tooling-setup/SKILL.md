---
name: chaathan-tooling-setup
description: Use when changing external tool installation, setup flows, tool checks, config-driven parameters, or failures involving host-installed recon utilities.
---

# Chaathan Tooling & Setup

## When to use

Activate this skill for tasks involving external binary installation, setup behavior, or tool availability.

## Relevant code

| File | Purpose |
|------|---------|
| `cli/setup.go` | Setup command entry, `--update` flag |
| `cli/tools_cmd.go` | `tools list` / `tools check` commands |
| `pkg/setup/setup.go` | Setup orchestration |
| `pkg/setup/go_tools.go` | Go tool installation (`go install`) |
| `pkg/setup/python_tools.go` | Python tool installation (pip/clone) |
| `pkg/setup/massdns.go` | MassDNS build-from-source |
| `pkg/setup/gf_patterns.go` | gf pattern installation |
| `pkg/setup/prereqs.go` | System prerequisite checks |
| `pkg/setup/log.go` | Setup log file management |
| `pkg/tools/registry.go` | Canonical tool catalogue (28 tools) |
| `pkg/tools/tools.go` | Runtime tool wrappers and ToolBox |
| `pkg/runner/runner.go` | Command execution, retry, docker, UA/proxy |
| `pkg/config/config.go` | Per-tool config parameters |
| `Makefile` | `make setup`, `make tools-check` targets |

## Tool categories (from registry)

| Category | Tools |
|----------|-------|
| Enum | subfinder, assetfinder, sublist3r, amass |
| DNS | dnsx, shuffledns, massdns |
| Probe | httpx, tlsx, naabu |
| URLs | waybackurls, gau, arjun |
| Crawl | katana, gospider, hakrawler |
| Analysis | GoLinkFinder |
| Fuzz | ffuf |
| Vuln | nuclei, dalfox |
| Recon | uncover, metabigor, github-subdomains |
| Cloud | cloud_enum |
| Util | anew, gf |

## When adding or changing a tool

1. Identify type: Go tool (`go install`), Python tool (pip/clone), compiled binary (from source), or system package.
2. Add/update install logic in the correct `pkg/setup/` file.
3. Add/update the entry in `pkg/tools/registry.go` (`AllTools`).
4. Update `tools check` availability reporting.
5. Update workflow/toolbox code for runtime invocation.
6. Update config structs if the tool has user-tunable parameters.
7. Update README only if user-visible setup or workflow behavior changed.

## Working rules

- Installation logic lives in `pkg/setup/`.
- Runtime invocation and argument construction live in `pkg/tools/` or the owning workflow step.
- User-facing checks live in `cli/tools_cmd.go`; setup entry in `cli/setup.go`.
- `AllTools` in `pkg/tools/registry.go` is the single source of truth for the tool catalogue.

## Failure handling

- Prefer explicit, actionable error messages that identify the missing dependency.
- Do not assume `sudo` or package-manager behavior beyond what the repo already does.
- Do not turn optional tool absence into a fatal error unless the workflow requires it.
- Distinguish between: Go code bug in Chaathan, missing external dependency, and bad upstream install command.

## Validation

```bash
go test ./...
go build -buildvcs=false -o chaathan .
```

If environment allows:
```bash
./chaathan tools check
./chaathan setup --help
```

## Avoid

- Do not scatter install logic outside `pkg/setup/`.
- Do not modify `AllTools` without checking setup, check, and workflow consumers.
- Do not make setup code own runtime scan behavior.
