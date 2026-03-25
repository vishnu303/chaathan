---
name: chaathan-tooling-setup
description: Use when changing Chaathan external tool installation, setup flows, prerequisites, tool checks, config-driven tool parameters, or failures involving host-installed recon utilities and the project setup process.
---

# Chaathan Tooling Setup

Use this skill for tasks involving external binaries, installation, and setup behavior.

## Relevant code

- `cli/setup.go`
- `cli/tools_cmd.go`
- `pkg/setup/`
- `pkg/tools/tools.go`
- `pkg/runner/runner.go`
- `pkg/config/config.go`
- `Makefile`

## Project model

Chaathan is a Go CLI that orchestrates many third-party recon tools. The project is not only the Go binary. A correct change must account for:

- whether a tool is installed
- how it is invoked
- how config overrides map into arguments
- how setup/check commands report failures

## Working rules

- Keep installation logic in `pkg/setup/`.
- Keep runtime invocation and argument construction in `pkg/tools/` or the owning workflow step.
- Keep user-facing checks in `cli/tools_cmd.go` and setup entrypoints in `cli/setup.go`.
- When a new tool is added, verify both install-time and run-time paths.

## When adding or changing a tool

1. Identify whether it is a Go tool, Python tool, packaged binary, or special-case dependency.
2. Add or update installation logic in the correct `pkg/setup/` file.
3. Update availability checks so `chaathan tools check` reports it correctly.
4. Update workflow/toolbox code to invoke it with controlled arguments.
5. Update config structs if the tool exposes user-tunable parameters.
6. Update README examples only if user-visible setup or workflow behavior changed.

## Validation

At minimum run:

```bash
go test ./...
go build -buildvcs=false -o chaathan .
```

If your environment allows it, also inspect:

```bash
./chaathan tools check
./chaathan setup --help
```

For setup bugs, distinguish clearly between:

- a Go code bug in Chaathan
- a missing external dependency on the machine
- a bad upstream tool install command

## Failure handling

- Prefer explicit, actionable error messages that tell the operator what dependency is missing.
- Do not make setup code assume `sudo` or package-manager behavior beyond what the repository already does.
- Avoid turning an optional tool absence into a fatal error unless the workflow truly requires it.
