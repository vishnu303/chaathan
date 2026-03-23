# Chaathan Tooling And Setup Playbook

Use this playbook for changes involving external binaries, installation, and setup behavior.

## Relevant code

- `cli/setup.go`
- `cli/tools_cmd.go`
- `pkg/setup/`
- `pkg/tools/tools.go`
- `pkg/runner/runner.go`
- `pkg/config/config.go`
- `Makefile`

## Working rules

- Keep installation logic in `pkg/setup/`.
- Keep runtime invocation and argument construction in `pkg/tools/` or the owning workflow step.
- Keep user-facing checks in `cli/tools_cmd.go` and setup entrypoints in `cli/setup.go`.
- When a new tool is added, verify both install-time and run-time paths.

## When adding or changing a tool

1. Identify whether it is a Go tool, Python tool, packaged binary, or special-case dependency.
2. Add or update installation logic in the correct `pkg/setup/` file.
3. Update availability checks so `chaathan tools check` reports it correctly.
4. Update workflow or toolbox code to invoke it with controlled arguments.
5. Update config structs if the tool exposes user-tunable parameters.

## Validation

```bash
go test ./...
go build -buildvcs=false -o chaathan .
```

If the environment allows it:

```bash
./chaathan tools check
./chaathan setup --help
```
