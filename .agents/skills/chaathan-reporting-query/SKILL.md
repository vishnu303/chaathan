---
name: chaathan-reporting-query
description: Use when changing query commands, ROI ranking, report generation, export formatting, or the database-to-CLI/report presentation path.
---

# Chaathan Reporting & Query

## When to use

Activate this skill when the task affects how stored scan data is queried, ranked, summarized, or rendered.

## Ownership

| Concern | Owner |
|---------|-------|
| Query subcommands, flags, terminal formatting | `cli/query.go` |
| Report command flags, output path selection | `cli/report.go` |
| Report assembly, format-specific rendering | `pkg/report/report.go` |
| Persistence, queries, ROI, metadata retrieval | `pkg/database/` (`database.go`, `roi.go`, `metadata.go`) |
| Display helpers (truncation, severity summary) | `utils/format.go` |
| Text file export | `utils/export.go`, `cli/export.go` |

Keep presentation in `cli/` and `pkg/report/`. Keep data access and ranking in `pkg/database/`.

## Working pattern

1. Start from the user-facing command (`cli/query.go` or `cli/report.go`).
2. Identify which database accessor or report field supplies the data.
3. Change the backing data function first if semantics are wrong.
4. Change display formatting second.
5. Verify JSON and human-readable output separately when both exist.

## Query changes

- **New filter:** wire flag in Cobra → parse in `cli/query.go` → keep selection logic near the database call.
- **Table output change:** keep JSON output stable unless the task explicitly changes API shape.
- **ROI ranking change:** inspect `pkg/database/roi.go`, `pkg/database/metadata.go`, and all fields printed in `query roi`.
- **Display change:** check truncation helpers in `utils/format.go`.

## Report changes

- **New field:** add to `Report` struct → populate in `Generate` → update each export format.
- Keep markdown, HTML, text, and JSON formats aligned unless there's a deliberate format-specific choice.
- HTML output must remain a standalone offline-usable file.
- Be careful with template functions and escaping around evidence blocks in markdown.

## Invariants

- Query commands degrade to "no results" instead of broken tables.
- JSON output remains machine-readable and predictable.
- Report generation fails with actionable errors if data retrieval or format is unsupported.
- Ranking changes must update `Reasons` alongside scores — the explanation is part of the feature.
- Presentation must tolerate missing optional metadata (URL/host metadata rows may not exist).

## Files commonly involved together

- `cli/query.go`, `cli/report.go`, `cli/export.go`
- `pkg/report/report.go`
- `pkg/database/database.go`, `pkg/database/roi.go`, `pkg/database/metadata.go`
- `utils/format.go`, `utils/export.go`

## Validation

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

If developing on Windows, use WSL with the installed Go path for all commands:
```bash
wsl /usr/local/go/bin/go test ./...
wsl /usr/local/go/bin/go vet ./...
wsl /usr/local/go/bin/go build -buildvcs=false -o chaathan .
```

Then verify presentation paths (if sample DB exists):
```bash
./chaathan query subdomains <id> --json
./chaathan query roi <id> --json
./chaathan report generate <id> --format json
./chaathan report generate <id> --format markdown
# On Windows, prefix with wsl: wsl ./chaathan query subdomains <id> --json
```

If no sample DB is available, rely on compile-time checks and code inspection.

## Avoid

- Do not put SQL or ranking heuristics in Cobra handlers.
- Do not change JSON field names casually — they are automation surfaces.
- Do not let one report format drift far from others without an explicit reason.
