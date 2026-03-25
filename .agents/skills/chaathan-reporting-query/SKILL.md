---
name: chaathan-reporting-query
description: Use when changing Chaathan query commands, ROI ranking output, scan report generation, export formatting, or the database-to-CLI/report presentation path for scan results.
---

# Chaathan Reporting And Query

Use this skill when the task affects how stored scan data is queried, ranked, summarized, or rendered to users.

## Ownership boundaries

- `cli/query.go` owns query subcommands, flags, filtering, and terminal formatting.
- `cli/report.go` owns report command flags and output path selection.
- `pkg/report/report.go` owns report assembly and format-specific rendering.
- `pkg/database/` owns persistence models, query functions, ROI computation, and metadata retrieval.
- `pkg/utils/` owns small display helpers such as URL truncation or severity summaries.

Keep presentation concerns in `cli/` and `pkg/report/`. Keep data access and ranking logic in `pkg/database/`.

## Current project shape

- Query commands read persisted scan data only. They are not supposed to rerun recon tools.
- ROI ranking is computed from saved URLs, endpoints, vulnerabilities, ports, and metadata in `pkg/database/roi.go`.
- Reports aggregate scan details from the database through `report.Generate(scanID)` and then export to markdown, JSON, HTML, or text.
- Terminal output uses `tabwriter` or explicit human-readable sections in `cli/query.go`.

## Working pattern

1. Start from the user-facing command in `cli/query.go` or `cli/report.go`.
2. Identify which database accessor or report field supplies the data.
3. Change the backing data function first if semantics are wrong.
4. Change display formatting second.
5. Verify JSON output and human-readable output separately when both exist.

## Query change checklist

- If adding a new filter:
  wire the flag in Cobra, parse it in `cli/query.go`, and keep the actual selection logic close to the owning database call when possible.
- If changing table output:
  keep JSON output stable unless the task explicitly changes API shape.
- If changing ROI ranking:
  inspect `pkg/database/roi.go`, `pkg/database/metadata.go`, and all fields printed in `query roi`.
- If changing endpoint, URL, or vulnerability displays:
  check truncation helpers and severity summaries in `pkg/utils/`.

## Report change checklist

- If adding a report field:
  add it to `Report`, populate it in `Generate`, then update each export format that should expose it.
- Keep markdown, HTML, text, and JSON behavior aligned unless there is a deliberate format-specific choice.
- When editing HTML output, preserve offline usability. It is a generated standalone file, not an app shell.
- When editing markdown templates, be careful with template functions and escaping around evidence blocks.

## Invariants to preserve

- Query commands should degrade cleanly to "no results" instead of printing broken tables.
- JSON output should remain machine-readable and predictable.
- Report generation should fail with actionable errors if data retrieval breaks or output format is unsupported.
- Ranking changes should update reasons as well as scores; the explanation is part of the feature.
- Database-backed presentation must tolerate missing optional metadata such as URL/host metadata rows.

## Files commonly involved together

- `cli/query.go`
- `cli/report.go`
- `pkg/report/report.go`
- `pkg/database/roi.go`
- `pkg/database/metadata.go`
- `pkg/database/database.go`
- `pkg/utils/format.go`

## Validation

Run the normal compile checks first:

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

Then verify the affected presentation path:

```bash
./chaathan query subdomains <scan_id> --json
./chaathan query roi <scan_id> --json
./chaathan report generate <scan_id> --format json
./chaathan report generate <scan_id> --format markdown
```

If you do not have a local database with sample scans, say so explicitly and rely on compile-time verification plus code inspection.

## Avoid

- Do not put SQL or ranking heuristics directly into Cobra handlers.
- Do not change JSON field names casually; they are part of the tool’s automation surface.
- Do not let one report format drift far away from the others without an explicit reason.
