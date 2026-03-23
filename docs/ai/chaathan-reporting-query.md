# Chaathan Reporting And Query Playbook

Use this playbook when the task affects how stored scan data is queried, ranked, summarized, or rendered.

## Ownership boundaries

- `cli/query.go` owns query subcommands, flags, filtering, and terminal formatting.
- `cli/report.go` owns report command flags and output path selection.
- `pkg/report/report.go` owns report assembly and format-specific rendering.
- `pkg/database/` owns persistence models, query functions, ROI computation, and metadata retrieval.
- `pkg/utils/` owns small display helpers such as URL truncation or severity summaries.

Keep presentation concerns in `cli/` and `pkg/report/`. Keep data access and ranking logic in `pkg/database/`.

## Current project shape

- Query commands read persisted scan data only.
- ROI ranking is computed from saved URLs, endpoints, vulnerabilities, ports, and metadata in `pkg/database/roi.go`.
- Reports aggregate scan details from the database through `report.Generate(scanID)` and export to markdown, JSON, HTML, or text.

## Invariants

- Query commands should degrade cleanly to "no results".
- JSON output should remain machine-readable and predictable.
- Report generation should fail with actionable errors if retrieval or export fails.
- Ranking changes should update reasons as well as scores.
- Presentation logic must tolerate missing optional metadata.

## Validation

```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

Then verify the affected path if sample scan data exists:

```bash
./chaathan query roi <scan_id> --json
./chaathan report generate <scan_id> --format json
./chaathan report generate <scan_id> --format markdown
```
