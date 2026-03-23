# Chaathan Code Review Playbook

Use this playbook when reviewing changes in this repository.

## Review priorities

Prioritize findings that could break:

- scan execution or step sequencing
- CLI compatibility or help/flag behavior
- database persistence and downstream queries
- report and export correctness
- setup and tool availability checks
- cancellation, resume, or skip semantics

This repository is orchestration-heavy. Small-looking changes often break behavior across multiple layers.

## Common regression patterns

- CLI flag added but not copied into `RunConfig` or workflow `Ctx`
- workflow artifact renamed without updating downstream consumers
- database model changed without schema update or fallback
- report field added in one format but missing from others
- ROI score changed without updating `Reasons`
- setup logic installs a tool but `tools check` or runtime invocation still disagrees

## Review output

Lead with concrete findings ordered by severity.

For each finding include:

- affected file and line
- what breaks or could regress
- why it matters in this codebase
- the missing validation if relevant

If there are no findings, state that explicitly and mention residual risks or untested surfaces.
