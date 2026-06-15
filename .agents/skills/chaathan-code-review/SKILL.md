---
name: chaathan-code-review
description: Use when reviewing changes in the Chaathan repository. Focuses on behavioral regressions, cross-layer propagation bugs, and orchestration-specific risks.
---

# Chaathan Code Review

## When to use

Activate this skill when reviewing a diff, PR, or code changes in this repository. **Do not use this skill while writing implementation code.**

## Priority Order of Review

When reviewing code, prioritize the identification of issues in the following order:
1. **Orchestration & State Transitions:** Scan execution order, step sequencing, resume states, skip options.
2. **CLI Compatibility:** Flags matching, help text alignment, input/argument validation.
3. **Database & Schema Integrity:** SQL schemas, metadata tables, index safety, transaction blocks, backwards compatibility.
4. **Data Exports:** Correctness of exported files (Markdown, JSON, HTML, TXT) across all endpoints.
5. **Setup & Verification:** External bin verification, prerequisite validations, path resolving.
6. **Cancellation & Signals:** Cleanup of running child tasks, process groups, and temporary configuration files.
7. **Notifications:** Payload formats, error handling when webhook triggers fail.

---

## Technical Review Matrix

| Layer | Key Targets to Inspect | Immediate Breakage Risks |
|:---|:---|:---|
| **CLI** | Flag parsing, validation, help strings, config overrides | Incorrect flag types, missing config bindings, parsing crashes |
| **Workflows** | Step ordering, file pointers (`Ctx.F`), skip flags, exit states | Hardcoded paths, wrong outputs fed downstream, lost states |
| **Orchestrate** | Signal traps, context cancellation propagation | Orphan processes, blocked pipelines, lock leaks |
| **Database** | SQL statements, parameters, index configurations, schema formats | SQLite locking errors, SQL injection, schema mismatches |
| **Report** | Presentation models, template escapes, single-file packaging | HTML rendering failures, template injection, missing outputs |
| **Setup** | Command lines, dependencies checks, runtime binary validation | Broken install routines, host mismatch, missing check updates |
| **Metadata** | Struct definition, key safety, parsing JSON schemas | Crashes on empty metadata, index key conflicts |

---

## Critical Code-Level Gotchas

During code reviews, look for these specific anti-patterns:

### 1. Workflow State Machine Regressions
- **Mistake:** Calling `MarkStepComplete` after a step has already failed via `MarkStepFailed`.
- **Mitigation:** The workflow must execute `c.markStepCompleteIfNoFailure(stepName)` on exit.
- **Mistake:** Returning hardcoded `false` or `true` on step failure/success instead of checking `c.cancelled()`.
- **Mitigation:** Verify that the step function ends with `return c.markStepCompleteIfNoFailure(stepName)` or explicitly returns `c.cancelled()` if interrupted.
- **Mistake:** Resume checks returning static boolean values.
- **Mitigation:** Ensure resume checks start with `if resume, skip := c.resumeOrSkip(stepName, stepHeader); skip { return resume }`.

### 2. Orphan Processes & PGID Leaks
- **Mistake:** Spawning external commands outside the core `pkg/runner` package using standard `exec.Command` without setting `Setpgid: true`.
- **Mitigation:** Inspect all manual execution paths (e.g., custom tools). Ensure `SysProcAttr` has `Setpgid: true` configured:
  ```go
  cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
  ```
  On cleanup or interruption, the killing signal must target the negative process ID (`-PID`) to cleanly terminate all children:
  ```go
  syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
  ```

### 3. Memory Exhaustion ($O(N)$ vs $O(1)$ Streams)
- **Mistake:** Loading raw scan outputs, crawl results, or URLs into memory arrays all at once for deduplication or parsing.
- **Mitigation:** Ensure high-volume files (e.g., URLs, crawled domains) are read line-by-line using `bufio.Scanner` and stream-deduplicated using hash key matches or priority min-heaps.

### 4. Silent Tool Replacements
- **Mistake:** Substituting an external tool run with custom, incomplete Go logic to bypass setup steps.
- **Mitigation:** All recon behaviors must use their configured external bin wrapper defined in `pkg/tools/`. Do not write duplicate parsing routines inside step functions.

---

## Review Output Template

When providing a code review report, format your findings strictly as follows:

### 1. Summary of Changes
Provide a brief, high-level summary of the reviewed code changes and their intent.

### 2. High-Severity Findings
List issues that will cause runtime crashes, data loss, state mismatches, or orphan processes. For each issue, specify:
- **Location:** File path and line range.
- **Bug Description:** What fails and how.
- **Impact:** Why this is critical.
- **Remediation:** Expected code snippet.

### 3. Low/Medium-Severity Findings
List issues concerning minor logic errors, style issues, performance improvements, or documentation drift.

### 4. Verification & Residual Risks
Identify components or downstream workflows that could still be affected and specify tests that must be executed to ensure regression safety.
