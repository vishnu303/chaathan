# Chaathan Code Review & Refactoring Plan

Full code review of the Chaathan Go CLI framework (~15k LOC across 40+ files).
`go vet` is clean, `go test` passes (only 2 packages have tests — that's a finding in itself).

---

## Review Methodology

Reviewed all files in `cli/`, `pkg/wildcard_flow/`, `pkg/company_flow/`, `pkg/database/`, `pkg/report/`, `pkg/setup/`, `pkg/tools/`, `pkg/runner/`, `pkg/scan/`, `pkg/config/`, `pkg/logger/`, `pkg/notify/`, `pkg/utils/`, `pkg/scope/`, `pkg/progress/`, `pkg/metadata/`, and `main.go`.

Findings are ordered by **impact** (behavioral risk → code quality → style), not by file location.

---

## Findings

### ⛔ Tier 1 — Bugs & Behavioral Risks

#### F1. Hand-rolled `contains()` in `cli/config.go` — O(n²) recursive, wrong semantics
**File:** [config.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/config.go#L234-L236)

```go
func contains(s, substr string) bool {
    return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr)))
}
```

This is a hand-rolled recursive `strings.Contains`. It:
- Has **O(n²)** worst-case stack depth (one stack frame per character)
- Will **stack overflow** on long strings (Go's default goroutine stack is 1MB)
- Is called in `maskSecret()` which processes user-supplied config values

**Fix:** Replace with `strings.Contains(s, substr)` — a one-liner from the standard library.

---

#### F2. `MergeAndDeduplicate` leaks file handles in a loop
**File:** [file.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/utils/file.go#L16-L35)

```go
for _, file := range inputFiles {
    f, err := os.Open(file)
    // ...
    defer f.Close()  // ← deferred in a loop — all FDs stay open until function returns
```

`defer` inside a loop doesn't close files until the enclosing function returns. With 6+ input files per merge call, and multiple merge calls per scan, this silently accumulates open file descriptors.

**Fix:** Extract the file-reading logic into a closure or use an explicit `f.Close()` at the end of each iteration.

---

#### F3. Global mutable state: `database.DB`, `config.Cfg`, CLI package vars
**Files:** [database.go:16](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/database/database.go#L16), [config.go:251](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go#L251), [root.go:14-20](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/root.go#L14-L20)

The project has 4 layers of global mutable state:
1. `database.DB *sql.DB` — global DB connection
2. `config.Cfg *Config` — set as side effect of `Load()`
3. `cli.Mode`, `cli.OutputDir`, `cli.Verbose`, `cli.ConfigPath`, `cli.Cfg` — cobra flag targets
4. `logger.currentStep`, `logger.totalSteps`, `logger.scanStartTime` — mutable scan-scoped state in a shared package

Impact: Makes the code **untestable** and prevents future concurrent scan support. For now the CLI is single-shot so this works, but it's tech debt.

**Fix (Phase 4):** Encapsulate DB behind an interface; pass `*Config` through function params; wrap logger state in a struct.

---

#### F4. `Truncate` operates on bytes, not runes — garbles multi-byte text
**File:** [format.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/utils/format.go#L10-L15)

```go
func Truncate(s string, max int) string {
    if len(s) <= max { return s }
    return s[:max-3] + "..."  // ← byte slice, not rune slice
}
```

Slicing a Go string by byte index can split a multi-byte UTF-8 character in half, producing invalid UTF-8. Domain names with IDN are fine (punycode is ASCII), but page titles from httpx can contain any Unicode.

**Fix:** Use `[]rune(s)` or `utf8.RuneCountInString` for the length check.

---

#### F5. `logger.Section()` unconditionally increments `currentStep`
**File:** [logger.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/logger/logger.go#L95-L110)

Every call to `Section()` increments `currentStep`. But `Section()` is also called by `cli/status.go`, `cli/scans.go`, `cli/diff.go`, `cli/query.go`, `cli/export.go`, and `cli/delete.go` — none of which are scan workflows. This means the step counter silently increments for non-scan commands and could produce confusing output if a scan is running in the same process.

**Fix:** Only increment when `totalSteps > 0` (scan context is initialized), or better: separate `Section` (generic heading) from `StepHeader` (scan-specific).

---

#### F6. `status.go` hardcodes `~/.chaathan/state` instead of using config
**File:** [status.go:73-74](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/status.go#L73-L74), also [scans.go:179-180](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/scans.go#L179-L180)

```go
home, _ := os.UserHomeDir()
stateDir := filepath.Join(home, ".chaathan", "state")
```

This ignores the user's config `OutputDir` and hardcodes the home directory. If `UserHomeDir()` fails (containers, CI), it silently uses `"/.chaathan/state"`.

**Fix:** Derive state directory from config; propagate `UserHomeDir` errors.

---

#### F7. Silently swallowed `os.UserHomeDir()` errors (10+ call sites)
**Files:** [root.go:129](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/root.go#L129), [delete.go:233](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/delete.go#L233), [export.go:70](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/export.go#L70), [scans.go:179](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/scans.go#L179), [status.go:73](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/status.go#L73), [flow.go:317](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#L317), [config.go:317,424](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go#L317)

Pattern: `home, _ := os.UserHomeDir()` — the error is discarded everywhere. In rootless containers or stripped environments, this returns `("")`, and all paths silently become `"/.chaathan/..."`.

**Fix:** Create a `pkg/paths` helper that resolves the chaathan home directory once at startup, fails loudly, and is referenced everywhere.

---

### 🔶 Tier 2 — Duplicated Code & Missed Abstractions

#### F8. Massive duplication in step functions (skip/resume/fail/complete pattern)
**Files:** All step functions in [asset_discovery.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/asset_discovery.go), [validation.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/validation.go), [content_discovery.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/content_discovery.go), [vulnerability_scanning.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/vulnerability_scanning.go)

Every step function repeats the same pattern:
```go
if c.State.IsStepCompleted("step_name") {
    logger.Section("Step N: ... [RESUMED — skipping]")
} else if !c.SkipFoo {
    logger.Section("Step N: ...")
    if err := runWithSkip(c, "tool", func(sCtx context.Context) error {
        return c.Tb.RunFoo(sCtx, ...)
    }); err != nil {
        if err == ErrToolSkipped { /* ... */ } else {
            c.StateMgr.MarkStepFailed(c.State, "step_name", err)
            logger.Warning("...")
        }
    } else {
        /* parse + log */
        c.StateMgr.MarkStepComplete(c.State, "step_name")
    }
} else {
    logger.Section("Step N: Skipping ... (--skip-foo)")
    c.StateMgr.MarkStepComplete(c.State, "step_name")
}
return c.cancelled()
```

This is repeated ~18 times with minor variations. ~700 lines of boilerplate.

**Fix:** Extract a `runStep(c *Ctx, cfg StepConfig)` helper that handles resume, skip flag, runWithSkip, error handling, and step marking in one place. Each step function shrinks to ~5-10 lines.

---

#### F9. Duplicated runner initialization in `wildcard_flow/flow.go` and `company_flow/flow.go`
**Files:** [wildcard_flow/flow.go:336-356](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#L336-L356), [company_flow/flow.go:133-153](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/company_flow/flow.go#L133-L153)

The Runner + ToolBox + Notifier construction is copy-pasted between both flow packages. ~40 lines duplicated.

**Fix:** Extract a shared `pkg/orchestrate` or factory function that builds Runner/ToolBox/Notifier from `*config.Config`.

---

#### F10. Duplicated signal handling goroutine
**Files:** [wildcard_flow/flow.go:253-265](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#L253-L265), [company_flow/flow.go:99-110](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/company_flow/flow.go#L99-L110)

Same 13-line signal handler goroutine duplicated.

**Fix:** Extract to `pkg/utils` or a shared orchestration package.

---

#### F11. Duplicated diff set-building logic
**File:** [diff.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/diff.go#L76-L238)

`diffSubdomains`, `diffPorts`, `diffVulns`, `diffURLs` all follow the same pattern: load old set, load new set, compute added/removed. This could be a generic `diffSets[T]` function.

**Fix:** Create a generic diff helper using Go 1.21+ generics or a `diffByKey()` pattern.

---

#### F12. Duplicated vulnerability scanning row scanning
**File:** [database.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/database/database.go#L636-L711)

`GetVulnerabilities` and `GetVulnerabilitiesBySeverity` have identical row-scanning code (~35 lines each). The only difference is the WHERE clause.

**Fix:** Extract `scanVulnRows(rows *sql.Rows)` helper.

---

#### F13. Duplicated severity-to-emoji switch in `cli/diff.go` and `cli/status.go`
**Files:** [diff.go:196-205](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/diff.go#L196-L205), [status.go:56-65](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/status.go#L56-L65)

Both files independently map severity/status strings to emoji+text. `pkg/logger` already has `ColorSeverity`/`ColorStatus` but these call sites use emoji variants instead.

**Fix:** Add emoji variants to `pkg/logger` and use them everywhere.

---

### 🟡 Tier 3 — Architecture & Design Improvements

#### F14. `flow.go` Run() is a 280-line function with 21 copy-pasted `if executeStep` blocks
**File:** [flow.go:244-518](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#L244-L518)

```go
if executeStep(c, "passive_enum", stepPassiveEnum) {
    finalizeScan(c, "cancelled")
    return nil
}
if executeStep(c, "active_enum", stepActiveEnum) {
    finalizeScan(c, "cancelled")
    return nil
}
// ... 19 more identical blocks
```

This is the most impactful refactoring opportunity. 63 lines (21 × 3) of pure boilerplate.

**Fix:** Replace with a step registry:
```go
steps := []struct { name string; fn func(*Ctx) bool }{
    {"passive_enum", stepPassiveEnum},
    {"active_enum",  stepActiveEnum},
    // ...
}
for _, step := range steps {
    if executeStep(c, step.name, step.fn) {
        finalizeScan(c, "cancelled")
        return nil
    }
}
```

---

#### F15. `RunConfig` → `Ctx` field copying is 100% mechanical and fragile
**File:** [flow.go:373-404](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go#L373-L404)

`RunConfig` and `Ctx` share 15+ identical fields (`SkipAmass`, `SkipNuclei`, etc.), and they're manually copied field-by-field. Adding a new skip flag requires editing 3 files.

**Fix:** Embed `RunConfig` in `Ctx` or pass `RunConfig` by pointer to step functions.

---

#### F16. `tools_cmd.go` defines a 28-element anonymous struct array duplicating `pkg/setup` tool metadata
**File:** [tools_cmd.go:14-62](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/tools_cmd.go#L14-L62)

The tool list with names, categories, descriptions, and required flags lives in `cli/tools_cmd.go`. But `pkg/setup/` has its own tool lists. These can drift.

**Fix:** Define the tool registry once in a shared package (e.g., `pkg/tools/registry.go`) and reference it from both CLI and setup.

---

#### F17. `config set` uses a giant switch statement — not extensible
**File:** [config.go:172-215](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/config.go#L172-L215)

Adding a new config key requires adding a case, plus updating the help text at the bottom. A data-driven approach (map of key → setter function) would be more maintainable.

**Fix (Phase 5):** Refactor to a registry pattern.

---

#### F18. `company_flow/Ctx` tracks `Total/Completed/Failed` manually — doesn't use `scan.State`
**File:** [company_flow/flow.go:69-71](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/company_flow/flow.go#L69-L71)

Unlike `wildcard_flow` which uses `scan.Manager` and `scan.State` for step tracking, `company_flow` uses manual counter fields. This means company scans can't be resumed.

**Fix:** Unify company flow to use `scan.State` like wildcard flow does.

---

### 🟢 Tier 4 — Missing Validation & Error Handling

#### F19. `CreateOutputDir` ignores `UserHomeDir` error + no sanitization of `target`
**File:** [root.go:126-138](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/root.go#L126-L138)

```go
home, _ := os.UserHomeDir()
baseDir = filepath.Join(home, ".chaathan", "scans")
path := filepath.Join(baseDir, target)  // target is user-controlled
```

No sanitization of `target` (could contain `../` or special characters). Also silently uses empty string if home dir fails.

**Fix:** `ValidateDomain` already runs before this, so `../` attacks are blocked for wildcard scans. But company names are only `strings.TrimSpace`-checked — no path sanitization. Add `filepath.Clean` and reject path separators.

---

#### F20. `json.MarshalIndent` errors silently discarded in query commands
**File:** [query.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/query.go) — lines 134, 172, 213, 259, 297, 372

Pattern: `data, _ := json.MarshalIndent(...)` — error discarded. If the data contains types that can't be marshaled, the user gets `null` with no explanation.

**Fix:** Check errors and log them.

---

#### F21. `os.MkdirAll` return value ignored in `report.go`
**File:** [report.go:63](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/report.go#L63)

```go
os.MkdirAll(reportsDir, 0755)  // error discarded
```

If the directory can't be created, the subsequent `WriteFile` will fail with a confusing error.

**Fix:** Check and log the error.

---

### 🔵 Tier 5 — Test Coverage & Observability

#### F22. Only 2 out of 17 packages have tests
15 packages have zero test files. Critical untested surfaces:
- `pkg/database/` — 1163-line file with 0 tests
- `pkg/wildcard_flow/` — 0 tests for any step function
- `pkg/utils/` — 0 tests for parsers, merge, validation
- `pkg/runner/` — 0 tests for retry logic

**Fix:** Start with table-driven tests for `pkg/utils/validate.go`, `pkg/utils/file.go`, `pkg/database/` CRUD, and `pkg/runner/` retry logic. These have the highest correctness impact and lowest setup cost.

---

#### F23. `pkg/database` uses `log.Printf` instead of `pkg/logger`
**File:** [database.go:1104](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/database/database.go#L1104)

```go
log.Printf("[WARN] gf_matches insert failed...")
```

This bypasses the project's styled logger, producing unstyled output interleaved with styled output.

**Fix:** Replace with `logger.Warning(...)`.

---

#### F24. `runner.New()` exists alongside `runner.NewWithRetry()` — dead code path
**File:** [runner.go:341-346](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/runner/runner.go#L341-L346)

`New()` creates runners with `MaxRetries: 0` and `RetryDelay: 0`. Both call sites in the codebase use `NewWithRetry()` instead. `New()` is dead code.

**Fix:** Remove `New()` or have it delegate to `NewWithRetry(mode, verbose, 1, 3*time.Second)`.

---

### ⚪ Tier 6 — Minor Improvements & Cleanup

#### F25. Hardcoded version string in `root.go`
**File:** [root.go:145](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/root.go#L145)

```go
fmt.Printf("... v2.0.0\n", ...)
```

Version is hardcoded. Should use `ldflags` injection at build time.

**Fix:** Add `var Version = "dev"` and inject via `go build -ldflags "-X ..."`.

---

#### F26. `NativeRunner` and `DockerRunner` have duplicated retry loops
**File:** [runner.go:52-98](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/runner/runner.go#L52-L98) vs [runner.go:134-178](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/runner/runner.go#L134-L178)

The retry loop logic is copy-pasted between `NativeRunner.Run()` and `DockerRunner.Run()`. 47 lines duplicated.

**Fix:** Extract a generic `retryLoop` function that takes a `runOnce` callback.

---

#### F27. `config.Save()` writes sensitive API keys to disk in plaintext
**File:** [config.go:288-313](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go#L288-L313)

The config file is written as `0644` (world-readable). API keys for GitHub, Shodan, etc. are in plaintext.

**Fix:** Use `0600` permissions for the config file.

---

#### F28. `getExtension()` in `report.go` duplicates logic that should live in `pkg/report`
**File:** [report.go:83-96](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/report.go#L83-L96)

The CLI shouldn't own format-to-extension mapping — that belongs in `pkg/report` alongside the format definitions.

**Fix:** Move to `pkg/report.ExtensionFor(format)`.

---

#### F29. `WithEnv` option not exposed in runner despite `Env` field in `RunOptions`
**File:** [runner.go:32-48](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/runner/runner.go#L32-L48)

`RunOptions` has an `Env` field, but there's no `WithEnv(...)` option function to set it. The field is only settable if someone constructs `RunOptions` manually.

**Fix:** Add `WithEnv(env ...string) Option`.

---

#### F30. `isEntrypointImage()` and `getDockerImage()` don't include all tools
**File:** [runner.go:276-339](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/runner/runner.go#L276-L339)

Several tools fall through to `"alpine"` which won't have the tool installed. `gospider`, `gau`, `waybackurls`, etc. are mapped to images that may not match current Docker Hub tags.

**Fix:** Validate docker image availability; consolidate image registry.

---

#### F31. `config.Save` writes a URL `https://github.com/yourusername/chaathan` in the header
**File:** [config.go:301-305](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go#L301-L305)

```go
header := `# Documentation: https://github.com/yourusername/chaathan`
```

This is a placeholder URL that was never updated.

**Fix:** Update to the real repo URL or remove.

---

---

## Implementation Phases

### Phase 1 — Critical Fixes (Low-risk, high-value)
*Estimated: 1-2 hours. No architectural changes. Pure bugfixes and safety.*

| # | Finding | Files | Effort |
|---|---------|-------|--------|
| F1 | Replace recursive `contains()` with `strings.Contains` | `cli/config.go` | 5 min |
| F2 | Fix deferred file close in loop | `pkg/utils/file.go` | 10 min |
| F4 | Fix byte-based truncation | `pkg/utils/format.go` | 10 min |
| F7 | Handle `UserHomeDir` errors (create `pkg/paths`) | 10+ files | 30 min |
| F20 | Check `json.MarshalIndent` errors | `cli/query.go` | 10 min |
| F21 | Check `os.MkdirAll` error | `cli/report.go` | 5 min |
| F23 | Replace `log.Printf` with `logger.Warning` | `pkg/database/database.go` | 5 min |
| F27 | Config file `0600` permissions | `pkg/config/config.go` | 5 min |
| F31 | Fix placeholder URL | `pkg/config/config.go` | 2 min |

---

### Phase 2 — Dedup & Small Refactors (Low-risk, medium-value)
*Estimated: 2-3 hours. Removes duplicated code without changing behavior.*

| # | Finding | Files | Effort |
|---|---------|-------|--------|
| F5 | Split `Section` from `StepHeader` in logger | `pkg/logger/logger.go` | 30 min |
| F12 | Extract `scanVulnRows` helper | `pkg/database/database.go` | 20 min |
| F13 | Unify severity/status emoji formatting | `cli/diff.go`, `cli/status.go`, `pkg/logger/` | 20 min |
| F24 | Remove dead `runner.New()` or consolidate | `pkg/runner/runner.go` | 10 min |
| F26 | Extract retry loop from Runner | `pkg/runner/runner.go` | 30 min |
| F28 | Move `getExtension` to `pkg/report` | `cli/report.go`, `pkg/report/` | 10 min |
| F29 | Add `WithEnv` option | `pkg/runner/runner.go` | 10 min |

---

### Phase 3 — Workflow Refactoring (Medium-risk, high-value)
*Estimated: 4-6 hours. The biggest bang-for-buck phase. Touches the core scan pipeline.*

| # | Finding | Files | Effort |
|---|---------|-------|--------|
| F8 | Extract `runStep()` helper for step boilerplate | `pkg/wildcard_flow/*.go` | 2-3 hours |
| F9 | Extract shared Runner/ToolBox/Notifier factory | `pkg/wildcard_flow/flow.go`, `pkg/company_flow/flow.go` | 30 min |
| F10 | Extract shared signal handler | `pkg/wildcard_flow/flow.go`, `pkg/company_flow/flow.go` | 20 min |
| F14 | Replace 21 `if executeStep` blocks with step registry loop | `pkg/wildcard_flow/flow.go` | 1 hour |
| F15 | Embed `RunConfig` in `Ctx` to eliminate field copying | `pkg/wildcard_flow/flow.go` | 1 hour |

> [!IMPORTANT]
> Phase 3 changes touch the scan pipeline. Each sub-task should be verified with `go build && go vet && go test ./...` before proceeding. The step registry change (F14) and the `runStep` extraction (F8) should be done together since they complement each other.

---

### Phase 4 — Architecture & Testability (Higher-risk, long-term value)
*Estimated: 6-8 hours. Structural improvements that enable future development.*

| # | Finding | Files | Effort |
|---|---------|-------|--------|
| F3 | Reduce global state (DB interface, pass config) | Multiple packages | 3-4 hours |
| F6 | Derive state directory from config, not hardcoded | `cli/status.go`, `cli/scans.go`, `pkg/wildcard_flow/flow.go` | 30 min |
| F11 | Generic diff helper | `cli/diff.go` | 1 hour |
| F16 | Shared tool registry | `cli/tools_cmd.go`, `pkg/setup/` | 1 hour |
| F18 | Unify company_flow to use `scan.State` | `pkg/company_flow/` | 1-2 hours |
| F19 | Path sanitization for company names | `cli/root.go`, `cli/company.go` | 20 min |
| F25 | Build-time version injection | `cli/root.go`, `Makefile` | 20 min |

---

### Phase 5 — Testing & Polish (Low-risk, ongoing)
*Estimated: 8-12 hours total. Can be done incrementally.*

| # | Finding | Files | Effort |
|---|---------|-------|--------|
| F22 | Add tests for `pkg/utils/validate.go` | New test file | 1 hour |
| F22 | Add tests for `pkg/utils/file.go` | New test file | 1 hour |
| F22 | Add tests for `pkg/database/` CRUD | New test file | 2-3 hours |
| F22 | Add tests for `pkg/runner/` retry logic | New test file | 1-2 hours |
| F17 | Refactor `config set` to registry pattern | `cli/config.go` | 1 hour |
| F30 | Validate/consolidate Docker image registry | `pkg/runner/runner.go` | 1 hour |

---

## Open Questions

> [!IMPORTANT]
> 1. **Phase 3 scope** — Do you want the step registry (F14) to be a simple slice of `{name, fn}` pairs, or a more structured registry with metadata (description, skip-flag name, output files)?
> 2. **Phase 4 - Global DB** — Are you open to wrapping `database.DB` behind an interface, or do you want to keep the package-level functions and just pass the `*sql.DB` through?
> 3. **Phase priority** — Do you want me to execute all phases, or start with specific phases? I'd recommend starting with Phase 1 + Phase 2 (safest, biggest immediate value), then Phase 3 separately.

## Verification Plan

### Automated Tests
```bash
go test ./...
go vet ./...
go build -buildvcs=false -o chaathan .
```

### Manual Verification
- After Phase 3: Run `chaathan wildcard --help` to verify step descriptions still match
- After Phase 4: Run `chaathan status` and `chaathan scans list` to verify dashboard still works
- After each phase: Inspect the affected command's `--help` output
