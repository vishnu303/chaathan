---
name: chaathan-flow
description: Use this skill when the user asks to modify, debug, or extend the chaathan-flow bug bounty recon framework. It provides essential architectural rules, execution flow details, and prevents known regressions.
---

# Chaathan-Flow Developer Skill

## Goal
To safely develop, debug, and extend the chaathan-flow codebase while adhering to its specific execution model, configuration patterns, and avoiding past regressions.

## Instructions

- **Adopt a Collaborative Persona**: 
  - Give a verbal high-level overview **before** writing any code.
  - Explain the **why** behind architectural choices, not just the what.
  - Use a conversational, senior-developer tone.
  - Proactively suggest improvements or ask clarifying questions when scope is ambiguous.

- **Follow the Execution Flow**:
  - Understand the pipeline: `cli/wildcard.go` → `ToolBox (pkg/tools/tools.go)` → `Runner (pkg/runner/runner.go)` → `exec.Command`.
  - Runner mode (`native` | `docker`) is a global CLI flag set in `cli/root.go`.
  - Keep retry logic strictly in `NativeRunner`/`DockerRunner` — do not add retry logic inside individual tool wrappers.

- **Adhere to Configuration Patterns**:
  - `ToolBox` only receives `*config.ToolsConfig`. For API key access (e.g. uncover), call `tb.WithAPIKeys(&Cfg.APIKeys)` after instantiating `ToolBox` in `wildcard.go`.
  - Never pass raw config values directly to tool arguments. Use a helper method with a safe fallback:
    ```go
    func (t *ToolBox) naabuThreads() int {
        if t.Config != nil && t.Config.Naabu.Threads > 0 {
            return t.Config.Naabu.Threads
        }
        return 25 // always provide a safe fallback
    }
    ```

- **Respect Resume Logic Capabilities**:
  - Resuming uses `goto` labels (`step2:`, `step3:` etc.) in `wildcard.go`. 
  - Ensure all variables are declared *before* the first `goto` label. Variable declarations cannot appear between a `goto` statement and its label.

- **When Adding a New Tool**:
  1. Add wrapper in `pkg/tools/tools.go`.
  2. Add Docker image in `runner.go → getDockerImage()` and `isEntrypointImage()` if it has an entrypoint.
  3. Add install entry in `setup.go → goTools` (Go) or `pyTools` (Python).
  4. Wire the call into `cli/wildcard.go` at the correct step.
  5. Add output parser in `pkg/utils/parser.go` and store findings via `pkg/database/database.go`.

## Constraints

- **CRITICAL**: Do NOT reintroduce known tool flag bugs.
  - `naabu`: Never use `-p top-1000`. Use `-top-ports 1000`.
  - `tlsx`: Never use `-resp-only` with `-so` or `-ex`. `-resp-only` is only valid with `-san`/`-cn` alone.
  - `uncover`: Never blindly pass `-e shodan,censys,fofa`. Only pass engines that have configured API keys.

- **CRITICAL**: Do not instruct the user to build on Windows for Windows execution. The binary specifically targets Linux (`GOOS=linux go build`).

## Examples

**Example 1: Adding a new tool to `tools.go`**
_User Request:_ "Add ffuf to the toolbox."
_Correct Action:_
1. Provide a verbal overview of the 5-step checklist.
2. Create `func (t *ToolBox) RunFfuf(...)` using a helper for threads/timeout.
3. Remind the user to add the tool to `setup.go`.

**Example 2: Debugging Uncover Silent Skip**
_User Request:_ "Uncover is silently skipping during the scan."
_Correct Action:_
1. Check if the user has API keys configured in `~/.chaathan/config.yaml` under `api_keys:`.
2. Ensure `tb.WithAPIKeys(&Cfg.APIKeys)` is being called in `wildcard.go` before Uncover runs.
