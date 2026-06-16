# Implementation Plan — Smart Session Manager (Auth Playbook)

This plan outlines the design and files to modify to support a Smart Session Manager ("Auth Playbook") in Chaathan. It enables automated API/form logins, dynamically extracts cookies/bearer tokens, performs active session checks, and automatically refreshes expired sessions mid-scan.

## User Review Required

> [!IMPORTANT]
> - Users configure the login credentials and endpoints under a new `auth` block in `config.yaml`.
> - If `auth.enabled` is `true`, Chaathan will run an initial login routine, extract cookies (and/or OAuth bearer tokens), and dynamically inject them into all executing tools (Katana, Httpx, Nuclei, Dalfox, etc.).
> - A background worker will check the session status against a protected endpoint (`session_check_url`) every N minutes, refreshing the session if it has expired.

## Proposed Changes

### 1. Configuration Schema

#### [MODIFY] [config.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/config/config.go)
- Define `AuthConfig` struct:
  ```go
  type AuthConfig struct {
      Enabled                 bool              `yaml:"enabled"`
      LoginURL                string            `yaml:"login_url"`
      Method                  string            `yaml:"method"` // GET, POST
      ContentType             string            `yaml:"content_type"` // application/json or application/x-www-form-urlencoded
      Body                    string            `yaml:"body"` // Raw string body containing credentials
      Headers                 map[string]string `yaml:"headers"` // Optional custom static headers for login
      SessionCheckURL         string            `yaml:"session_check_url"`
      SessionCheckSuccessStr  string            `yaml:"session_check_success_string"`
      SessionCheckIntervalMin int               `yaml:"session_check_interval_min"`
      TokenJSONPath           string            `yaml:"token_json_path"` // Optional: key to extract OAuth bearer token
  }
  ```
- Add `Auth AuthConfig `yaml:"auth"`` to `Config` struct.
- In `DefaultConfig()`, initialize `Auth` with default values (disabled by default).

---

### 2. Session Manager Implementation

#### [NEW] [session.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/auth/session.go)
Create a thread-safe `SessionManager` in a new package `pkg/auth`:
- `SessionManager` struct:
  - Cache fields: `activeCookie string`, `activeHeaders []string`, `lastCheck time.Time`.
  - Mutex for thread-safe access.
- `Login(ctx context.Context) error`:
  - Sends a login request to `LoginURL` with credentials.
  - Reads `Set-Cookie` headers to build the full cookie string.
  - If `TokenJSONPath` is configured, parses the response JSON and extracts the bearer token (e.g. `access_token`) and adds an `Authorization: Bearer <token>` header.
- `CheckSession(ctx context.Context) bool`:
  - Requests `SessionCheckURL` using cached credentials.
  - Returns `true` if HTTP status is `200` AND `SessionCheckSuccessStr` (if defined) is found in response body.
- `GetActiveSession(ctx context.Context) (string, []string, error)`:
  - Checks if cache is present and valid.
  - If `lastCheck` is older than `SessionCheckIntervalMin`, runs `CheckSession`.
  - If `CheckSession` fails or cache is empty, runs `Login()` to refresh credentials.

---

### 3. Tool Execution & Toolbox Integration

#### [MODIFY] [tools.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/tools/tools.go)
- Add `SessionManager` pointer field to `ToolBox`.
- Implement `tb.RefreshSession(ctx context.Context)`:
  - If `SessionManager` is set, calls `GetActiveSession` and updates `tb.CustomCookie` and `tb.CustomHeaders` dynamically.
- Modify `Runner.Run` calls inside `ToolBox` methods to invoke `t.RefreshSession(ctx)` right before running the commands.

---

### 4. Workflow Context Wiring

#### [MODIFY] [flow.go](file:///c:/Users/vishn/Desktop/chaathan/pkg/wildcard_flow/flow.go)
- Add `SessionMgr *auth.SessionManager` to the `Ctx` struct.
- In `Run()`, if `cfg.Cfg.Auth.Enabled` is `true`, initialize the `SessionManager` and perform an initial `Login()`.
- Attach the `SessionManager` instance to `infra.ToolBox` so that all tool runners have access to it.

---

## Verification Plan

### Automated Tests
Build and verify unit tests:
```bash
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go test ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go vet ./..."
wsl bash -i -c "cd /mnt/c/Users/vishn/desktop/chaathan && go build -buildvcs=false -o chaathan ."
```

### Manual Verification
1. Setup a dummy local web application or mock HTTP server that requires login (returns cookie/token) and has a protected page.
2. Configure `config.yaml` to point to the mock login and session check endpoints.
3. Run a wildcard scan on the mock application and inspect outputs to verify that cookies are successfully extracted, validated, and refreshed dynamically.
