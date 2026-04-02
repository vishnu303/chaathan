# WAF Bypass — Implementation Plan

Framework-level evasion features to reduce detection by target WAFs during active scanning phases (Phase 2–4). These changes are all **orchestration-layer** — they inject flags/headers into existing external tool invocations. No tool source code modification required.

---

## Phase 1: User-Agent Rotation (All Target-Facing Tools)

**Status**: ✅ Done for `pkg/metadata/collector.go` — needs extending to external tools.

### What

Move `realUserAgents` pool from `pkg/metadata/collector.go` to a shared location and inject a random real browser UA into every tool that directly hits the target.

### Where

#### [MODIFY] [tools.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go)

Add a `var realUserAgents` pool and `randomUA()` helper at package level. Then inject into each Run method:

| Method | Flag to add |
|--------|-------------|
| `RunHttpx()` | `-H "User-Agent: <ua>"` |
| `RunNuclei()` / `RunNucleiURLs()` | `-H "User-Agent: <ua>"` |
| `RunKatana()` | `-H "User-Agent: <ua>"` |
| `RunGoSpider()` | `--user-agent "<ua>"` |
| `RunFfuf()` | `-H "User-Agent: <ua>"` |
| `RunDalfox()` | `--header "User-Agent: <ua>"` |
| `RunArjun()` | `--headers '{"User-Agent":"<ua>"}'` |

**Skip these** (they talk to APIs, not the target):
subfinder, assetfinder, gau, waybackurls, dnsx, shuffledns, metabigor, uncover, github-subdomains

#### [MODIFY] [config.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go)

Add optional override:
```yaml
general:
  user_agent: ""  # empty = rotate from built-in pool
```

If set, use that single UA instead of the pool.

### Effort: ~30 minutes

---

## Phase 2: WAF Bypass Headers

### What

Inject headers that make requests appear to originate from internal/trusted infrastructure. Many WAFs whitelist traffic with these headers.

### Headers to inject

```
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

### Where

#### [MODIFY] [tools.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go)

Create a `wafBypassHeaders()` function that returns a `[]string` of `-H` flags:

```go
func wafBypassHeaders() []string {
    return []string{
        "-H", "X-Forwarded-For: 127.0.0.1",
        "-H", "X-Originating-IP: 127.0.0.1",
        "-H", "X-Real-IP: 127.0.0.1",
    }
}
```

Append these to args in: `RunHttpx`, `RunNuclei`, `RunNucleiURLs`, `RunKatana`, `RunFfuf`.

For gospider/dalfox/arjun, use their tool-specific header syntax.

#### [MODIFY] [config.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go)

```yaml
general:
  waf_bypass_headers: true  # default: true
  custom_headers:           # additional headers to inject
    - "X-Custom-Header: value"
```

### Effort: ~30 minutes

---

## Phase 3: Proxy Support

### What

Route all target-facing traffic through a proxy (Tor, Burp, rotating residential proxies). This is the single most effective WAF bypass — it rotates the source IP.

### Where

#### [MODIFY] [config.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go)

```yaml
general:
  proxy: ""  # e.g., "socks5://127.0.0.1:9050" or "http://user:pass@proxy:8080"
```

#### [MODIFY] [cli/wildcard.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/wildcard.go)

Add `--proxy` CLI flag that overrides config.

#### [MODIFY] [tools.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go)

Inject proxy flag when configured:

| Method | Flag |
|--------|------|
| `RunHttpx` | `-http-proxy <proxy>` |
| `RunNuclei` / `RunNucleiURLs` | `-proxy <proxy>` |
| `RunKatana` | `-proxy <proxy>` |
| `RunGoSpider` | `--proxy <proxy>` |
| `RunFfuf` | `-x <proxy>` |
| `RunDalfox` | `--proxy <proxy>` |
| `RunArjun` | not supported natively — skip |

#### [MODIFY] [collector.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/metadata/collector.go)

Pass proxy to `http.Transport` when configured:
```go
transport.Proxy = http.ProxyURL(proxyURL)
```

### Effort: ~1 hour

---

## Phase 4: Global Rate Limiting

### What

Most WAFs trigger on request frequency (>50 req/sec from one IP). Each tool has its own rate flag — expose a single config knob that sets them all.

### Where

#### [MODIFY] [config.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/config/config.go)

```yaml
general:
  requests_per_second: 0  # 0 = tool default, >0 = enforced limit
```

#### [MODIFY] [tools.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go)

When `requests_per_second > 0`, inject:

| Method | Flag |
|--------|------|
| `RunHttpx` | `-rl <n>` |
| `RunNuclei` / `RunNucleiURLs` | `-rl <n>` |
| `RunKatana` | `-rl <n>` |
| `RunFfuf` | `-rate <n>` |
| `RunDalfox` | `--delay <ms>` (compute from rps) |
| `RunNaabu` | `-rate <n>` |

### Effort: ~30 minutes

---

## Phase 5: Realistic Browser Headers

### What

Beyond User-Agent, real browsers send consistent Accept/Accept-Language/Accept-Encoding headers. Missing these is a fingerprint.

### Headers

```
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
```

### Where

Same injection points as Phase 2. Bundle them into `browserHeaders()` and append to args.

> [!WARNING]
> Some tools (nuclei, ffuf) override Accept/Accept-Encoding internally. Test each tool to ensure injected headers don't conflict with tool-specific behavior.

### Effort: ~15 minutes

---

## Phase 6: Jitter / Slow Mode

### What

Add a `--slow` CLI flag that:
1. Adds random delay (1–5s jitter) between tool invocations within each step
2. Doubles the inter-step delay
3. Reduces concurrency for parallel tools (katana/gospider workers, nuclei threads)

This makes the scan traffic pattern look organic rather than automated.

### Where

#### [MODIFY] [cli/wildcard.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/cli/wildcard.go)

Add `--slow` / `--stealth` boolean flag.

#### [MODIFY] [flow.go (wildcard)](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/wildcard_flow/flow.go)

When `c.SlowMode`:
```go
// Between each Phase 3/4 step
time.Sleep(time.Duration(2+rand.Intn(4)) * time.Second)
```

#### [MODIFY] [tools.go](file:///media/vishnu/Local%20Disk/Project%20Files/chaathan-flow/pkg/tools/tools.go)

When slow mode, reduce concurrency:
- `RunKatana`: add `-c 2` (default is 10)
- `RunGoSpider`: add `-c 2`
- `RunNuclei`: add `-c 5` (default is 25)
- `RunFfuf`: add `-t 10` (default is 40)

### Effort: ~1 hour

---

## Implementation Order

```mermaid
graph LR
    P1["Phase 1<br/>UA Rotation<br/>30min"] --> P2["Phase 2<br/>WAF Headers<br/>30min"]
    P2 --> P5["Phase 5<br/>Browser Headers<br/>15min"]
    P5 --> P4["Phase 4<br/>Rate Limiting<br/>30min"]
    P4 --> P3["Phase 3<br/>Proxy Support<br/>1hr"]
    P3 --> P6["Phase 6<br/>Jitter/Slow<br/>1hr"]

    style P1 fill:#22c55e,color:#fff
    style P2 fill:#22c55e,color:#fff
    style P5 fill:#eab308,color:#000
    style P4 fill:#eab308,color:#000
    style P3 fill:#f97316,color:#fff
    style P6 fill:#f97316,color:#fff
```

**Total estimated effort: ~4 hours**

## Config Example (Final State)

```yaml
general:
  user_agent: ""                    # empty = rotate from built-in pool
  proxy: ""                         # socks5://127.0.0.1:9050
  requests_per_second: 0            # 0 = tool default
  waf_bypass_headers: true          # inject X-Forwarded-For etc.
  custom_headers:                   # additional headers
    - "Authorization: Bearer xxx"
  slow_mode: false                  # reduce concurrency + add jitter
```

## CLI Flags (Final State)

```
chaathan wildcard -d example.com \
  --proxy socks5://127.0.0.1:9050 \
  --rate-limit 10 \
  --slow \
  --user-agent "custom UA string"
```

## What This Does NOT Cover

- **TLS fingerprint mimicry** (JA3) — requires `utls` library integration in our Go code and is impossible for external binaries. Tools like `nuclei` have their own JA3 randomization (`-tlsr`).
- **IP rotation at network level** — use upstream infrastructure (Tor, cloud functions, rotating proxies). The proxy flag enables this but doesn't provide the infra.
- **Payload-level WAF bypass** (encoding, case variation) — this is handled by individual tools (nuclei templates, dalfox payloads), not the orchestrator.
