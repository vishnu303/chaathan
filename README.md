# Chaathan

A modular CLI pentesting framework for bug bounty reconnaissance and vulnerability scanning. Single binary, persistent SQLite database, 28 integrated tools.

```
   _____ _                 _   _                 
  / ____| |               | | | |                
 | |    | |__   __ _  __ _| |_| |__   __ _ _ __  
 | |    | '_ \ / _' |/ _' | __| '_ \ / _' | '_ \ 
 | |____| | | | (_| | (_| | |_| | | | (_| | | | |
  \_____|_| |_|\__,_|\__,_|\__|_| |_|\__,_|_| |_|
```

## What It Does

Chaathan runs a **21-step automated recon workflow** on a target domain and a **3-step company reconnaissance workflow** — subdomain discovery, DNS resolution, port scanning, web crawling, vulnerability scanning, XSS detection, subdomain takeover checks, cloud enumeration, JS secret scanning, ASN discovery — and stores everything in a local SQLite database you can query, diff, and export.

## Install

```bash
git clone https://github.com/vishnu303/chaathan-flow.git
cd chaathan-flow

# One-command setup: builds, installs to /usr/local/bin, installs all tools
make all

# Or step by step:
make build          # Build binary
make install        # Install to /usr/local/bin
make setup          # Install all external tools
```

**Requirements:** Go 1.21+, Git, Linux

## Quick Start

```bash
chaathan setup                          # Install tools (first time)
chaathan setup --update                 # Reinstall / update all tools

chaathan wildcard -d target.com         # Full 21-step domain recon
chaathan company -n "Company Inc"       # Company/org discovery

chaathan tools check                    # Verify tool installations
chaathan status                         # Dashboard overview

chaathan query vulns 1 --severity critical    # Query results
chaathan query subdomains 1 --live            # Live subdomains only
chaathan report generate 1 --format html      # Generate report
```

---

## Workflows

### Wildcard Scan (21 Steps)

```bash
chaathan wildcard -d target.com
```

| Phase | Steps | Tools | Output |
|-------|-------|-------|--------|
| **1 — Asset Discovery** | 1–5 | Subfinder, Assetfinder, Sublist3r, Amass, GitHub-subdomains, Uncover, Hakrawler | `all_subdomains.txt` |
| **2 — Validation** | 6–10 | DNSx, ShuffleDNS, Httpx, tlsx, Naabu | `live_hosts.txt` |
| **3 — Content Discovery** | 11–17 | Waybackurls, GAU, Katana, GoSpider, GoLinkFinder, Arjun, gf, ffuf | `all_urls_live.txt` |
| **4 — Vulnerability Scan** | 18–21 | Nuclei (infra + URLs), Subjack, Dalfox | DB findings |

<details>
<summary>Full step breakdown</summary>

| Step | Tool(s) | What It Does | Skip Flag |
|------|---------|-------------|-----------|
| 1 | Subfinder, Assetfinder, Sublist3r | Passive subdomain enumeration | — |
| 2 | Amass | Active DNS brute-force | `--skip-amass` |
| 3 | github-subdomains | GitHub scraping for subdomains | needs `--github-token` |
| 4 | Uncover | Shodan/Censys/Fofa passive dorking | `--skip-uncover` |
| 5 | Hakrawler | JavaScript crawling for subdomain & endpoint discovery | `--skip-subdomainizer` |
| 6 | DNSx | Consolidation + DNS resolution | — |
| 7 | ShuffleDNS/MassDNS | DNS brute-force with wordlist | `--skip-shuffledns` |
| 8 | Httpx | HTTP probing + tech detection | — |
| 9 | tlsx | TLS cert analysis + SAN extraction | `--skip-tlsx` |
| 10 | Naabu | Port scanning (all subdomains) | `--skip-naabu` |
| 11 | Waybackurls, GAU | Historical URL discovery | — |
| 12 | Katana, GoSpider | Web crawling | `--skip-crawl` |
| 13 | GoLinkFinder | JavaScript endpoint extraction | — |
| 14 | Arjun | HTTP parameter discovery | `--skip-arjun` |
| 15 | Httpx | URL consolidation + live check | — |
| 16 | Httpx, gf | JS file secret scan | — |
| 17 | ffuf | Directory fuzzing | needs `--wordlist` |
| 18 | Nuclei | Vuln scanning — infrastructure | `--skip-nuclei` |
| 19 | Nuclei | Vuln scanning — URLs | `--skip-nuclei` |
| 20 | Subjack | Subdomain takeover detection | `--skip-subjack` |
| 21 | Dalfox | XSS scanning on parameterized URLs | `--skip-dalfox` |

</details>

**Fast scan** (skip heavy tools):
```bash
chaathan wildcard -d target.com --skip-amass --skip-naabu --skip-nuclei
```

**Stealth scan** (avoid WAF detection):
```bash
chaathan wildcard -d target.com --proxy socks5://127.0.0.1:9050 --rate-limit 10
```

**Resume interrupted scan:**
```bash
chaathan wildcard -d target.com --resume <scan_id>
```

Press **`s`** during scanning to skip the current tool without aborting.

### Company Scan (3 Steps)

```bash
chaathan company -n "Company Inc"
```

| Step | Tool | What It Does | Skip Flag |
|------|------|-------------|-----------|
| 1 | Metabigor | ASN & network range discovery | `--skip-metabigor` |
| 2 | Amass Intel | Root domain discovery (reverse-whois) | `--skip-amass-intel` |
| 3 | Cloud Enum | Cloud infrastructure enumeration | `--skip-cloud-enum` |

---

## Commands

### Scanning

| Command | Description |
|---------|-------------|
| `chaathan wildcard -d <domain>` | 21-step domain recon workflow |
| `chaathan wildcard -d <domain> --proxy <url>` | Scan through a proxy |
| `chaathan wildcard -d <domain> --rate-limit <n>` | Cap all tools to N req/sec |
| `chaathan company -n <name>` | 3-step company discovery workflow |

### Data & Results

| Command | Description |
|---------|-------------|
| `chaathan status` | Dashboard — recent scans, progress, stats |
| `chaathan scans list` | List all past scans |
| `chaathan scans show <id>` | Scan details and statistics |
| `chaathan scans resume <id>` | Resume an interrupted scan |
| `chaathan scans delete <id>` | Delete a specific scan |
| `chaathan diff <id1> <id2>` | Compare two scans |

### Querying

| Command | Description |
|---------|-------------|
| `chaathan query subdomains <id>` | Query discovered subdomains |
| `chaathan query vulns <id>` | Query vulnerabilities |
| `chaathan query ports <id>` | Query open ports |
| `chaathan query urls <id>` | Query discovered URLs |
| `chaathan query endpoints <id>` | Query API endpoints |
| `chaathan query roi <id>` | Rank URLs by testing ROI |

### Reporting & Export

| Command | Description |
|---------|-------------|
| `chaathan report generate <id>` | Generate html/md/json report |
| `chaathan export <id>` | Export results to text files |

### Tooling & Config

| Command | Description |
|---------|-------------|
| `chaathan setup` | Install missing external tools |
| `chaathan setup --update` | Force-reinstall all tools to latest |
| `chaathan tools list` | List all 28 tools with categories |
| `chaathan tools check` | Check which tools are installed |
| `chaathan config show` | Show current configuration |
| `chaathan config edit` | Edit config in your editor |
| `chaathan config set <key> <val>` | Set a config value |
| `chaathan config reset` | Reset config to defaults |
| `chaathan config path` | Show config file path |

### Cleanup

| Command | Description |
|---------|-------------|
| `chaathan delete target <domain>` | Delete all data for a target |
| `chaathan delete scan <id>` | Delete a specific scan |
| `chaathan delete old <days>` | Delete scans older than N days |
| `chaathan delete list` | List scans available for deletion |

---

## Query Examples

```bash
# Subdomains
chaathan query subdomains 1 --live         # only live ones
chaathan query subdomains 1 --grep api     # filter by pattern
chaathan query subdomains 1 --json         # JSON output

# Vulnerabilities
chaathan query vulns 1 --severity critical

# ROI-ranked targets
chaathan query roi 1 --limit 10
chaathan query roi 1 --json -o roi.json

# Pipe to other tools
chaathan query subdomains 1 --live > live.txt
chaathan query urls 1 > urls_for_burp.txt
```

## Scan Diffing

```bash
chaathan diff 1 2
```

Shows new/removed subdomains, new open ports, new vulnerabilities with severity, and new URLs. Useful for continuous monitoring.

---

## Configuration

Config lives at `~/.chaathan/config.yaml`:

```bash
chaathan config edit                   # open in editor
chaathan config show                   # view current config
chaathan config set api_keys.github ghp_xxxxx
```

<details>
<summary>Full config reference</summary>

```yaml
general:
  max_retries: 1
  retry_delay_sec: 3
  mode: native
  concurrency: 5
  ua_rotation: false
  user_agent: ""
  proxy: ""

tools:
  subfinder:
    threads: 30
    timeout: 30
  naabu:
    threads: 25
    rate: 1000
    ports: "top-1000"
  nuclei:
    concurrency: 25
    rate_limit: 150
    severity: [low, medium, high, critical]
    exclude_tags: [dos, fuzz]
  httpx:
    threads: 50
    timeout: 10
    ports: ["80", "443", "8080", "8443"]

notifications:
  enabled: false
  step_complete: false
  min_severity: high
  discord_webhook: ""
  slack_webhook: ""
  telegram_bot_token: ""
  telegram_chat_id: ""
  webhook_url: ""
  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    username: ""
    password: ""
    from: ""
    to: ""

scope:
  in_scope: []
  out_of_scope: []
  exclude_ips: []
  allowed_ports: []

rate_limits:
  global_rps: 0   # ceiling across all tools; 0 = disabled
```

</details>

---

## Notifications

Get alerts on Discord/Slack/Telegram when critical findings are discovered:

```bash
chaathan config set notifications.enabled true
chaathan config set notifications.discord_webhook https://discord.com/api/webhooks/xxx/yyy
chaathan config set notifications.telegram_bot_token 12345:ABCDE
chaathan config set notifications.telegram_chat_id 987654321
chaathan config set notifications.min_severity high
```

Set `notifications.step_complete` to `true` for per-step notifications. Subdomain takeover findings trigger immediate alerts.

---

## WAF Evasion / Stealth Mode

All features are opt-in — disabled by default, zero behavior change unless enabled.

### User-Agent Rotation

Rotate using real browser UAs (Chrome, Firefox, Edge, Safari) instead of tool-identifiable strings:

```yaml
general:
  ua_rotation: true
```

Or set a fixed UA:
```yaml
general:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Proxy Support

```bash
chaathan wildcard -d target.com --proxy socks5://127.0.0.1:9050    # Tor
chaathan wildcard -d target.com --proxy http://127.0.0.1:8080       # Burp
```

Or permanently in config:
```yaml
general:
  proxy: "socks5://127.0.0.1:9050"
```

Proxy is injected into httpx, nuclei, katana, gospider, ffuf, dalfox, naabu, and the metadata collector. Arjun is skipped (no native proxy flag).

### Global Rate Limiting

```bash
chaathan wildcard -d target.com --rate-limit 10
```

Acts as a ceiling — if a tool's per-tool rate is already lower, it stays lower.

### Combined Stealth

```bash
chaathan wildcard -d target.com \
  --proxy socks5://127.0.0.1:9050 \
  --rate-limit 10
```

With `ua_rotation: true` in config: randomized browser UAs + rotating IPs via Tor + rate-limited traffic.

---

## Integrated Tools (28)

| Category | Tools |
|----------|-------|
| **Subdomain Discovery** | subfinder, assetfinder, sublist3r, amass |
| **DNS** | dnsx, shuffledns, massdns |
| **Web Probing** | httpx, tlsx, naabu |
| **URL Discovery** | waybackurls, gau, arjun |
| **Web Crawling** | katana, gospider |
| **JS Analysis** | GoLinkFinder, hakrawler |
| **Fuzzing** | ffuf |
| **Vuln Scanning** | nuclei, subjack, dalfox |
| **Passive Recon** | uncover, metabigor, github-subdomains |
| **Cloud** | cloud_enum |
| **Utility** | anew, gf |

```bash
chaathan tools check          # see what's installed
chaathan setup                # install missing tools
chaathan setup --update       # reinstall all tools (force update to latest)
```

---

## Output Structure

```
~/.chaathan/
├── config.yaml
├── chaathan.db                  # SQLite — all results
├── logs/
│   └── setup_2024-01-15.log     # Setup install logs
├── scans/
│   └── target.com/
│       ├── intermediate_files/  # Raw outputs from individual tools
│       ├── final_files/         # Consolidated product files
│       │   ├── nuclei_vulns.json
│       │   ├── gf_secrets_findings.txt
│       │   └── dalfox_xss.json
│       ├── SUMMARY.txt
│       └── REPORT.md
├── reports/
│   └── scan_1.md
└── state/
    └── scan_1.json              # for resume
```

---

## Continuous Monitoring

```bash
# Daily scan via cron
0 0 * * * /usr/local/bin/chaathan wildcard -d target.com

# Weekly diff to spot changes
chaathan diff <old_scan_id> <new_scan_id>

# Cleanup old data
0 0 * * 0 /usr/local/bin/chaathan delete old 7
```

---

## Project Structure

```
chaathan-flow/
├── main.go                    # Entry point
├── Makefile                   # Build, install, setup, test, vet
├── cli/                       # Cobra commands (13 files)
│   ├── root.go                # Global flags, version, init
│   ├── wildcard.go            # 21-step recon command
│   ├── company.go             # 3-step company command
│   ├── setup.go               # Tool installation
│   ├── scans.go               # Scan management
│   ├── query.go               # Result queries
│   ├── report.go              # Report generation
│   ├── export.go              # Text export
│   ├── delete.go              # Data cleanup
│   ├── diff.go                # Scan comparison
│   ├── status.go              # Dashboard
│   ├── config.go              # Config management
│   └── tools_cmd.go           # Tools list/check
├── pkg/
│   ├── wildcard_flow/         # 21-step workflow (4 phase files + helpers)
│   ├── company_flow/          # 3-step workflow (3 step files + flow)
│   ├── orchestrate/           # Signal handling, infra bootstrap
│   ├── database/              # SQLite persistence, queries, ROI ranking
│   ├── report/                # Report templates and multi-format export
│   ├── scan/                  # Scan state, resume, step definitions
│   ├── setup/                 # Tool installation (Go, Python, massdns, gf)
│   ├── tools/                 # Tool registry (28 tools) and wrappers
│   ├── runner/                # Command execution, retry, docker mode
│   ├── config/                # YAML config loading and defaults
│   ├── metadata/              # Host metadata collection
│   ├── scope/                 # Scope filtering
│   ├── notify/                # Discord, Slack, Telegram notifications
│   ├── logger/                # Styled terminal output, colors
│   ├── progress/              # Spinners and progress bars
│   ├── paths/                 # ~/.chaathan directory paths
│   └── utils/                 # File I/O, parsers, export, validation
```

## Makefile

```bash
make build          # build binary
make install        # build + install to /usr/local/bin
make setup          # build + install all tools
make clean          # remove build artifacts
make test           # run tests
make vet            # static analysis
make tools-check    # check installed tools
make all            # build + install + setup (one-stop)
```

---

## License

MIT

## Author

Built by [vishnu303](https://github.com/vishnu303) for the bug bounty community.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The author is not responsible for any misuse, damage, or illegal activities caused by usage of this tool. Use at your own risk.
