# Chaathan

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite)](https://sqlite.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux)](https://linux.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> **Chaathan** is an enterprise-grade, single-binary Go pentesting orchestration framework built for professional bug hunters and red teams. It automates high-performance multi-phase reconnaissance, stores results in a centralized SQLite database, tracks targets over time with stateful diffs, and fires real-time alerts on critical discoveries.

---

## ⚡ Core Capabilities

*   **Stateful 23-Step Wildcard Recon**: End-to-end domain discovery, HTTP probing, historical URL extraction, vulnerability auditing, and WAF fingerprinting.
*   **Stateful 3-Step Company Discovery**: Network ASN mappings, reverse-WHOIS root enumeration, and public cloud asset discovery.
*   **Universal WAF/CDN Origin Bypass**: Automatically maps WAF-shielded hosts, tests candidate origin IPs, and validates direct origin routing with browser-spoofed headers.
*   **Relational Intelligence**: Stores all assets, open ports, vulnerabilities, URLs, and API endpoints in a high-speed local SQLite database.
*   **Intelligent ROI Ranking**: Evaluates crawled endpoints to rank test targets by vulnerability density and potential ROI.
*   **Continuous Monitoring & Diffs**: Compare scans over time to immediately isolate new subdomains, ports, or vulnerabilities.
*   **Real-time Alerts**: Native webhook support for Discord, Slack, Telegram, and generic HTTP endpoints with automated subdomain takeover detection.

---

## 🎮 Consolidated Command Center

All commands in the Chaathan ecosystem—including installation, building, testing, scanning, querying, diffing, reporting, configuration, and scheduling—are consolidated in this single section. There are no scattered commands throughout the rest of the document.

### 1. Build & Installation (Makefile)

Run these targets from the root of the cloned repository directory to compile the binary and provision external engines.

```bash
# Clone the repository
git clone https://github.com/vishnu303/chaathan.git && cd chaathan

# Orchestration targets
make all            # Installs chaathan binary and provisions all 30 tools (Recommended)
make build          # Compiles the single chaathan binary in the local directory
make install        # Installs the compiled binary globally to /usr/local/bin
make setup          # Provisions and compiles all 30 third-party tools
make test           # Executes the Go unit test suite
make vet            # Performs static analysis and code verification
make clean          # Cleans up local compilation and build artifacts
```

### 2. Reconnaissance & Scanning

| Purpose | Command |
| :--- | :--- |
| **Standard Scan** | `chaathan wildcard -d target.com` |
| **Fast Scan** *(Skip heavy DNS/vuln/port scans)* | `chaathan wildcard -d target.com --skip-amass --skip-naabu --skip-nuclei` |
| **Stealth Scan** *(Proxy + Rate limit)* | `chaathan wildcard -d target.com --proxy socks5://127.0.0.1:9050 --rate-limit 10` |
| **Auto-Proxy Scan** *(Free rotating proxies)* | `chaathan wildcard -d target.com --auto-proxy` |
| **Auto-Proxy + Stealth** | `chaathan wildcard -d target.com --auto-proxy --rate-limit 10` |
| **Stateful Resume** | `chaathan wildcard -d target.com --resume <scan_id>` |
| **Session-Authenticated Scan** | `chaathan wildcard -d target.com --cookie "PHPSESSID=abc; auth=1" -H "X-Client: Pro" --token "jwt_value"` |
| **Origin IP Bypass Scan** | `chaathan wildcard -d target.com --origin-bypass` |
| **Execution Logging** | `chaathan wildcard -d target.com --log` |
| **Company Discovery** | `chaathan company -n "Acme Corporation"` |
| **Company Discovery** *(Fast)* | `chaathan company -n "Acme Corporation" --skip-metabigor` |

### 3. Database Queries & Filtering

Extract and pivot relational reconnaissance datasets directly from the local SQLite database.

```bash
# Subdomain queries
chaathan query subdomains 1 --live          # Filter for live HTTP assets only
chaathan query subdomains 1 --grep api      # Filter subdomains containing 'api'
chaathan query subdomains 1 --json          # Output in clean JSON format
chaathan query subdomains 1 --live > live.txt # Pipe live subdomains to a text file

# Vulnerabilities, Ports, & Endpoints
chaathan query vulns 1 --severity critical  # Filter vulnerabilities by severity level
chaathan query ports 1                      # List all discovered open ports
chaathan query urls 1                       # List all historical and crawled URL paths
chaathan query urls 1 > urls_for_burp.txt   # Export all discovered URLs for external proxies
chaathan query endpoints 1                  # List resolved REST/GraphQL API endpoints

# Attack Surface Analysis
chaathan query roi 1 --limit 10             # Rank high-value web targets by estimated ROI
chaathan query roi 1 --json -o roi.json     # Export high-ROI assets directly to JSON
chaathan diff 1 2                           # Isolate differences (new subdomains, open ports, vulns) between two scans
```

### 4. Telemetry & Environment Control

Manage running scans, configure system options, clean up old records, and verify tool health.

```bash
# Dashboard & Telemetry
chaathan status                             # Show interactive dashboard of active and historical runs
chaathan scans list                         # List database scan history and run metadata
chaathan scans show <id>                    # Inspect detailed runtime metrics for a specific scan
chaathan scans resume <id>                  # Resume a suspended or interrupted scan from the database
chaathan scans delete <id>                  # Delete metadata and tables for a single scan ID

# Data Cleanups
chaathan delete target target.com           # Completely purge all database entries for a target domain
chaathan delete old 30                      # Delete all database runs and assets older than 30 days
chaathan delete list                        # Catalog and list all scans flagged as eligible for deletion

# Tooling Checks & Provisioning
chaathan setup                              # Install missing external third-party dependencies
chaathan setup --update                     # Force rebuild and update all 30 third-party tools to latest
chaathan tools list                         # Show categorization list of all 30 integrated engines
chaathan tools check                        # Perform disk audits and check binary paths for all tools
```

### 5. Config Management

```bash
chaathan config path                        # Display filepath to local config.yaml
chaathan config show                        # Print compiled configuration schema currently loaded
chaathan config edit                        # Open config.yaml in the system default CLI text editor
chaathan config set api_keys.github ghp_xx  # Programmatically write GitHub token for subdomains
chaathan config set notifications.enabled true # Programmatically enable notification dispatchers
chaathan config reset                       # Overwrite config.yaml back to system defaults
```

### 6. Reports & Text File Exports

```bash
chaathan report generate 1 --format html    # Output an interactive HTML/Markdown report of scan assets
chaathan export 1                           # Dump raw text asset files from database to the workspace directory
```

### 7. Continuous Automation (System Cron)

Integrate these system scheduler triggers directly into your crontab environment for continuous surveillance.

```bash
# Quiet, bandwidth-controlled daily scan at midnight
0 0 * * * /usr/local/bin/chaathan wildcard -d target.com --rate-limit 5

# Compare latest scan states automatically every Sunday
chaathan diff <previous_id> <latest_id>

# Run a weekly database prune to clean out data older than 7 days
0 0 * * 0 /usr/local/bin/chaathan delete old 7
```

---

## 📦 System Provisioning & Requirements

Chaathan is packaged as a single static binary. It acts as an orchestration engine, launching and managing 30 third-party security utilities.

> [!IMPORTANT]  
> **Host Requirements:** Linux operating system (tested extensively on Ubuntu, Arch, and CachyOS). Go 1.21 or greater and Git must be pre-installed on the host system.
> All external scanning engines (such as Amass, Nuclei, Httpx, Dalfox) are dynamically compiled and verified during the `make all` bootstrap process (syntax detailed in the Command Center).

---

## 🌪️ Reconnaissance Pipelines

Chaathan orchestrates complex multi-stage recon chains, consolidating raw outputs into optimized files and structured SQLite database schemas.

### A. Wildcard Workflow (23 Steps)
```
[Proxy Scraping] ──> [Asset Discovery] ──> [DNS & Port Validation] ──> [Content crawling] ──> [Vulnerability Audits] ──> [WAF Fingerprints]
```

| Phase | Steps | Key Tools Used | Central Artifact Generated |
| :--- | :--- | :--- | :--- |
| **Phase 0: Proxy Scraping** | 1 | `mubeng` | `proxy_pool.txt` + rotating proxy server |
| **Phase 1: Asset Discovery** | 2–6 | `subfinder`, `assetfinder`, `amass`, `uncover`, `github-subdomains` | `all_subdomains.txt` |
| **Phase 2: Validation** | 7–11 | `dnsx`, `shuffledns`, `httpx`, `tlsx`, `naabu` | `live_hosts.txt` |
| **Phase 3: Content Discovery** | 12–18 | `katana`, `gospider`, `waybackurls`, `gau`, `GoLinkFinder`, `arjun`, `ffuf` | `all_urls_live.txt` |
| **Phase 4: Vulnerability Scan** | 19–22 | `nuclei` (smart CVE + DAST rules), `dalfox` (targeted XSS scanning) | Saved to SQLite (`vulnerabilities` table) |
| **Phase 5: Fingerprinting** | 23 | `httpx`, `nuclei` | `tech_fingerprint.json` |

<details>
<summary>🔍 Expand Detailed 23-Step Pipeline Spec</summary>

| Step | Engine | Purpose / Action | Skip Trigger Flag |
| :--- | :--- | :--- | :--- |
| 1 | `mubeng` | Auto-scrape free proxies, validate against target, start rotating proxy | `--auto-proxy` to enable |
| 2 | `subfinder`, `assetfinder`, `sublist3r` | Passive domain enumeration | - |
| 3 | `amass` | High-depth active DNS brute-forcing | `--skip-amass` |
| 4 | `github-subdomains` | Scraping Github public repos for references | Needs `--github-token` |
| 5 | `uncover` | Passive search engine dorking (Shodan, FOFA) | `--skip-uncover` |
| 6 | `hakrawler` | Extracting assets hidden in JS modules | `--skip-hakrawler` |
| 7 | `dnsx` | Subdomain validation & initial DNS filtering | - |
| 8 | `shuffledns` | Active DNS wild-card filtering and resolution | `--skip-shuffledns` |
| 9 | `httpx` | Live web application probing and tech fingerprinting | - |
| 10 | `tlsx` | SSL/TLS certificate analysis & SAN mining | `--skip-tlsx` |
| 11 | `naabu` | Multi-port validation scanning across discoveries | `--skip-naabu` |
| 12 | `waybackurls`, `gau` | Querying historical web archives for endpoints | - |
| 13 | `katana`, `gospider` | Dynamic web spiders crawling client assets | `--skip-crawl` |
| 14 | `GoLinkFinder` | Analyzing static and dynamic JS scripts for URLs | - |
| 15 | `arjun` | Query parameter and hidden field discovery | `--skip-arjun` |
| 16 | `httpx` | Live verification of extracted discovery links | - |
| 17 | `httpx`, `gf` | Scanning JS packages for high-risk hardcoded secrets | - |
| 18 | `ffuf` | Focused path discovery using wordlists | Needs `--wordlist` |
| 19 | `nuclei` | General infra misconfiguration & public CVE auditing | `--skip-nuclei` |
| 20 | `nuclei` | Dynamic application testing (DAST) payload fuzzing | `--skip-nuclei` |
| 21 | `nuclei (takeovers)` | Proactive subdomain takeover analysis | `--skip-takeovers` |
| 22 | `dalfox` | High-efficiency parameterized cross-site scripting (XSS) audit | `--skip-dalfox` |
| 23 | `httpx`, `nuclei` | Direct technology classification & WAF identification | `--skip-fingerprint` |

</details>

### B. Company Discovery Workflow (3 Steps)
Automates target profiling and corporate footprinting before launching active domain tests.

| Step | Utility | Scope of Action | Skip Trigger Flag |
| :--- | :--- | :--- | :--- |
| **1** | `metabigor` | Discovers network ranges, ASN prefixes, and routing tables | `--skip-metabigor` |
| **2** | `amass intel` | Performs reverse WHOIS lookups to discover root domain registrations | `--skip-amass-intel` |
| **3** | `cloud_enum` | Audits public cloud storage infrastructure (AWS, GCP, Azure) | `--skip-cloud-enum` |

---

## 🛡️ Enterprise Stealth & WAF Bypass Playbook

Chaathan is designed to traverse hostile, firewalled networks. It includes granular controls for request personalization, proxy routing, and firewall evasion. Detailed CLI flag invocations are cataloged inside the **Consolidated Command Center** under *Reconnaissance & Scanning*.

### 🔑 Authenticated State Auditing
Allows you to audit deeply nested authenticated application zones (private APIs, parameterized endpoints, gated directories). You can feed complex session cookies (`--cookie`), customized request headers (`-H`), and shorthand OAuth authorization tokens (`--token`) directly into Chaathan. The engine transparently parses these structures and cascades them down to sub-executables like `httpx`, `katana`, `nuclei`, and `dalfox`.

### 🛰️ WAF & CDN Origin IP Bypass
Modern web applications sit behind front-end shields like Cloudflare, Akamai, and AWS CloudFront. By specifying the `--origin-bypass` switch, Chaathan actively attempts to bypass these filters:
1. **Host Mapping:** Compiles all subdomains currently resolving to known CDN/WAF IP ranges.
2. **Origin Discovery:** Extracts candidate non-WAF backend IP addresses discovered during the earlier stages of the scan.
3. **Validation Probes:** Performs rapid concurrent TLS handshake probes directly against candidate origin IPs while spoofing the target domain's `Host` header, validating if the origin serves unshielded data.
4. **Relational Tracking:** Automatically stores any validated edge bypasses in the SQLite database and triggers real-time alerts.

### 🕴️ Complete Anonymization & Routing
- **User-Agent Rotation:** Enabled natively by default (`ua_rotation: true` in config). Chaathan dynamically swaps standard command-line user-agent headers for authentic, rotating desktop and mobile browser signatures (Chrome, Firefox, Safari) on every request, evading signature-based blocking.
- **Proxy Cascading:** Pipe all underlying scanning traffic through an external gateway. Pass SOCKS5 (e.g., Tor) or HTTP (e.g., Burp Suite) configurations to route execution, audit logs, or debugging sessions.
- **Automated Proxy Rotation (`--auto-proxy`):** Automatically scrapes and validates free proxies from public sources against the target domain, then starts `mubeng` as a local rotating proxy server. Every outgoing request from every tool uses a different exit IP address — no manual proxy configuration needed. Dead proxies are automatically removed from the pool.

---

## 🛠️ Architecture & Development Patterns

Following a comprehensive package refactor, the `cli` package has been optimized to adhere to the highest Go development standards and clean coding principles:

*   **Thin CLI Pattern**: Command handlers in `cli/` focus exclusively on argument parsing, flag binding, and user-facing terminal presentation, delegating all scanning, database, and reporting workflows to dedicated packages under `pkg/`.
*   **Centralized Helpers (`cli/helpers.go`)**: Repetitive validations, custom parsing (e.g., scan ID and age parameters), rotating configuration overrides, and path resolutions are unified inside a dedicated helpers module to avoid code duplication.
*   **Deterministic Output & UX**: Key-value settings output (like `config set` errors) are systematically grouped and sorted using the Go `"sort"` package to guarantee stable, predictable, and clean terminal displays.
*   **Unified Serialization**: A single `writeJSONOrPrint` routine standardizes JSON output formatting and file-writing across all database query subcommands.

*   **Decoupled & Standardized Utility Packages**: Core utility packages (`pkg/paths`, `pkg/config`, `pkg/scope`, `pkg/logger`, and `pkg/progress`) have been refactored for maximum decoupling:
    *   **Environment-Aware Configuration & Paths**: `pkg/paths` supports environment overrides (e.g. `CHAATHAN_HOME`) allowing isolated testing configurations, and `pkg/config` maps API keys efficiently to environment variable lookups.
    *   **Unified Terminal Styling**: Progress indicators in `pkg/progress` reuse consolidated ANSI color structures and duration formatting from `pkg/logger` to avoid duplication.
    *   **High-Performance File Logging**: The logging system performs ANSI regex cleaning and timestamping outside critical mutex locks to drastically reduce lock contention and thread synchronization overhead.
    *   **Simplified Scope Validation**: Duplicate filtering checks and regular expression compilation have been refactored into centralized package helpers within `pkg/scope`.

*   **DRY & Robust Execution & Bootstrapping**: Execution-related modules (`pkg/runner`, `pkg/tools`, `pkg/setup`, `pkg/update`, and `pkg/orchestrate`) have been optimized for logic consolidation:
    *   **Unified Command Runner**: Common timeout context setup and retry loops in `pkg/runner` are abstracted into a single, context-aware retry helper shared by both Native and Docker run methods.
    *   **Consolidated Arguments Building**: Tool arguments preparation (proxy configuration, custom headers/cookies, and browser-like user agents) is unified into a single configuration-driven helper `appendCommon` in `pkg/tools`, avoiding code replication across 20+ tool wrappers.
    *   **Unified System Paths**: Shared GOPATH resolutions and file-check validations have been consolidated in `pkg/setup` to keep tool installation dry.
    *   **Standardized SemVer Rules**: The self-update system utilizes robust SemVer check comparisons and standard loop forms to verify upgrades.
*   **Workflow Orchestration & State Management (`pkg/wildcard_flow/`)**:
    *   **Step Entry/Exit Standardization**: Unified state validation and terminal instrumentation through `resumeOrSkip(stepName, stepHeader)` and `markStepCompleteIfNoFailure(stepName)` helpers, preventing invalid state transitions (such as marking steps complete when pre-conditions or executions fail).
    *   **Resource-Efficient Stream-Based I/O**: High-performance file operations (like `copyFile`) refactored to use `io.Copy` stream pipelines instead of reading entire files into memory, guaranteeing $O(1)$ memory complexity even during massive reconnaissance runs.

---

## 💡 Demonstrated Development Skills

This codebase showcases a range of advanced Go engineering and system-level programming skills:
*   **Go Concurrency & Coordination**: Safe management of background workers, rotating proxies, and parallel probes using context propagation, channel orchestration, and wait group controls.
*   **Structured State Machine Management**: Strict validation of workflow progress and recovery. Relies on structured SQLite persistence for step-by-step resume support, enabling execution interruption and restart without target re-scanning.
*   **Low-Memory High-Throughput I/O**: Stream pipelines using reader/writer interfaces (`io.Reader`/`io.Writer`) to handle vast lists of subdomains and URLs without memory exhaustion.
*   **Factory-Driven Tool Registry**: A clean, unified interface for invoking and configuring 30+ external binaries dynamically based on global runtime flags, network proxies, and target scopes.

---

## ⚖️ Legal & Disclaimer

**Disclaimer:** This utility is designed strictly for authorized penetration testing, vulnerability assessment, and approved bug bounty participation. The author assumes absolutely zero liability for unauthorized exploitation, service degradation, or system misuse. Ensure explicit written consent is secured before directing high-volume testing assets at external target nodes.

**License:** MIT License. Developed by [vishnu303](https://github.com/vishnu303).
