# Modules

[← README](../README.md) · [Installation](INSTALLATION.md) · [Configuration](CONFIGURATION.md) · [Usage](USAGE.md) · **Modules** · [Architecture](ARCHITECTURE.md) · [Troubleshooting](TROUBLESHOOTING.md)

---

- [Common execution path](#common-execution-path)
- [1. Reconnaissance](#1-reconnaissance)
- [2. Enumeration](#2-enumeration)
- [3. Vulnerability Analysis](#3-vulnerability-analysis)
- [4. Safe Validation](#4-safe-validation)
- [5. Report Generator](#5-report-generator)
- [6. System Health](#6-system-health)
- [Findings model](#findings-model)
- [Verification status](#verification-status)

---

## Common execution path

Every external tool in every module goes through the same engine
(`core/adapters.py → run_adapter`):

1. Session authorization (profile flags + typed `YES` this session)
2. OS support → tool found → version detected → required config present
   (otherwise *Unsupported OS / Missing / Error / Not Configured*)
3. Program request policy (required headers supported? scanners allowed?)
4. Explicit confirmation (`YES`. Every run for intrusive tools)
5. Scope Engine on **every** input target. Blocked targets are never passed to the tool
6. Execution: `shell=False`, stdin closed, timeout, working directory = evidence folder
7. Output parsed and deduplicated. Every discovered asset is classified (in / out / unverified)
8. Findings saved as *Needs Review*. The scan record is saved as JSON

Binary paths and timeouts can be overridden per tool in `config/bugx.yaml`
(`tools.<name>.path`, `tools.<name>.timeout`).

**Missing tools never crash BUGX.** They are listed with an install hint, and
BUGX never installs anything.

---

## 1. Reconnaissance

**Purpose:** map the attack surface: subdomains, DNS, live HTTP services, open
ports, technologies, TLS names and cloud assets.

**Execute:** Control Center → `1`, pick a tool. Non-interactive passive
Subfinder: `bugx recon DOMAIN PROFILE`.

**Output:** `output/recon/<program_id>/<scan_id>_<tool>.json` + raw output in
`output/evidence/<program_id>/<scan_id>/`.

| # | Tool | Binary | Safe settings used by BUGX | Notes |
|---|---|---|---|---|
| 1 | Subfinder | `subfinder` | `-d <domain> -silent -oJ -rl <rate>` | Passive, no target traffic |
| 2 | Amass | `amass` | `enum -passive -d <domain> -timeout 15` | Passive. Kali wrapper needs libpostal data once ([Installation](INSTALLATION.md#1-kali-linux)) |
| 3 | dnsx | `dnsx` | `-json -a -aaaa -cname -resp -rl -t`, hosts via stdin | CNAME targets become new (classified) hosts |
| 4 | httpx | `httpx-toolkit`, `httpx` | `-json -sc -title -td -server -ct -rl -t -H`, no redirect following | The Python `httpx` client is rejected. Redirect `Location` is re-checked |
| 5 | Nmap | `nmap` | `-sT -Pn -sV --version-light --top-ports 100 -T3 --max-rate` | No NSE scripts, no OS detection, no SYN scan |
| 6 | Naabu | `naabu` | `-top-ports 100 -scan-type c -json -rate -c` | Linux/macOS only |
| 7 | Katana | `katana` | `-jsonl -d 2 -fs fqdn -rl -c -H` | Never leaves the exact host |
| 8 | WhatWeb | `whatweb` | `-a 1 --log-json --header -U` | One request per URL. Linux/macOS only |
| 9 | tlsx | `tlsx` | `-json -san -cn -tv -ex -ss -mm` | SAN names become classified hosts |
| 10 | Cloudlist | `cloudlist` | `-json [-pc config]` | Lists **your own** cloud accounts. *Not Configured* without `~/.config/cloudlist/provider-config.yaml` |

**Limitations:** Subfinder/Amass quality depends on their own provider API keys
(configured in those tools, not BUGX). Discovered hosts are **never**
auto-authorized: subdomains of an `exact` asset are *unverified* unless the
profile has a matching wildcard.

---

## 2. Enumeration

**Purpose:** discover content, parameters, API routes, JavaScript endpoints and
secrets on in-scope hosts.

**Execute:** Control Center → `2`.

**Output:** `output/enumeration/<program_id>/…`, evidence folder, plus
`inventory` / collected JS for the built-ins.

| # | Tool | Binary | Safe settings | Notes |
|---|---|---|---|---|
| 1 | FFUF | `ffuf` | `-u <url>/FUZZ -w <list> -json -rate -t -maxtime 1500 -mc 200,204,301,302,307,401,403,405 -H` | Needs `wordlists.directories` |
| 2 | Feroxbuster | `feroxbuster` | `--silent --json --no-state -d 2 --rate-limit -t --time-limit 25m -H -a` | Needs a wordlist |
| 3 | Dirsearch | `dirsearch` | `--format json -o --max-rate -t -H --user-agent` | Built-in wordlist |
| 4 | Arjun | `arjun` | `-oJ -m GET --rate-limit -t --headers` | GET parameter discovery |
| 5 | ParamSpider | `paramspider` | `-d <domain> -s` | Archive data only, no target traffic |
| 6 | Kiterunner | `kr` | `scan <url> -w <routes> -o json -x <conc> -j 1 -H` | Needs `wordlists.api_routes` (*Not Configured* otherwise). Linux/macOS |
| 7 | LinkFinder | `linkfinder` | `-i <url> -o cli` | No header option → **blocked** when the profile requires headers |
| 8 | SecretFinder | `secretfinder` / `SecretFinder.py` | `-i <url> -o cli` | Values **redacted** before storage. No header option → blocked when headers are required |
| 9 | Hakrawler | `hakrawler` | stdin URL, `-d 2 -u -t -timeout 10 -h "H1;;H2"` | Same host only |
| 10 | GoWitness | `gowitness` | v3: `scan single --url --screenshot-path --chrome-header`. v2: `single -P` | Needs Chrome/Chromium |

### Built-in extras (no external tool)

| # | Feature | What it does | Safety |
|---|---|---|---|
| 11 | Endpoint inventory | Merges saved results into one list. Tags login, registration, password reset, API, GraphQL, JS, admin, upload and parameter endpoints | Offline (reads saved JSON only) |
| 12 | Collect JavaScript | Downloads in-scope `.js` files for Retire.js or manual review | Scope-checked per URL and redirect. Policy headers, rate limit, 5 MB cap |
| 13 | Browser inspection | Playwright MCP: title, final URL, links (classified), form controls, console errors, screenshot | Allow-listed MCP tools only. Never fills or submits forms or runs JS. Scope-checked preflight + final URL check |

**Requirements for 13:** `pip install -e ".[browser]"`, Node.js 18+ (`npx`), and
Chromium/Chrome/Edge. See [Installation §6](INSTALLATION.md#6-playwright-mcp-browser-inspection).

---

## 3. Vulnerability Analysis

**Purpose:** find **candidate** vulnerabilities. Nothing here is proof. Every
result goes to Safe Validation as *Needs Review*.

**Execute:** Control Center → `3`. Network scanners show an **ACTIVE
VULNERABILITY SCAN** panel and need a typed `YES` **every run**. They are
**blocked** when the profile has `automated_scanning: false`.

**Output:** `output/vulnerability_analysis/<program_id>/…`, findings in
`output/findings/<program_id>/findings.json`.

| # | Tool | Binary | Safe settings | Notes |
|---|---|---|---|---|
| 1 | Nuclei | `nuclei` | `-jsonl -duc -ni -rl -c -tags/-t <selected> -etags dos,fuzz,intrusive,bruteforce,… -H` | Template set must be selected in `nuclei:`. Run `nuclei -update-templates` once |
| 2 | OWASP ZAP | `zap-baseline.py` | `-t <url> -J zap_report.json -m 2 -I`, headers via ZAP replacer `-z` | Baseline = spider + passive rules only. Docker wrapper: [examples/zap-baseline.py](examples/zap-baseline.py) |
| 3 | Nikto | `nikto` | `-Format json -Tuning x6 -maxtime 30m -nointeractive -ask no` | DoS tests excluded. No custom-header option → blocked when headers are required |
| 4 | testssl.sh | `testssl.sh` / `testssl` | `--quiet --color 0 --warnings batch --jsonfile --reqheader host:port` | Only LOW+ severities become findings. Linux/macOS |
| 5 | Dalfox | `dalfox` | `url <url> --format json --skip-bav --delay -w -H` | Needs URLs with parameters |
| 6 | SQLmap | `sqlmap` | `--batch --level=1 --risk=1 --technique=BEU --threads=1 --delay` | **Detection only.** `--dump`, `--dbs`, `--os-*`, `--file-*`, `--forms`, `--crawl`, risk>1, level>2, time-based/stacked techniques are **rejected in code** |
| 7 | Wapiti | `wapiti` | `-m xss,sql,crlf,redirect,csrf,methods,ssl,wapp,cms -l 1 --scope folder --max-scan-time 1800` | Excludes brute force, buster, upload, exec, file, permanentxss, ssrf, timesql |
| 8 | Retire.js | `retire` | `--path <dir> --outputformat json` | Local files (e.g. the collected JS folder). No target traffic |
| 9 | Trivy | `trivy` | `fs --scanners vuln --format json` | Local source tree you are authorized to analyse |
| 10 | Semgrep | `semgrep` | `scan --config p/security-audit --json --metrics=off` | Local source tree. Config in `semgrep.config` |

**Limitations:** scanners produce false positives. Scanner confidence is capped
at *Medium*. Template/rule coverage depends on the tool versions you install.

---

## 4. Safe Validation

**Purpose:** turn scanner leads into confirmed or rejected findings **by hand**.

**Execute:** Control Center → `4`, pick a finding.

| Action | Behaviour |
|---|---|
| Details + scope re-check | Shows the finding and re-classifies its URL against the current profile |
| Safe validation procedure | Category-specific manual steps |
| `[1]` Safe replay | **One GET request**, scope-checked, policy headers, confirmation required. Redirects followed only if in scope |
| `[2]` Set status | *Needs Review, Potential, Validated, False Positive, Not Reproducible*. *Validated* requires a note or evidence |
| `[3]` Reproduction steps / impact | Stored on the finding, used in reports |
| `[4]` CVSS | Vector + score. Stored only when you provide it |

**Output:** `output/validation/<program_id>/<finding_id>_<timestamp>.json`
(append-only history) + the updated findings index.

**Safety:** no payloads, no state-changing requests, no automatic promotion to
*Validated*.

---

## 5. Report Generator

**Purpose:** build a report from saved scans and findings at any time.

**Execute:** Control Center → `5`, or `bugx report PROFILE [--formats …] [--validated-only]`.

| Option | Output |
|---|---|
| Full report | All findings except False Positive / Not Reproducible |
| Validated only | Only *Validated* findings |
| Formats | `markdown`, `html`, `json`, `pdf` (default: all four) |

**Output:** `output/reports/<program_id>/bugx_report_<timestamp>.{md,html,json,pdf}`.
Contents: program and authorization, scope, attack surface, per-module results,
tools used, findings with severity/confidence/OWASP mapping, methodology and
limitations.

**Requirements:** PDF needs Chromium/Chrome/Edge. Without one, PDF is skipped
with a reason. **Safety:** all scanner text is autoescaped in HTML.

---

## 6. System Health

`bugx doctor` or Control Center → `6`: OS, Python version, Python dependencies,
BUGX version, `config/bugx.yaml` validity, program profiles, output directory
permissions, Playwright MCP client and browser, and every tool's status and
version.

---

## Findings model

| Field | Values |
|---|---|
| Severity | Critical, High, Medium, Low, Informational |
| Confidence | High, Medium, Low, Tentative (scanner output ≤ Medium. *High* only after validation) |
| Validation status | Needs Review (default), Potential, Validated, False Positive, Not Reproducible |
| Mapping | OWASP Top 10 2021 and OWASP API Top 10 2023, by category |
| CVSS | Only when you enter a vector during validation |

---

## Verification status

| Level | Tools |
|---|---|
| **Run end to end against real binaries** (localhost mock target, `pytest -m e2e`) | httpx-toolkit 1.9.0, Katana 1.7.0, FFUF 2.1.0-dev, Feroxbuster 2.13.1, WhatWeb 0.6.4, Nmap 7.991, Nuclei 3.8.0, SQLmap 1.10.6, Playwright MCP 0.0.86 + Chromium |
| **Unit-tested only** (command construction + parser on sample output) | Subfinder, Amass, dnsx, Naabu, tlsx, Cloudlist, Dirsearch, Arjun, ParamSpider, Kiterunner, LinkFinder, SecretFinder, Hakrawler, GoWitness, OWASP ZAP, Nikto, testssl.sh, Dalfox, Wapiti, Retire.js, Trivy, Semgrep |

If a unit-tested-only adapter misbehaves with your tool version, please open an
issue with `bugx doctor` output and the tool's version.

---

Next: [Architecture →](ARCHITECTURE.md)
