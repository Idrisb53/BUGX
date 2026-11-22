# Installation

[← README](../README.md) · **Installation** · [Configuration](CONFIGURATION.md) · [Usage](USAGE.md) · [Modules](MODULES.md) · [Architecture](ARCHITECTURE.md) · [Troubleshooting](TROUBLESHOOTING.md)

---

BUGX needs **Python 3.10 or newer** and Git. External security tools are
**optional**: each module works with whatever is installed and reports the rest
as *Missing* with an install hint. BUGX never installs anything by itself.

- [1. Kali Linux](#1-kali-linux)
- [2. Debian / Ubuntu](#2-debian--ubuntu)
- [3. Windows (PowerShell)](#3-windows-powershell)
- [4. Python extras](#4-python-extras)
- [5. External tools](#5-external-tools)
- [6. Playwright MCP (browser inspection)](#6-playwright-mcp-browser-inspection)
- [7. PDF reports](#7-pdf-reports)
- [8. Verify the installation](#8-verify-the-installation)
- [9. Updating and uninstalling](#9-updating-and-uninstalling)

---

## 1. Kali Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/Idrisb53/BUGX.git
cd BUGX

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[browser,dev]"

bugx doctor
```

Kali-specific notes:

- ProjectDiscovery httpx is packaged as **`httpx-toolkit`**. `/usr/bin/httpx` is
  the unrelated Python HTTP client. BUGX detects that binary and rejects it.
- Kali's `amass` wrapper calls `sudo` the first time to download libpostal data.
  BUGX never runs `sudo`, so Amass shows **Error** until you run this once
  yourself: `sudo libpostal_data download all /var/lib/libpostal`.

## 2. Debian / Ubuntu

Same as Kali. Make sure your Python is 3.10 or newer (`python3 --version`).
Ubuntu 22.04+ and Debian 12+ ship a recent enough version.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/Idrisb53/BUGX.git
cd BUGX
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[browser,dev]"
bugx doctor
```

Many security tools are not in the Debian/Ubuntu repositories. Use `go install`
or the upstream release binaries (see [§5](#5-external-tools)).

## 3. Windows (PowerShell)

```powershell
winget install --id Git.Git -e        # if Git is not installed
winget install --id Python.Python.3.12 -e

git clone https://github.com/Idrisb53/BUGX.git
cd BUGX
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[browser,dev]"
bugx doctor
```

- If activation is blocked, run
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
- Go-based tools: install Go, then use the same `go install …@latest` commands as
  on Linux. `%USERPROFILE%\go\bin` must be on `PATH`.
- Or download release `.zip` files and point BUGX at them in `config/bugx.yaml`:

  ```yaml
  tools:
    ffuf:
      path: C:\tools\ffuf\ffuf.exe
  ```

- **Not supported natively** (BUGX marks them *Unsupported OS*): Naabu, WhatWeb,
  testssl.sh, Kiterunner. Use WSL for those.

> Windows support has not been verified end to end. Linux is the primary
> platform.

## 4. Python extras

| Install command | Adds | Needed for |
|---|---|---|
| `pip install -e .` | typer, rich, pydantic, pyyaml, jinja2 | Everything except the browser integration |
| `pip install -e ".[browser]"` | `mcp>=1.0` | Playwright MCP browser inspection |
| `pip install -e ".[dev]"` | `pytest>=8`, `ruff` | Running tests / contributing |

`-e` (editable) keeps BUGX reading `config/` and writing `output/` inside your
checkout. For a non-editable install, set `BUGX_HOME` to the checkout
(see [Configuration](CONFIGURATION.md#environment-variables)).

## 5. External tools

Install only what you need. `bugx doctor` shows the current state.

### Kali (apt)

```bash
sudo apt install -y subfinder amass dnsx httpx-toolkit nmap naabu katana whatweb \
                    ffuf feroxbuster dirsearch nuclei nikto sqlmap wapiti testssl.sh \
                    hakrawler dalfox seclists
nuclei -update-templates
```

### Go-based tools (any OS with Go)

```bash
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest
go install github.com/sensepost/gowitness@latest
```

### Python / Node tools

```bash
pipx install arjun
pipx install semgrep
npm install -g retire
```

### Others

| Tool | Where |
|---|---|
| ParamSpider, LinkFinder, SecretFinder | Upstream GitHub repositories (Python scripts). Put them on `PATH` or set `tools.<name>.path` |
| Kiterunner (`kr`) | Upstream release binary + a routes file in `wordlists.api_routes` |
| OWASP ZAP baseline | Docker image. BUGX ships a wrapper: [`docs/examples/zap-baseline.py`](examples/zap-baseline.py) |
| Trivy | Upstream install script / package repository |

Wordlists: FFUF and Feroxbuster use the first file in `wordlists.directories`
that exists (SecLists / dirb defaults).

## 6. Playwright MCP (browser inspection)

*Optional.* BUGX launches the Playwright MCP server itself over stdio. You need:

1. `pip install -e ".[browser]"` (the MCP Python SDK)
2. Node.js 18+ with `npx` on `PATH`
3. A Chromium-based browser (Chromium, Chrome or Edge). BUGX auto-detects it, or
   you can set `playwright_mcp.executable_path` in `config/bugx.yaml`.

The server package is pinned to `@playwright/mcp@0.0.86`
(`playwright_mcp.command`). Check with `bugx doctor` → *BROWSER / PLAYWRIGHT MCP*.

## 7. PDF reports

PDFs are printed from the HTML report with a headless Chromium/Chrome/Edge.
Without a browser, Markdown, HTML and JSON are still written and the PDF entry
explains why it was skipped.

## 8. Verify the installation

```bash
bugx version                 # BUGX v1.2.0
bugx doctor                  # Python, dependencies, tools, config, browser
bugx scope-check www.example.com docs/examples/example-profile.yaml   # SCOPE CHECK PASSED
pytest -m "not e2e" -q       # requires the [dev] extra
```

## 9. Updating and uninstalling

```bash
git pull
pip install -e ".[browser,dev]"     # picks up dependency or version changes

pip uninstall bugx-cli              # uninstall the package
```

Your profiles (`config/programs/`) and results (`output/`) are local files and
are gitignored. Back them up before deleting the checkout.

---

Next: [Configuration →](CONFIGURATION.md)
