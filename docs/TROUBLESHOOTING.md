# Troubleshooting

[← README](../README.md) · [Installation](INSTALLATION.md) · [Configuration](CONFIGURATION.md) · [Usage](USAGE.md) · [Modules](MODULES.md) · [Architecture](ARCHITECTURE.md) · **Troubleshooting**

---

Start with **`bugx doctor`**. It checks Python, dependencies, config, profiles,
output permissions, the browser and every tool.

- [Python and dependency errors](#python-and-dependency-errors)
- [CLI startup errors](#cli-startup-errors)
- [Missing or broken external tools](#missing-or-broken-external-tools)
- [Permission errors](#permission-errors)
- [Invalid program configuration](#invalid-program-configuration)
- [Scope validation failures](#scope-validation-failures)
- [Tools blocked by policy](#tools-blocked-by-policy)
- [Playwright / browser issues](#playwright--browser-issues)
- [Windows / Linux compatibility](#windows--linux-compatibility)
- [Reporting a bug](#reporting-a-bug)

---

## Python and dependency errors

| Symptom | Cause | Fix |
|---|---|---|
| `ERROR: Package 'bugx-cli' requires a different Python` | Python < 3.10 | Install Python 3.10+ and recreate the venv |
| `ModuleNotFoundError: No module named 'typer'` (or rich, yaml, jinja2) | Dependencies not installed in the active environment | `source .venv/bin/activate && pip install -e .` |
| `error: externally-managed-environment` (Kali/Debian/Ubuntu) | Installing into the system Python | Use a venv: `python3 -m venv .venv && source .venv/bin/activate` |
| `ModuleNotFoundError: No module named 'mcp'` | Browser extra not installed | `pip install -e ".[browser]"`. Only needed for browser inspection |
| `pytest: command not found` | Dev extra not installed | `pip install -e ".[dev]"` |
| `bugx version` shows an old version / `pip show bugx-cli` shows `0.1.0` | Stale editable-install metadata | `pip install -e .` again |

## CLI startup errors

| Symptom | Fix |
|---|---|
| `bugx: command not found` | Activate the venv. Or run `python -m bugx` |
| A Windows `.venv` copied to Linux (`.venv/Scripts/…`) | Venvs are not portable. Delete it and create a new one on Linux |
| Garbled colours / box characters | Use a UTF-8 terminal with 256 colours (Windows Terminal, not legacy `cmd.exe`) |
| Interactive prompts misbehave when piped | The workflow is interactive. Use `scope-check`, `report`, `history` or `recon` for scripts |

## Missing or broken external tools

| Status in BUGX | Meaning | Fix |
|---|---|---|
| **MISSING** | Binary not found on `PATH` | Install it, or set `tools.<name>.path` in `config/bugx.yaml` |
| **ERROR** | Found, but the version check failed or the binary is the wrong program | Run the tool's version command yourself and see below |
| **NOT CONFIGURED** | Tool needs a config/wordlist BUGX can't find | Set it in `config/bugx.yaml` (see [Configuration](CONFIGURATION.md)) |
| **UNSUPPORTED OS** | Tool is Linux/macOS only | Use Linux or WSL |

Known cases:

- **httpx shows ERROR on Kali.** `/usr/bin/httpx` is the Python HTTP client. Fix:
  `sudo apt install httpx-toolkit`.
- **Amass shows ERROR on Kali.** The wrapper wants to `sudo`-download libpostal
  data. Fix: `sudo libpostal_data download all /var/lib/libpostal` once.
- **FFUF / Feroxbuster NOT CONFIGURED.** No wordlist found. Fix:
  `sudo apt install seclists` or set `wordlists.directories`.
- **Kiterunner NOT CONFIGURED.** Set `wordlists.api_routes` to a `.kite`/`.txt` routes file.
- **Cloudlist NOT CONFIGURED.** Create `~/.config/cloudlist/provider-config.yaml`
  (your own cloud credentials, in Cloudlist's config, never in BUGX).
- **Nuclei finds nothing.** Run `nuclei -update-templates` once. Check `nuclei.tags` / `nuclei.templates`.
- **Go tools not found after `go install`.** Add `~/go/bin` (Linux) or
  `%USERPROFILE%\go\bin` (Windows) to `PATH`.

## Permission errors

| Symptom | Fix |
|---|---|
| `PermissionError` writing to `output/` | `bugx doctor` → *Output*. Make sure you own the directory (`sudo chown -R $USER output`) or set `BUGX_OUTPUT_DIR` to a writable path |
| Files under `output/` owned by root | You ran BUGX with `sudo` earlier. Don't. BUGX never needs root (Nmap uses `-sT` connect scans) |
| `Activate.ps1 cannot be loaded` (Windows) | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |

## Invalid program configuration

| Message | Fix |
|---|---|
| `Programs directory not found` | BUGX can't locate `config/`. Run from the checkout with an editable install, or `export BUGX_HOME=/path/to/BUGX` |
| `Missing or invalid program section` / `authorization section` / `scope section` | The YAML is missing a top-level block. Compare with [`docs/examples/example-profile.yaml`](examples/example-profile.yaml). (The old `allowed_domains` format is not supported) |
| `Missing or invalid program field: <field>` | Add the field (`id`, `name`, `platform`, `program_url`, `policy_url`) |
| Profile listed as **invalid** in `bugx programs` | Fix the YAML syntax (indentation, quotes around `*.wildcards`) |
| Everything is blocked | `authorization.user_confirmed` and `policy_reviewed` must **both** be `true` |

## Scope validation failures

| Message | Meaning | Fix |
|---|---|---|
| `Testing blocked: unverified` | The target matches no eligible asset | Check `exact` vs. `wildcard`. `*.example.com` does **not** include `example.com` |
| `Testing blocked: out_of_scope` / *Matches an explicitly excluded asset* | An exclusion matched (exclusions always win) | Intended. Remove the exclusion only if the program allows it |
| Default target is empty or wrong | `program.program_url` points to a platform page (e.g. `hackerone.com/...`) | Set it to the real in-scope site |
| URL asset never matches | Scheme, host, port and path must all match | Use a trailing `/*` for "this path and below". Check `http` vs. `https` |
| IP address targets rejected | IPs are not supported as assets | Use hostnames |
| `No authorized target selected. BUGX stopped.` | 3 rejected targets in a row | Check with `bugx scope-check TARGET PROFILE` first |

## Tools blocked by policy

| Message | Fix |
|---|---|
| *This program's policy forbids automated scanning. Blocked.* | Intended when the profile has `automated_scanning: false`. Change it only if the program allows scanners |
| Nikto / LinkFinder / SecretFinder blocked | These tools can't send custom headers, and the profile requires one. Intended |
| *Active scanning not confirmed* | You must type exactly `YES` (uppercase) |

## Playwright / browser issues

| Symptom | Fix |
|---|---|
| `bugx doctor` → *MCP SDK missing* | `pip install -e ".[browser]"` |
| `npx` not found | Install Node.js 18+ |
| No browser detected / PDF skipped | Install Chromium (`sudo apt install chromium`), Chrome or Edge, or set `playwright_mcp.executable_path` |
| First browser inspection is slow | `npx` downloads `@playwright/mcp@0.0.86` on first use |
| Browser inspection stops on a page | The page redirected out of scope. BUGX leaves it on purpose |

## Windows / Linux compatibility

- Linux (Kali, Debian, Ubuntu) is the primary, tested platform.
- Windows: core workflow, scope checks and reports are platform-independent
  Python. Naabu, WhatWeb, testssl.sh and Kiterunner are not supported natively.
  WSL is recommended for full tool coverage. **Windows has not been verified end
  to end.**
- Paths in `config/bugx.yaml` may use Windows syntax (`C:\tools\ffuf.exe`).
- Line endings: some source files use CRLF. Git handles this transparently.

## Reporting a bug

Open an issue with the bug report template, including:

- `bugx version` and `bugx doctor` output
- OS and Python version
- exact steps and the full error

**Remove target names, tokens, cookies and scan output before posting.**
Security issues in BUGX itself: see [SECURITY.md](../SECURITY.md).

---

[← Back to README](../README.md)
