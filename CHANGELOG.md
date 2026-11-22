# Changelog

All notable changes to BUGX are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Public release preparation: full README (architecture diagram, screenshots,
  disclaimer), `docs/` (Installation, Configuration, Usage, Modules,
  Architecture, Troubleshooting), `CONTRIBUTING.md`, `SECURITY.md`, MIT
  `LICENSE`, `.env.example`, GitHub issue/PR templates and a CI workflow that
  runs the mocked test suite on Python 3.10–3.13.
- Real terminal screenshots in `assets/screenshots/`.

### Changed
- Startup banner and About screen now credit **IDRIS4HACK**.
- Documentation moved into `docs/` (`TOOL_CONFIGURATION.md` → `docs/MODULES.md`,
  `SCOPE_CONFIGURATION.md` → `docs/CONFIGURATION.md`).
- `.gitignore` now also excludes real program profiles, logs, temporary and OS files.
- Package metadata: license, author, keywords and classifiers in `pyproject.toml`.

### Fixed
- Target prompt now shows its suggested default (`Target URL/domain [example.com]:`). Rich was
  treating the bracketed value as markup and hiding it. Regression test added.

### Removed (from version control only, files kept locally)
- Local scan output, real program profiles, legacy `cli_backup.py`,
  `config/default.yaml`, `test_scope_engine.py` (ported to
  `tests/test_scope_engine_baseline.py`) and the internal development audit.

## [1.2.0] - 2026-11-21

### Added
- Step 3 of the workflow: select an existing program profile **or** configure a new one.
- Scope review table, per-session authorization confirmation, validated target selection.
- 10 reconnaissance, 10 enumeration and 10 vulnerability-analysis tool adapters on a shared, fail-closed execution engine.
- Endpoint inventory, scoped JavaScript collector, Playwright MCP browser inspection.
- Safe Validation (scope re-check, guidance, single-GET replay, status history, CVSS with vector).
- Report generator: Markdown, HTML (autoescaped), JSON, PDF. Scan history. `bugx history`, `bugx report`.
- System Health: Python/deps, tool versions, Error / Not Configured states, config validity, output permissions, Playwright MCP and browser.
- Centralised JSON results (`output/<module>/<program>/`), findings index, logs.
- `config/bugx.yaml`, `python -m bugx`, optional extras `[browser]`, `[dev]`.
- Test suite: 164 unit/integration tests + 11 end-to-end tests against a local mock target.

### Fixed
- Recon result file paths were never printed (key mismatch).
- Every launch created a duplicate profile (there was no way to load one).
- The session target could be the platform's program page (e.g. hackerone.com) and block every module.
- `httpx` detection picked the Python HTTP client on Kali.
- `bugx recon` exited 0 on failure. Recon output depended on the working directory. The project root assumed an editable install.
- Package and CLI now share a single version number.
- HTML report rendered scanner text without escaping.
- Browser followed server-side redirects to out-of-scope hosts before BUGX could check them (preflight added).

### Changed
- The recon menu lists the 10 recon tools. Directory/parameter/JS/API discovery moved to Enumeration. GAU/Waybackurls removed.
- New-profile creation no longer prompts for additional/excluded assets or request rules. Edit the profile YAML instead.

## [1.1.0] - 2026-11-16

- Interactive platform selection, profile creation, Scope Engine v2.0, passive
  Subfinder recon, System Health, placeholders for the other modules.
