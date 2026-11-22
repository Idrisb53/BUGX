"""System health checks for BUGX (read-only; never installs anything)."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import platform
import sys
import tempfile
from pathlib import Path

from bugx import __version__
from bugx.core import config
from bugx.core.program_manager import load_program_file, validate_program_profile
from bugx.core.policy import load_policy

REQUIRED_PACKAGES = ("typer", "rich", "pyyaml", "jinja2")
OPTIONAL_PACKAGES = {"mcp": "browser inspection (pip install 'bugx-cli[browser]')"}

_IMPORT_NAMES = {"pyyaml": "yaml"}


def python_checks() -> list[dict]:
    rows = [
        {"item": "Python", "status": "Installed" if sys.version_info >= (3, 10) else "Error",
         "detail": platform.python_version()},
        {"item": "BUGX", "status": "Installed", "detail": __version__},
        {"item": "Operating System", "status": "Installed", "detail": f"{platform.system()} {platform.release()}"},
    ]
    for package in REQUIRED_PACKAGES:
        found = importlib.util.find_spec(_IMPORT_NAMES.get(package, package)) is not None
        version = ""
        if found:
            try:
                version = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                version = "?"
        rows.append({"item": f"python: {package}", "status": "Installed" if found else "Missing",
                     "detail": version or f"pip install {package}"})
    for package, purpose in OPTIONAL_PACKAGES.items():
        found = importlib.util.find_spec(package) is not None
        rows.append({"item": f"python: {package} (optional)", "status": "Installed" if found else "Not Configured",
                     "detail": purpose if not found else importlib.metadata.version(package)})
    return rows


def config_checks() -> list[dict]:
    rows = []
    try:
        settings = config.load_settings()
        rows.append({"item": "config/bugx.yaml", "status": "Installed" if (config.CONFIG_DIR / config.SETTINGS_FILENAME).is_file() else "Not Configured",
                     "detail": "using built-in defaults" if not (config.CONFIG_DIR / config.SETTINGS_FILENAME).is_file() else "valid"})
    except ValueError as error:
        settings = config.DEFAULT_SETTINGS
        rows.append({"item": "config/bugx.yaml", "status": "Error", "detail": str(error)})

    valid = invalid = 0
    problems = []
    for path in sorted(config.PROGRAMS_DIR.rglob("*.yaml")) if config.PROGRAMS_DIR.is_dir() else []:
        try:
            profile = load_program_file(path)
            validate_program_profile(profile)
            load_policy(profile, settings)
            valid += 1
        except (ValueError, OSError) as error:
            invalid += 1
            problems.append(f"{path.name}: {error}")
    rows.append({"item": "Program profiles", "status": "Installed" if valid and not invalid else ("Error" if invalid else "Not Configured"),
                 "detail": f"{valid} valid, {invalid} invalid" + (f" ({'; '.join(problems[:3])})" if problems else "")})
    return rows


def output_checks() -> list[dict]:
    root = config.output_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=root, prefix=".bugx-write-test-", delete=True):
            pass
        return [{"item": "Output directory", "status": "Installed", "detail": f"{root} (writable)"}]
    except OSError as error:
        return [{"item": "Output directory", "status": "Error", "detail": f"{root}: {error}"}]


def browser_checks(settings: dict) -> list[dict]:
    from bugx.integrations.playwright.browser import availability

    state = availability(settings)
    rows = [
        {"item": "Playwright MCP (BUGX client)", "status": "Installed" if state["available"] else "Not Configured",
         "detail": state["launcher_command"] if state["available"] else "; ".join(state["missing"])},
        {"item": "Browser executable", "status": "Installed" if state["browser"] else "Missing",
         "detail": state["browser"] or "install chromium / Chrome / Edge"},
    ]
    claude_cfg = Path.home() / ".claude.json"
    registered = False
    if claude_cfg.is_file():
        try:
            import json

            data = json.loads(claude_cfg.read_text(encoding="utf-8"))
            servers = set((data.get("mcpServers") or {}).keys())
            for project in (data.get("projects") or {}).values():
                servers.update((project.get("mcpServers") or {}).keys())
            registered = any("playwright" in name.lower() for name in servers)
        except (ValueError, OSError):
            registered = False
    rows.append({"item": "Playwright MCP in Claude Code", "status": "Installed" if registered else "Not Configured",
                 "detail": "registered" if registered else "optional: claude mcp add playwright -- npx @playwright/mcp@0.0.86"})
    return rows


def run_health(settings: dict | None = None) -> dict:
    try:
        settings = settings or config.load_settings()
    except ValueError:
        settings = config.DEFAULT_SETTINGS
    return {
        "system": python_checks(),
        "configuration": config_checks() + output_checks(),
        "browser": browser_checks(settings),
        "env": {"BUGX_HOME": os.environ.get("BUGX_HOME", ""), "project_root": str(config.PROJECT_ROOT)},
    }
