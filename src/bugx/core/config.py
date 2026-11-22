"""Central BUGX paths and settings.

Paths resolve in this order:
1. ``BUGX_HOME`` environment variable (project root containing ``config/``).
2. The source checkout this package lives in (editable install / ``src`` layout).
3. The current working directory.

``BUGX_OUTPUT_DIR`` overrides the output directory (used by tests).
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from bugx import __version__

VERSION = __version__

SETTINGS_FILENAME = "bugx.yaml"

DEFAULT_SETTINGS: dict[str, Any] = {
    "defaults": {
        "timeout": 600,
        "rate_limit": 5,
        "concurrency": 5,
        "version_timeout": 20,
    },
    "wordlists": {
        "directories": [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ],
        "api_routes": "",
    },
    "nuclei": {
        "templates": [],
        "tags": ["exposure", "misconfig", "tech", "ssl"],
        "exclude_tags": [
            "dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force",
            "default-login", "rce", "sqli", "osint", "token-spray",
        ],
        "severity": ["info", "low", "medium", "high", "critical"],
    },
    "semgrep": {"config": "p/security-audit"},
    "playwright_mcp": {
        "command": ["npx", "-y", "@playwright/mcp@0.0.86"],
        "browser": "chromium",
        "executable_path": "",
        "headless": True,
    },
    "tools": {},
}


def _project_root() -> Path:
    env = os.environ.get("BUGX_HOME")
    if env:
        return Path(env).expanduser().resolve()

    checkout = Path(__file__).resolve().parents[3]
    if (checkout / "config").is_dir() or (checkout / "pyproject.toml").is_file():
        return checkout

    return Path.cwd().resolve()


PROJECT_ROOT = _project_root()
CONFIG_DIR = PROJECT_ROOT / "config"
PROGRAMS_DIR = CONFIG_DIR / "programs"
TEMPLATES_DIR = PROJECT_ROOT / "templates"


def output_root() -> Path:
    """Return the output directory (evaluated at call time)."""
    env = os.environ.get("BUGX_OUTPUT_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return PROJECT_ROOT / "output"


def _merge(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings(path: Path | None = None) -> dict[str, Any]:
    """Load ``config/bugx.yaml`` merged over the built-in defaults.

    Invalid or missing files fall back to defaults; an invalid file raises
    ``ValueError`` so the health check can report it.
    """
    settings_path = path or CONFIG_DIR / SETTINGS_FILENAME

    if not settings_path.is_file():
        return copy.deepcopy(DEFAULT_SETTINGS)

    try:
        with settings_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid settings file {settings_path}: {error}") from error

    if not isinstance(data, dict):
        raise ValueError(f"Settings file must be a mapping: {settings_path}")

    return _merge(DEFAULT_SETTINGS, data)


def first_existing(paths: list[str]) -> str | None:
    """Return the first path in ``paths`` that exists."""
    for candidate in paths or []:
        if candidate and Path(candidate).expanduser().is_file():
            return str(Path(candidate).expanduser())
    return None
