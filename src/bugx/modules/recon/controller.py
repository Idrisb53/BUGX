"""Reconnaissance controller: tool lookup and execution through the shared engine."""

from __future__ import annotations

from bugx.core.adapters import ToolAdapter, run_adapter
from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager
from bugx.modules.recon.registry import RECON_ADAPTERS


def get_adapter(key: str) -> ToolAdapter:
    for adapter in RECON_ADAPTERS:
        if adapter.key == key:
            return adapter
    raise KeyError(f"Unknown recon tool: {key}")


def run_recon_tool(session: Session, key: str, targets: list[str] | None = None,
                   results: ResultsManager | None = None, options: dict | None = None):
    return run_adapter(get_adapter(key), session, targets, results=results, options=options)
