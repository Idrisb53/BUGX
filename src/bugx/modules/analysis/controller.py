"""Vulnerability-analysis controller."""

from __future__ import annotations

from bugx.core.adapters import ToolAdapter, run_adapter
from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager
from bugx.modules.analysis.registry import ANALYSIS_ADAPTERS

NEEDS_PARAMETERS = {"dalfox", "sqlmap"}


def get_adapter(key: str) -> ToolAdapter:
    for adapter in ANALYSIS_ADAPTERS:
        if adapter.key == key:
            return adapter
    raise KeyError(f"Unknown analysis tool: {key}")


def run_analysis_tool(session: Session, key: str, targets: list[str] | None = None,
                      results: ResultsManager | None = None, options: dict | None = None):
    return run_adapter(get_adapter(key), session, targets, results=results, options=options)
