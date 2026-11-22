"""Enumeration controller: tool execution plus endpoint inventory."""

from __future__ import annotations

from bugx.core.adapters import ToolAdapter, run_adapter
from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager
from bugx.modules.enumeration.registry import ENUMERATION_ADAPTERS


def get_adapter(key: str) -> ToolAdapter:
    for adapter in ENUMERATION_ADAPTERS:
        if adapter.key == key:
            return adapter
    raise KeyError(f"Unknown enumeration tool: {key}")


def run_enumeration_tool(session: Session, key: str, targets: list[str] | None = None,
                         results: ResultsManager | None = None, options: dict | None = None):
    return run_adapter(get_adapter(key), session, targets, results=results, options=options)
