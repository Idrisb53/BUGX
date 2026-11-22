"""Thin wrapper around the official MCP Python SDK (stdio transport).

Only availability checks live here; the browser logic is in
``bugx.integrations.playwright``.
"""

from __future__ import annotations

import importlib.util
import shutil


def sdk_available() -> bool:
    return importlib.util.find_spec("mcp") is not None


def command_available(command: list[str]) -> bool:
    return bool(command) and shutil.which(command[0]) is not None


def text_of(result) -> str:
    """Concatenate the text parts of an MCP ``CallToolResult``."""
    parts = []
    for content in getattr(result, "content", []) or []:
        text = getattr(content, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def is_error(result) -> bool:
    return bool(getattr(result, "is_error", False) or getattr(result, "isError", False))
