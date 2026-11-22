"""Dirsearch – directory and file enumeration."""

import json

from bugx.core.adapters import RunContext, ToolAdapter
from bugx.core.results_manager import safe_name


class DirsearchAdapter(ToolAdapter):
    key = "dirsearch"
    name = "Dirsearch"
    module = "enumeration"
    category = "Directory enumeration"
    purpose = "Directory and file enumeration with the built-in wordlist"
    binaries = ("dirsearch", "dirsearch.py")
    version_args = ("--version",)
    install = {
        "linux": "sudo apt install dirsearch  |  pipx install dirsearch",
        "windows": "pipx install dirsearch",
        "darwin": "pipx install dirsearch",
    }
    input_kind = "url"
    default_timeout = 1800

    def _out(self, ctx, target):
        return ctx.work_dir / f"dirsearch_{safe_name(target)}.json"

    def build_args(self, ctx: RunContext, target):
        args = [
            "-u", target, "--format", "json", "-o", str(self._out(ctx, target)), "-q",
            "--max-rate", str(ctx.policy.rate_limit), "-t", str(ctx.policy.concurrency),
            "--timeout", "10",
        ]
        for name, value in ctx.policy.required_headers.items():
            args += ["-H", f"{name}: {value}"]
        if ctx.policy.user_agent:
            args += ["--user-agent", ctx.policy.user_agent]
        return args

    def evidence_files(self, ctx, target):
        return [self._out(ctx, target)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._out(ctx, target)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        rows = data.get("results", []) if isinstance(data, dict) else []
        if isinstance(rows, dict):  # legacy {"<url>": [ ... ]}
            rows = [r for v in rows.values() for r in (v or [])]
        items = []
        for row in rows:
            url = row.get("url") or row.get("path")
            if url:
                items.append({
                    "type": "path",
                    "asset": url,
                    "method": "GET",
                    "status_code": row.get("status"),
                    "length": row.get("content-length") or row.get("contentLength"),
                    "content_type": row.get("content-type", ""),
                    "redirect": row.get("redirect", ""),
                })
        return items
