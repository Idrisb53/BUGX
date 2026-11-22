"""Semgrep – static analysis of an authorized local source tree (metrics off)."""

import json
from pathlib import Path

from bugx.core.adapters import RunContext, ToolAdapter

_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}


class SemgrepAdapter(ToolAdapter):
    key = "semgrep"
    name = "Semgrep"
    module = "vulnerability_analysis"
    category = "Static code analysis"
    purpose = "Static security analysis of source code you are authorized to review"
    binaries = ("semgrep",)
    version_args = ("--version",)
    install = {"any": "pipx install semgrep"}
    supported_os = frozenset({"linux", "darwin", "windows"})
    input_kind = "path"
    sends_traffic = False
    http = False
    ok_returncodes = (0, 1)
    default_timeout = 1800

    def _report(self, ctx):
        return ctx.work_dir / "semgrep.json"

    def build_args(self, ctx: RunContext, target):
        if not Path(target).is_dir():
            raise ValueError(f"Directory not found: {target}")
        config = (ctx.settings.get("semgrep") or {}).get("config", "p/security-audit")
        return ["scan", "--config", config, "--json", "--metrics=off", "--quiet", "--output", str(self._report(ctx)), target]

    def evidence_files(self, ctx, target):
        return [self._report(ctx)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        items = []
        for row in data.get("results", []) or []:
            extra = row.get("extra") or {}
            meta = extra.get("metadata") or {}
            owasp = meta.get("owasp")
            items.append({
                "type": "finding",
                "finding": {
                    "title": row.get("check_id", "semgrep finding").split(".")[-1].replace("-", " "),
                    "severity": _SEVERITY.get(extra.get("severity", "INFO"), "Low"),
                    "confidence": "Low",
                    "category": "code_issue",
                    "owasp": ", ".join(owasp) if isinstance(owasp, list) else (owasp or ""),
                    "url": f"{row.get('path')}:{(row.get('start') or {}).get('line', '')}",
                    "description": extra.get("message", ""),
                    "references": list(meta.get("references") or []),
                },
            })
        return items
