"""Retire.js – detect JavaScript libraries with known vulnerabilities (local files)."""

import json
from pathlib import Path

from bugx.core.adapters import RunContext, ToolAdapter


class RetireAdapter(ToolAdapter):
    key = "retire"
    name = "Retire.js"
    module = "vulnerability_analysis"
    category = "Outdated components"
    purpose = "Scan downloaded/local JavaScript for vulnerable library versions"
    binaries = ("retire",)
    version_args = ("--version",)
    install = {"any": "npm install -g retire"}
    input_kind = "path"
    sends_traffic = False
    http = False
    ok_returncodes = (0, 13)  # 13 = vulnerabilities found
    default_timeout = 900

    def _report(self, ctx):
        return ctx.work_dir / "retire.json"

    def build_args(self, ctx: RunContext, target):
        if not Path(target).exists():
            raise ValueError(f"Path not found: {target}")
        return ["--path", target, "--outputformat", "json", "--outputpath", str(self._report(ctx))]

    def evidence_files(self, ctx, target):
        return [self._report(ctx)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        rows = data.get("data", []) if isinstance(data, dict) else data
        items = []
        for row in rows or []:
            for result in row.get("results", []) or []:
                for vuln in result.get("vulnerabilities", []) or []:
                    ids = vuln.get("identifiers") or {}
                    summary = ids.get("summary") or ", ".join(ids.get("CVE", []) or []) or "Known vulnerability"
                    items.append({
                        "type": "finding",
                        "finding": {
                            "title": f"Vulnerable JavaScript library {result.get('component')} {result.get('version')}",
                            "severity": vuln.get("severity", "medium"),
                            "confidence": "Medium",
                            "category": "outdated_component",
                            "url": row.get("file", target),
                            "description": summary,
                            "references": list(vuln.get("info") or []),
                            "remediation": f"Upgrade {result.get('component')} to a fixed version.",
                        },
                    })
        return items
