"""Dalfox – reflected XSS analysis of URLs with parameters (no blind XSS callbacks)."""

import json

from bugx.core.adapters import RunContext, ToolAdapter
from bugx.core.results_manager import safe_name

_CONFIDENCE = {"V": "Medium", "R": "Low", "G": "Tentative"}


class DalfoxAdapter(ToolAdapter):
    key = "dalfox"
    name = "Dalfox"
    module = "vulnerability_analysis"
    category = "XSS analysis"
    purpose = "Parameter analysis and reflected XSS detection"
    binaries = ("dalfox",)
    version_args = ("version",)
    install = {
        "linux": "sudo apt install dalfox  |  go install github.com/hahwul/dalfox/v2@latest",
        "windows": "go install github.com/hahwul/dalfox/v2@latest",
        "darwin": "brew install dalfox",
    }
    input_kind = "url"
    intrusive = True
    default_timeout = 1800

    def _report(self, ctx, target):
        return ctx.work_dir / f"dalfox_{safe_name(target)}.json"

    def build_args(self, ctx: RunContext, target):
        if "?" not in target:
            raise ValueError("Dalfox needs a URL with query parameters (e.g. from enumeration results).")
        delay = max(0, int(1000 / max(1, ctx.policy.rate_limit)))
        return ["url", target, "--format", "json", "-o", str(self._report(ctx, target)), "--silence",
                "--no-spinner", "--skip-bav", "--delay", str(delay), "-w", str(ctx.policy.concurrency),
                *ctx.header_args("-H")]

    def evidence_files(self, ctx, target):
        return [self._report(ctx, target)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx, target)
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8").strip()
        rows = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip().startswith("{")]
        items = []
        for row in rows:
            if not isinstance(row, dict) or not row:
                continue
            kind = str(row.get("type", "R"))[:1]
            url = row.get("data") or target
            items.append({
                "type": "finding",
                "asset": url,
                "finding": {
                    "title": "Potential reflected XSS" if kind != "V" else "Reflected XSS (payload reflected and verified by Dalfox)",
                    "severity": row.get("severity") or "Medium",
                    "confidence": _CONFIDENCE.get(kind, "Low"),
                    "category": "xss",
                    "url": url,
                    "method": row.get("method", "GET"),
                    "parameter": row.get("param", ""),
                    "description": row.get("message_str", "") or "Dalfox reported a reflection of an XSS payload.",
                    "evidence": [f"payload: {row.get('payload', '')}", f"evidence: {row.get('evidence', '')}"],
                    "remediation": "Context-aware output encoding and a restrictive Content-Security-Policy.",
                    "references": ["https://owasp.org/www-community/attacks/xss/"],
                },
            })
        return items
