"""Nikto – web server checks with DoS tests excluded (tuning x6)."""

import json

from bugx.core.adapters import RunContext, ToolAdapter


class NiktoAdapter(ToolAdapter):
    key = "nikto"
    name = "Nikto"
    module = "vulnerability_analysis"
    category = "Web server checks"
    purpose = "Web server misconfiguration and dangerous file checks (no DoS tests)"
    binaries = ("nikto", "nikto.pl")
    version_args = ("-Version",)
    install = {
        "linux": "sudo apt install nikto",
        "windows": "Requires Perl: git clone https://github.com/sullo/nikto (run program/nikto.pl)",
        "darwin": "brew install nikto",
    }
    input_kind = "url"
    intrusive = True
    supports_headers = False  # Nikto cannot add custom request headers
    ok_returncodes = (0, 1)
    default_timeout = 2400

    def _report(self, ctx):
        return ctx.work_dir / "nikto.json"

    def build_args(self, ctx: RunContext, target):
        return ["-h", target, "-Format", "json", "-output", str(self._report(ctx)),
                "-Tuning", "x6", "-maxtime", "30m", "-nointeractive", "-ask", "no"]

    def evidence_files(self, ctx, target):
        return [self._report(ctx)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx)
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        data = json.loads(text) if text else []
        hosts = data if isinstance(data, list) else [data]
        items = []
        for host in hosts:
            for vuln in (host or {}).get("vulnerabilities", []) or []:
                url = vuln.get("url") or ""
                if url and not url.startswith("http"):
                    url = target.rstrip("/") + "/" + url.lstrip("/")
                items.append({
                    "type": "finding",
                    "asset": url or target,
                    "finding": {
                        "title": (vuln.get("msg") or "Nikto finding")[:160],
                        "severity": "Low",
                        "confidence": "Low",
                        "url": url or target,
                        "method": vuln.get("method", "GET"),
                        "description": vuln.get("msg", "") + (f" (Nikto ID {vuln.get('id')})" if vuln.get("id") else ""),
                        "references": [vuln["references"]] if isinstance(vuln.get("references"), str) else [],
                    },
                })
        return items
