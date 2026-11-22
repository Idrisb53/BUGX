"""Wapiti – web vulnerability scanning with a restricted, non-destructive module set.

Excluded on purpose: brute_login_form, buster, upload, exec, file, permanentxss
(stores payloads), timesql, ssrf (external callback), shellshock, log4shell,
spring4shell, takeover, xxe, backup, nikto.
"""

import json
from urllib.parse import urljoin

from bugx.core.adapters import RunContext, ToolAdapter

SAFE_MODULES = "xss,sql,crlf,redirect,csrf,methods,ssl,wapp,cms"
_LEVELS = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


class WapitiAdapter(ToolAdapter):
    key = "wapiti"
    name = "Wapiti"
    module = "vulnerability_analysis"
    category = "Web vulnerability scanning"
    purpose = f"Black-box scan limited to modules: {SAFE_MODULES}"
    binaries = ("wapiti",)
    version_args = ("--version",)
    install = {"linux": "sudo apt install wapiti", "any": "pipx install wapiti3"}
    input_kind = "url"
    intrusive = True
    default_timeout = 3600

    def _report(self, ctx):
        return ctx.work_dir / "wapiti.json"

    def build_args(self, ctx: RunContext, target):
        args = ["-u", target, "-m", SAFE_MODULES, "-l", "1", "--scope", "folder",
                "-f", "json", "-o", str(self._report(ctx)), "--flush-session",
                "--max-scan-time", "1800", "--max-attack-time", "600",
                "--tasks", str(ctx.policy.concurrency), "--no-bugreport"]
        for name, value in ctx.policy.required_headers.items():
            args += ["-H", f"{name}: {value}"]
        if ctx.policy.user_agent:
            args += ["-A", ctx.policy.user_agent]
        return args

    def evidence_files(self, ctx, target):
        return [self._report(ctx)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        items = []
        for category, entries in (data.get("vulnerabilities") or {}).items():
            for entry in entries or []:
                url = urljoin(target, entry.get("path", ""))
                items.append({
                    "type": "finding",
                    "asset": url,
                    "finding": {
                        "title": f"{category}: {entry.get('info', '')}"[:160],
                        "severity": _LEVELS.get(entry.get("level"), "Low"),
                        "confidence": "Low",
                        "url": url,
                        "method": entry.get("method", "GET"),
                        "parameter": entry.get("parameter", "") or "",
                        "description": entry.get("info", ""),
                        "evidence": [entry.get("http_request", "")[:2000]] if entry.get("http_request") else [],
                        "references": [entry["wstg"]] if isinstance(entry.get("wstg"), str) else list(entry.get("wstg") or []),
                    },
                })
        return items
