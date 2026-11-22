"""OWASP ZAP – baseline (spider + passive rules) scan via zap-baseline.py.

zap-baseline does not run active attack rules. It is provided by the ZAP
Docker images (``zaproxy/zap-stable``) and by ZAP installs that ship the
packaged scan scripts.
"""

import json

from bugx.core.adapters import RunContext, ToolAdapter


class ZapAdapter(ToolAdapter):
    key = "zap"
    name = "OWASP ZAP"
    module = "vulnerability_analysis"
    category = "Web application scanning"
    purpose = "ZAP baseline: spider + passive scan rules only"
    binaries = ("zap-baseline.py", "zap-baseline")
    version_args = ()
    install = {
        "linux": "docker pull zaproxy/zap-stable, then put a zap-baseline.py wrapper on PATH (see TOOL_CONFIGURATION.md)",
        "windows": "Docker Desktop + zaproxy/zap-stable image; wrapper script on PATH",
        "darwin": "docker pull zaproxy/zap-stable",
    }
    input_kind = "url"
    intrusive = True
    ok_returncodes = (0, 1, 2)  # 1 = FAIL alerts, 2 = WARN alerts
    default_timeout = 3600

    def _report(self, ctx):
        return ctx.work_dir / "zap_report.json"

    def build_args(self, ctx: RunContext, target):
        # zap-baseline writes reports relative to its working dir (/zap/wrk in
        # Docker); BUGX runs it with cwd = evidence dir, so pass a bare name.
        args = ["-t", target, "-J", self._report(ctx).name, "-m", "2", "-I"]
        cfg = []
        for index, header in enumerate(ctx.policy.header_list()):
            name, value = header.split(":", 1)
            prefix = f"replacer.full_list({index})"
            cfg += [
                f"-config {prefix}.description=bugx{index}",
                f"-config {prefix}.enabled=true",
                f"-config {prefix}.matchtype=REQ_HEADER",
                f"-config {prefix}.matchstr={name.strip()}",
                f"-config {prefix}.regex=false",
                f"-config {prefix}.replacement={value.strip()}",
            ]
        if cfg:
            if any(" " in c.split("=", 1)[1] for c in cfg):
                raise ValueError("ZAP replacer values cannot contain spaces; set headers without spaces.")
            args += ["-z", " ".join(cfg)]
        return args

    def evidence_files(self, ctx, target):
        return [self._report(ctx)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        items = []
        for site in data.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                risk = str(alert.get("riskdesc", "Informational")).split(" ")[0]
                for instance in (alert.get("instances") or [{}])[:20]:
                    url = instance.get("uri") or target
                    items.append({
                        "type": "finding",
                        "asset": url,
                        "finding": {
                            "title": alert.get("name") or alert.get("alert", "ZAP alert"),
                            "severity": risk,
                            "confidence": "Low",
                            "url": url,
                            "method": instance.get("method", "GET"),
                            "parameter": instance.get("param", ""),
                            "description": _strip_html(alert.get("desc", "")),
                            "remediation": _strip_html(alert.get("solution", "")),
                            "references": [r for r in _strip_html(alert.get("reference", "")).split("\n") if r],
                            "evidence": [instance.get("evidence", "")] if instance.get("evidence") else [],
                        },
                    })
        return items


def _strip_html(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "\n", text or "").strip()
