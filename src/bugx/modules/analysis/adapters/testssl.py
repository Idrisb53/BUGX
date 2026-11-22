"""testssl.sh – TLS/SSL configuration analysis."""

import json

from bugx.core.adapters import RunContext, ToolAdapter, to_host_port

_REPORTED = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class TestsslAdapter(ToolAdapter):
    key = "testssl"
    name = "testssl.sh"
    module = "vulnerability_analysis"
    category = "TLS analysis"
    purpose = "TLS protocol, cipher and certificate configuration checks"
    binaries = ("testssl.sh", "testssl")
    version_args = ("--version",)
    install = {
        "linux": "sudo apt install testssl.sh",
        "windows": "Run from WSL or Git Bash: git clone https://github.com/drwetter/testssl.sh",
        "darwin": "brew install testssl",
    }
    supported_os = frozenset({"linux", "darwin"})
    input_kind = "url"  # keeps an explicit port; converted to host:port below
    default_timeout = 1800

    def _report(self, ctx, target):
        from bugx.core.results_manager import safe_name

        return ctx.work_dir / f"testssl_{safe_name(target)}.json"

    def build_args(self, ctx: RunContext, target):
        args = ["--quiet", "--color", "0", "--warnings", "batch", "--jsonfile", str(self._report(ctx, target))]
        for header in ctx.policy.header_list():
            args += ["--reqheader", header]
        endpoint = to_host_port(target)
        return [*args, endpoint if ":" in endpoint else f"{endpoint}:443"]

    def evidence_files(self, ctx, target):
        return [self._report(ctx, target)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx, target)
        if not path.is_file():
            return []
        rows = json.loads(path.read_text(encoding="utf-8") or "[]")
        items = []
        for row in rows if isinstance(rows, list) else []:
            severity = str(row.get("severity", "")).upper()
            if severity not in _REPORTED:
                continue
            items.append({
                "type": "finding",
                "asset": target,
                "finding": {
                    "title": f"TLS: {row.get('id', 'issue')} – {str(row.get('finding', ''))[:100]}",
                    "severity": severity,
                    "confidence": "Medium",
                    "category": "tls",
                    "url": f"https://{target}",
                    "description": str(row.get("finding", "")),
                    "references": [f"https://nvd.nist.gov/vuln/detail/{c}" for c in str(row.get("cve", "")).split() if c],
                    "remediation": "Disable weak protocols/ciphers and fix certificate issues as reported.",
                },
            })
        return items
