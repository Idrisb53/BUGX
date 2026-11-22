"""WhatWeb – technology fingerprinting at aggression level 1 (one request)."""

import json

from bugx.core.adapters import RunContext, ToolAdapter


class WhatWebAdapter(ToolAdapter):
    key = "whatweb"
    name = "WhatWeb"
    module = "recon"
    category = "Technology fingerprinting"
    purpose = "Identify web technologies with a single stealthy request"
    binaries = ("whatweb",)
    version_args = ("--version",)
    install = {
        "linux": "sudo apt install whatweb",
        "windows": "Requires Ruby; run from WSL or install Ruby + git clone https://github.com/urbanadventurer/WhatWeb",
        "darwin": "brew install whatweb",
    }
    supported_os = frozenset({"linux", "darwin"})
    input_kind = "url"
    default_timeout = 300

    def _log(self, ctx, target):
        from bugx.core.results_manager import safe_name

        return ctx.work_dir / f"whatweb_{safe_name(target)}.json"

    def build_args(self, ctx: RunContext, target):
        args = ["-a", "1", "-q", "--no-errors", "--max-threads", str(ctx.policy.concurrency),
                f"--log-json={self._log(ctx, target)}"]
        for name, value in ctx.policy.required_headers.items():
            args += ["--header", f"{name}:{value}"]
        if ctx.policy.user_agent:
            args += ["-U", ctx.policy.user_agent]
        return [*args, target]

    def evidence_files(self, ctx, target):
        return [self._log(ctx, target)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._log(ctx, target)
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        try:
            rows = json.loads(text)
        except json.JSONDecodeError:
            rows = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        items = []
        for row in rows if isinstance(rows, list) else [rows]:
            if not isinstance(row, dict) or not row.get("target"):
                continue
            plugins = row.get("plugins") or {}
            tech = {}
            for plugin, detail in plugins.items():
                versions = (detail or {}).get("version") or []
                tech[plugin] = versions[0] if versions else ""
            items.append({"type": "technology", "asset": row["target"], "status_code": row.get("http_status"), "technologies": tech})
        return items
