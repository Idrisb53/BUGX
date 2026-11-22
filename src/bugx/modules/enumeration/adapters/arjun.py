"""Arjun – HTTP parameter discovery."""

import json

from bugx.core.adapters import RunContext, ToolAdapter
from bugx.core.results_manager import safe_name


class ArjunAdapter(ToolAdapter):
    key = "arjun"
    name = "Arjun"
    module = "enumeration"
    category = "Parameter discovery"
    purpose = "Discover hidden HTTP GET parameters"
    binaries = ("arjun",)
    version_args = ()
    install = {"any": "pipx install arjun"}
    input_kind = "url"
    default_timeout = 1200

    def _out(self, ctx, target):
        return ctx.work_dir / f"arjun_{safe_name(target)}.json"

    def build_args(self, ctx: RunContext, target):
        args = [
            "-u", target, "-oJ", str(self._out(ctx, target)), "-m", "GET",
            "--rate-limit", str(ctx.policy.rate_limit), "-t", str(ctx.policy.concurrency),
        ]
        headers = ctx.policy.header_list()
        if headers:
            args += ["--headers", "\n".join(headers)]
        return args

    def evidence_files(self, ctx, target):
        return [self._out(ctx, target)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._out(ctx, target)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        items = []
        for url, detail in (data.items() if isinstance(data, dict) else []):
            detail = detail or {}
            for param in detail.get("params", []):
                items.append({"type": "parameter", "asset": url, "method": detail.get("method", "GET"), "parameter": param})
        return items
