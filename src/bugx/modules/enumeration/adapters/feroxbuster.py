"""Feroxbuster – recursive content discovery (depth-limited)."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines
from bugx.modules.enumeration.adapters._wordlist import wordlist_status


class FeroxbusterAdapter(ToolAdapter):
    key = "feroxbuster"
    name = "Feroxbuster"
    module = "enumeration"
    category = "Recursive content discovery"
    purpose = "Recursive directory discovery, depth 2"
    binaries = ("feroxbuster",)
    version_args = ("-V",)
    install = {
        "linux": "sudo apt install feroxbuster",
        "windows": "Download feroxbuster.exe from github.com/epi052/feroxbuster/releases",
        "darwin": "brew install feroxbuster",
    }
    input_kind = "url"
    default_timeout = 1800

    def config_status(self, settings):
        return wordlist_status(settings)

    def build_args(self, ctx: RunContext, target):
        args = [
            "-u", target, "-w", ctx.wordlist(), "--silent", "--json", "--no-state",
            "-d", str(ctx.options.get("depth", 2)),
            "--rate-limit", str(ctx.policy.rate_limit), "-t", str(ctx.policy.concurrency),
            "--time-limit", "25m",
        ]
        for name, value in ctx.policy.required_headers.items():
            args += ["-H", f"{name}: {value}"]
        if ctx.policy.user_agent:
            args += ["-a", ctx.policy.user_agent]
        return args

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            if row.get("type") not in (None, "response") or not row.get("url"):
                continue
            headers = row.get("headers") or {}
            items.append({
                "type": "path",
                "asset": row["url"],
                "method": row.get("method", "GET"),
                "status_code": row.get("status"),
                "length": row.get("content_length"),
                "content_type": headers.get("content-type", ""),
            })
        return items
