"""Kiterunner – API route discovery using a .kite/.txt route list."""

from pathlib import Path

from bugx.core.adapters import RunContext, ToolAdapter, json_lines, strip_ansi


class KiterunnerAdapter(ToolAdapter):
    key = "kiterunner"
    name = "Kiterunner"
    module = "enumeration"
    category = "API discovery"
    purpose = "Discover API routes with a route wordlist"
    binaries = ("kr", "kiterunner")
    version_args = ("version",)
    install = {
        "linux": "Download kr from github.com/assetnote/kiterunner/releases; set wordlists.api_routes (e.g. routes-small.kite)",
        "windows": "Not officially supported; use WSL.",
        "darwin": "Download kr from github.com/assetnote/kiterunner/releases",
    }
    supported_os = frozenset({"linux", "darwin"})
    input_kind = "url"
    default_timeout = 1800

    def config_status(self, settings):
        routes = (settings.get("wordlists") or {}).get("api_routes") or ""
        if not routes or not Path(routes).expanduser().is_file():
            return False, "Set wordlists.api_routes in config/bugx.yaml to a Kiterunner .kite or .txt file."
        return True, f"routes: {routes}"

    def build_args(self, ctx: RunContext, target):
        routes = str(Path(ctx.settings["wordlists"]["api_routes"]).expanduser())
        args = [
            "scan", target, "-w", routes, "-o", "json",
            "-x", str(ctx.policy.concurrency), "-j", "1",
            "--fail-status-codes", "400,404,405,426,501,502,503",
        ]
        for header in ctx.policy.header_list():
            args += ["-H", header]
        return args

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(strip_ansi(stdout)):
            url = row.get("url") or row.get("URL")
            path = row.get("path") or row.get("Path")
            if not url and path:
                url = target.rstrip("/") + "/" + str(path).lstrip("/")
            if url:
                items.append({
                    "type": "api_endpoint",
                    "asset": url,
                    "method": row.get("method") or row.get("Method") or "GET",
                    "status_code": row.get("status") or row.get("StatusCode"),
                    "length": row.get("length") or row.get("ContentLength"),
                })
        return items
