"""Naabu – fast TCP connect port scan of the top ports."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines, to_host


class NaabuAdapter(ToolAdapter):
    key = "naabu"
    name = "Naabu"
    module = "recon"
    category = "Port scanning"
    purpose = "TCP connect scan of the top 100 ports"
    binaries = ("naabu",)
    install = {
        "linux": "sudo apt install naabu  |  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest (needs libpcap-dev)",
        "windows": "Not natively supported; use Nmap instead.",
        "darwin": "brew install naabu",
    }
    supported_os = frozenset({"linux", "darwin"})
    input_kind = "host"
    batch = True
    http = False
    default_timeout = 1200

    def build_args(self, ctx: RunContext, target):
        hosts = ",".join(sorted({to_host(t) for t in ctx.targets}))
        return [
            "-host", hosts, "-top-ports", str(ctx.options.get("top_ports", 100)),
            "-scan-type", "c", "-json", "-silent",
            "-rate", str(max(1, ctx.policy.rate_limit * 10)), "-c", str(ctx.policy.concurrency),
        ]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            port = row.get("port")
            if isinstance(port, dict):
                port = port.get("Port") or port.get("port")
            host = row.get("host") or row.get("ip")
            if host and port:
                items.append({"type": "port", "asset": str(host).lower(), "port": int(port), "ip": row.get("ip", "")})
        return items
