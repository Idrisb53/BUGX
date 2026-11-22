"""dnsx – DNS resolution and record checks for discovered hosts."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines, to_host


class DnsxAdapter(ToolAdapter):
    key = "dnsx"
    name = "dnsx"
    module = "recon"
    category = "DNS resolution"
    purpose = "Resolve A/AAAA/CNAME records of in-scope hosts"
    binaries = ("dnsx",)
    install = {
        "linux": "sudo apt install dnsx  |  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "windows": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "darwin": "brew install dnsx",
    }
    input_kind = "host"
    batch = True
    http = False
    default_timeout = 600

    def build_args(self, ctx: RunContext, target):
        return [
            "-silent", "-json", "-a", "-aaaa", "-cname", "-resp",
            "-rl", str(ctx.policy.rate_limit), "-t", str(ctx.policy.concurrency),
        ]

    def stdin(self, ctx, target):
        return "\n".join(sorted({to_host(t) for t in ctx.targets})) + "\n"

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            host = str(row.get("host", "")).lower()
            if not host:
                continue
            items.append({
                "type": "dns",
                "asset": host,
                "a": row.get("a", []),
                "aaaa": row.get("aaaa", []),
                "cname": row.get("cname", []),
                "status_code": row.get("status_code", ""),
            })
            for cname in row.get("cname", []) or []:
                items.append({"type": "host", "asset": str(cname).lower().rstrip("."), "source": f"cname of {host}"})
        return items
