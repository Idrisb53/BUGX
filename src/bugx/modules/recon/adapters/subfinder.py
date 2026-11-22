"""Subfinder – passive subdomain discovery (no traffic to the target)."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines


class SubfinderAdapter(ToolAdapter):
    key = "subfinder"
    name = "Subfinder"
    module = "recon"
    category = "Subdomain discovery"
    purpose = "Passive subdomain discovery from public sources"
    binaries = ("subfinder",)
    install = {
        "linux": "sudo apt install subfinder  |  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "windows": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest (or release .zip from GitHub)",
        "darwin": "brew install subfinder",
    }
    input_kind = "domain"
    sends_traffic = False
    http = False
    default_timeout = 600

    def build_args(self, ctx: RunContext, target):
        return ["-d", target, "-silent", "-oJ", "-rl", str(ctx.policy.rate_limit)]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            host = str(row.get("host", "")).strip().lower()
            if host:
                items.append({"type": "host", "asset": host, "source": row.get("source", "")})
        if not items:  # plain-text fallback (older versions)
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line and " " not in line and not line.startswith("{"):
                    items.append({"type": "host", "asset": line, "source": ""})
        return items
