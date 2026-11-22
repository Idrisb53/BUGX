"""Katana – web crawling restricted to the exact target host."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines


class KatanaAdapter(ToolAdapter):
    key = "katana"
    name = "Katana"
    module = "recon"
    category = "Web crawling"
    purpose = "Crawl in-scope URLs (same FQDN only) to discover endpoints"
    binaries = ("katana",)
    install = {
        "linux": "sudo apt install katana  |  go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "windows": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "darwin": "brew install katana",
    }
    input_kind = "url"
    default_timeout = 1200

    def build_args(self, ctx: RunContext, target):
        return [
            "-u", target, "-jsonl", "-silent",
            "-d", str(ctx.options.get("depth", 2)),
            "-fs", "fqdn",  # never follow links to other hosts
            "-rl", str(ctx.policy.rate_limit), "-c", str(ctx.policy.concurrency),
            "-timeout", "10",
            *ctx.header_args("-H"),
        ]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            request = row.get("request") or {}
            response = row.get("response") or {}
            url = request.get("endpoint") or row.get("endpoint") or row.get("url")
            if url:
                items.append({
                    "type": "url",
                    "asset": url,
                    "method": request.get("method", "GET"),
                    "status_code": response.get("status_code"),
                    "source": request.get("source", ""),
                })
        return items
