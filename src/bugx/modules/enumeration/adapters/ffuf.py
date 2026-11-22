"""FFUF – directory and content discovery (rate limited, single host)."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines
from bugx.modules.enumeration.adapters._wordlist import wordlist_status


class FfufAdapter(ToolAdapter):
    key = "ffuf"
    name = "FFUF"
    module = "enumeration"
    category = "Content discovery"
    purpose = "Directory and file discovery with a wordlist"
    binaries = ("ffuf",)
    version_args = ("-V",)
    install = {
        "linux": "sudo apt install ffuf  |  go install github.com/ffuf/ffuf/v2@latest",
        "windows": "go install github.com/ffuf/ffuf/v2@latest (or release .zip)",
        "darwin": "brew install ffuf",
    }
    input_kind = "url"
    default_timeout = 1800

    def config_status(self, settings):
        return wordlist_status(settings)

    def build_args(self, ctx: RunContext, target):
        return [
            "-u", target.rstrip("/") + "/FUZZ", "-w", ctx.wordlist(), "-json", "-s",
            "-rate", str(ctx.policy.rate_limit), "-t", str(ctx.policy.concurrency),
            "-timeout", "10", "-maxtime", "1500",
            "-mc", "200,204,301,302,307,401,403,405",
            *ctx.header_args("-H"),
        ]

    def parse(self, ctx, stdout, stderr, target):
        return [
            {
                "type": "path",
                "asset": row["url"],
                "method": "GET",
                "status_code": row.get("status"),
                "length": row.get("length"),
                "content_type": row.get("content-type", ""),
                "redirect": row.get("redirectlocation", ""),
            }
            for row in json_lines(stdout)
            if row.get("url")
        ]
