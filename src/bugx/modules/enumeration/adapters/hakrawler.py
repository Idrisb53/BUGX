"""Hakrawler – fast crawling (same host only; subdomains not followed)."""

from bugx.core.adapters import RunContext, ToolAdapter, strip_ansi


class HakrawlerAdapter(ToolAdapter):
    key = "hakrawler"
    name = "Hakrawler"
    module = "enumeration"
    category = "Web crawling"
    purpose = "Crawl a URL and list discovered endpoints"
    binaries = ("hakrawler",)
    version_args = ()
    install = {
        "linux": "sudo apt install hakrawler  |  go install github.com/hakluke/hakrawler@latest",
        "windows": "go install github.com/hakluke/hakrawler@latest",
        "darwin": "go install github.com/hakluke/hakrawler@latest",
    }
    input_kind = "url"
    default_timeout = 900

    def build_args(self, ctx: RunContext, target):
        args = ["-d", str(ctx.options.get("depth", 2)), "-u", "-t", str(ctx.policy.concurrency), "-timeout", "10"]
        headers = ctx.policy.header_list()
        if headers:
            args += ["-h", ";;".join(headers)]
        return args

    def stdin(self, ctx, target):
        return target + "\n"

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for line in strip_ansi(stdout).splitlines():
            value = line.strip()
            if value.startswith("[") and "] " in value:
                value = value.split("] ", 1)[1].strip()
            if value.startswith(("http://", "https://")):
                items.append({"type": "url", "asset": value, "method": "GET", "source": target})
        return items
