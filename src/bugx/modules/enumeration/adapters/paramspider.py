"""ParamSpider – parameterised URLs from public web archives.

ParamSpider queries archive sources, not the target itself.
"""

from bugx.core.adapters import RunContext, ToolAdapter


class ParamSpiderAdapter(ToolAdapter):
    key = "paramspider"
    name = "ParamSpider"
    module = "enumeration"
    category = "Parameter discovery"
    purpose = "Collect archived URLs with parameters for the in-scope domain"
    binaries = ("paramspider",)
    version_args = ()
    install = {"any": "pipx install git+https://github.com/devanshbatham/ParamSpider"}
    input_kind = "domain"
    sends_traffic = False
    http = False
    default_timeout = 900

    def build_args(self, ctx: RunContext, target):
        return ["-d", target, "-s"]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")) and "?" in line:
                params = [p.split("=", 1)[0] for p in line.split("?", 1)[1].split("&") if p]
                items.append({"type": "url", "asset": line, "method": "GET", "parameters": params, "source": "archive"})
        return items
