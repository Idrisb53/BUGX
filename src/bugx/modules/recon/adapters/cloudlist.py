"""Cloudlist – list assets from YOUR configured cloud provider accounts.

Cloudlist does not contact the bug-bounty target. It only makes sense when
the program includes cloud assets you own/are authorised for; every returned
asset is still classified by the Scope Engine.
"""

from pathlib import Path

from bugx.core.adapters import RunContext, ToolAdapter, json_lines


class CloudlistAdapter(ToolAdapter):
    key = "cloudlist"
    name = "Cloudlist"
    module = "recon"
    category = "Cloud asset discovery"
    purpose = "Enumerate assets from configured cloud provider accounts"
    binaries = ("cloudlist",)
    install = {
        "linux": "go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest",
        "windows": "go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest",
        "darwin": "go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest",
    }
    input_kind = "none"
    batch = True
    sends_traffic = False
    http = False
    default_timeout = 600

    @staticmethod
    def provider_config() -> Path:
        return Path.home() / ".config" / "cloudlist" / "provider-config.yaml"

    def config_status(self, settings):
        path = ((settings.get("tools") or {}).get(self.key) or {}).get("provider_config") or self.provider_config()
        if not Path(path).is_file():
            return False, f"Provider config not found: {path}"
        return True, ""

    def build_args(self, ctx: RunContext, target):
        args = ["-silent", "-json"]
        custom = ctx.tool_settings(self.key).get("provider_config")
        if custom:
            args += ["-pc", str(custom)]
        return args

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            asset = row.get("dns_name") or row.get("hostname") or row.get("public_ip") or row.get("ip")
            if asset:
                items.append({"type": "cloud_asset", "asset": str(asset).lower(), "provider": row.get("provider", "")})
        return items
