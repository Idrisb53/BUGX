"""OWASP Amass – passive attack-surface / subdomain discovery."""

import re

from bugx.core.adapters import RunContext, ToolAdapter, strip_ansi

_NAME = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b", re.I)


class AmassAdapter(ToolAdapter):
    key = "amass"
    name = "Amass"
    module = "recon"
    category = "Attack surface discovery"
    purpose = "Passive subdomain and attack-surface enumeration"
    binaries = ("amass",)
    install = {
        "linux": "sudo apt install amass, then once: sudo libpostal_data download all /var/lib/libpostal (Kali wrapper needs it)",
        "windows": "Download the release .zip from github.com/owasp-amass/amass/releases",
        "darwin": "brew install amass",
    }
    input_kind = "domain"
    sends_traffic = False
    http = False
    default_timeout = 1800

    def build_args(self, ctx: RunContext, target):
        minutes = max(1, int(ctx.options.get("amass_minutes", 15)))
        return ["enum", "-passive", "-d", target, "-timeout", str(minutes)]

    def parse(self, ctx, stdout, stderr, target):
        domain = (target or "").lower()
        hosts = set()
        for match in _NAME.finditer(strip_ansi(stdout)):
            name = match.group(1).lower().rstrip(".")
            if name == domain or name.endswith("." + domain):
                hosts.add(name)
        return [{"type": "host", "asset": host, "source": "amass"} for host in sorted(hosts)]
