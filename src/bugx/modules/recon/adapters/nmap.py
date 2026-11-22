"""Nmap – TCP connect scan of the top ports (no scripts, no OS detection)."""

import xml.etree.ElementTree as ET

from bugx.core.adapters import RunContext, ToolAdapter


class NmapAdapter(ToolAdapter):
    key = "nmap"
    name = "Nmap"
    module = "recon"
    category = "Port and service discovery"
    purpose = "TCP connect scan of top ports with service names"
    binaries = ("nmap",)
    version_args = ("--version",)
    install = {
        "linux": "sudo apt install nmap",
        "windows": "Install from https://nmap.org/download.html (adds nmap.exe to PATH)",
        "darwin": "brew install nmap",
    }
    input_kind = "host"
    http = False
    default_timeout = 1800

    def build_args(self, ctx: RunContext, target):
        top = int(ctx.options.get("top_ports", 100))
        return [
            "-sT", "-Pn", "-sV", "--version-light", "--top-ports", str(top), "-T3",
            "--max-rate", str(max(1, ctx.policy.rate_limit * 10)),
            "--host-timeout", "15m", "-oX", "-", target,
        ]

    def parse(self, ctx, stdout, stderr, target):
        start = stdout.find("<?xml")
        if start < 0:
            return []
        if "<!DOCTYPE" in stdout[start:start + 500] and "<!ENTITY" in stdout:
            raise ValueError("Refusing to parse XML with entity declarations.")
        root = ET.fromstring(stdout[start:])
        items = []
        for host in root.findall("host"):
            names = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
            hostname = names[0] if names else target
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                items.append({
                    "type": "port",
                    "asset": hostname,
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                })
        return items
