"""tlsx – TLS certificate and configuration discovery."""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines, to_host


class TlsxAdapter(ToolAdapter):
    key = "tlsx"
    name = "tlsx"
    module = "recon"
    category = "TLS discovery"
    purpose = "Collect certificate names (SAN/CN), TLS version and certificate problems"
    binaries = ("tlsx",)
    install = {
        "linux": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        "windows": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        "darwin": "brew install tlsx",
    }
    input_kind = "host"
    batch = True
    http = False
    default_timeout = 600

    def build_args(self, ctx: RunContext, target):
        return ["-silent", "-json", "-san", "-cn", "-tv", "-ex", "-ss", "-mm", "-c", str(ctx.policy.concurrency)]

    def stdin(self, ctx, target):
        return "\n".join(sorted({to_host(t) for t in ctx.targets})) + "\n"

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            host = str(row.get("host", "")).lower()
            if not host:
                continue
            items.append({
                "type": "tls",
                "asset": host,
                "port": row.get("port"),
                "tls_version": row.get("tls_version", ""),
                "subject_cn": row.get("subject_cn", ""),
                "issuer_cn": row.get("issuer_cn", ""),
                "not_after": row.get("not_after", ""),
                "expired": bool(row.get("expired")),
                "self_signed": bool(row.get("self_signed")),
                "mismatched": bool(row.get("mismatched")),
            })
            for name in row.get("subject_an", []) or []:
                name = str(name).lower().lstrip("*.")
                if name:
                    items.append({"type": "host", "asset": name, "source": f"certificate SAN of {host}"})
        return items
