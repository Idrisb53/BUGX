"""ProjectDiscovery httpx – HTTP service probing.

On Kali the binary is ``httpx-toolkit``; ``/usr/bin/httpx`` is the unrelated
Python HTTP client, which :meth:`verify_binary` rejects.
"""

from bugx.core.adapters import RunContext, ToolAdapter, json_lines, to_host_port


class HttpxAdapter(ToolAdapter):
    key = "httpx"
    name = "httpx"
    module = "recon"
    category = "HTTP probing"
    purpose = "Probe in-scope hosts for live HTTP services, titles and technologies"
    binaries = ("httpx-toolkit", "httpx")
    install = {
        "linux": "sudo apt install httpx-toolkit  |  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "windows": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "darwin": "brew install httpx",
    }
    input_kind = "host"
    batch = True
    default_timeout = 900

    def verify_binary(self, executable, version_output):
        if "projectdiscovery" not in version_output.lower():
            return (
                f"{executable} is not ProjectDiscovery httpx (likely the Python httpx client). "
                "Install httpx-toolkit or set tools.httpx.path in config/bugx.yaml."
            )
        return None

    def build_args(self, ctx: RunContext, target):
        # Redirects are NOT followed automatically; the Location is recorded
        # and re-validated by the scope gate instead.
        return [
            "-silent", "-json", "-sc", "-title", "-td", "-server", "-ct",
            "-rl", str(ctx.policy.rate_limit), "-t", str(ctx.policy.concurrency),
            "-timeout", "10",
            *ctx.header_args("-H"),
        ]

    def stdin(self, ctx, target):
        # Keep explicit ports (host:8443); httpx probes http/https itself.
        return "\n".join(sorted({to_host_port(t) for t in ctx.targets})) + "\n"

    def parse(self, ctx, stdout, stderr, target):
        gate = ctx.session.gate()
        items = []
        for row in json_lines(stdout):
            url = row.get("url") or ""
            if not url:
                continue
            item = {
                "type": "http_service",
                "asset": url,
                "status_code": row.get("status_code") or row.get("status-code"),
                "title": row.get("title", ""),
                "webserver": row.get("webserver", ""),
                "content_type": row.get("content_type") or row.get("content-type", ""),
                "technologies": row.get("tech", []),
            }
            location = row.get("location")
            if location:
                item["redirect"] = gate.validate_redirect(url, location)
            items.append(item)
        return items
