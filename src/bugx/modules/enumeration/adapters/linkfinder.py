"""LinkFinder – extract endpoints from a JavaScript file or page."""

from urllib.parse import urljoin

from bugx.core.adapters import RunContext, ToolAdapter, strip_ansi


class LinkFinderAdapter(ToolAdapter):
    key = "linkfinder"
    name = "LinkFinder"
    module = "enumeration"
    category = "JavaScript analysis"
    purpose = "Extract endpoints referenced in JavaScript"
    binaries = ("linkfinder", "linkfinder.py")
    version_args = ()
    install = {"any": "git clone https://github.com/GerbenJavado/LinkFinder && pipx install ./LinkFinder"}
    input_kind = "url"
    supports_headers = False  # LinkFinder has no custom-header option
    default_timeout = 300

    def build_args(self, ctx: RunContext, target):
        return ["-i", target, "-o", "cli"]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for line in strip_ansi(stdout).splitlines():
            value = line.strip()
            if not value or value.startswith(("[", "Usage", "Error", "Running")) or " " in value:
                continue
            absolute = urljoin(target, value)
            items.append({"type": "endpoint", "asset": absolute, "raw": value, "source": target})
        return items
