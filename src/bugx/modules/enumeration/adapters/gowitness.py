"""GoWitness – screenshots of in-scope web applications (evidence only)."""

from bugx.core.adapters import RunContext, ToolAdapter


class GoWitnessAdapter(ToolAdapter):
    key = "gowitness"
    name = "GoWitness"
    module = "enumeration"
    category = "Screenshots"
    purpose = "Capture page screenshots for evidence"
    binaries = ("gowitness",)
    version_args = ("version",)
    install = {
        "linux": "go install github.com/sensepost/gowitness@latest (needs Chrome/Chromium)",
        "windows": "Download gowitness.exe from github.com/sensepost/gowitness/releases (needs Chrome)",
        "darwin": "go install github.com/sensepost/gowitness@latest",
    }
    input_kind = "url"
    default_timeout = 300

    def _shots(self, ctx):
        path = ctx.work_dir / "screenshots"
        path.mkdir(exist_ok=True)
        return path

    def build_args(self, ctx: RunContext, target):
        version = str(ctx.options.get("tool_version", ""))
        shots = str(self._shots(ctx))
        if version.startswith(("2.", "1.")):
            return ["single", target, "-P", shots]
        args = ["scan", "single", "--url", target, "--screenshot-path", shots]
        for header in ctx.policy.header_list():
            args += ["--chrome-header", header]
        return args

    def parse(self, ctx, stdout, stderr, target):
        return [
            {"type": "screenshot", "asset": target, "path": str(path)}
            for path in sorted(self._shots(ctx).glob("*"))
            if path.suffix.lower() in (".png", ".jpg", ".jpeg")
        ]
