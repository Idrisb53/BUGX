"""Nuclei – template-based detection with an explicitly selected safe template set."""

from pathlib import Path

from bugx.core.adapters import RunContext, ToolAdapter, json_lines

TEMPLATE_DIRS = (Path.home() / "nuclei-templates", Path.home() / ".local" / "nuclei-templates")


class NucleiAdapter(ToolAdapter):
    key = "nuclei"
    name = "Nuclei"
    module = "vulnerability_analysis"
    category = "Template-based detection"
    purpose = "Safe template set: exposures, misconfigurations, technologies, TLS (no DoS/fuzz/intrusive)"
    binaries = ("nuclei",)
    install = {
        "linux": "sudo apt install nuclei && nuclei -update-templates",
        "windows": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
        "darwin": "brew install nuclei && nuclei -update-templates",
    }
    input_kind = "url"
    intrusive = True
    default_timeout = 3600

    def config_status(self, settings):
        cfg = settings.get("nuclei") or {}
        if not cfg.get("templates") and not cfg.get("tags"):
            return False, "Select a safe template set: nuclei.templates or nuclei.tags in config/bugx.yaml."
        if not cfg.get("templates") and not any(d.is_dir() for d in TEMPLATE_DIRS):
            return False, "Nuclei templates not downloaded. Run: nuclei -update-templates"
        return True, "templates: " + ",".join(cfg.get("templates") or cfg.get("tags"))

    def build_args(self, ctx: RunContext, target):
        cfg = ctx.settings.get("nuclei") or {}
        args = ["-u", target, "-jsonl", "-silent", "-nc", "-duc", "-ni",
                "-rl", str(ctx.policy.rate_limit), "-c", str(ctx.policy.concurrency), "-timeout", "10"]
        if cfg.get("templates"):
            args += ["-t", ",".join(cfg["templates"])]
        else:
            args += ["-tags", ",".join(cfg.get("tags", []))]
        if cfg.get("exclude_tags"):
            args += ["-etags", ",".join(cfg["exclude_tags"])]
        if cfg.get("severity"):
            args += ["-s", ",".join(cfg["severity"])]
        return [*args, *ctx.header_args("-H")]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for row in json_lines(stdout):
            info = row.get("info") or {}
            url = row.get("matched-at") or row.get("host") or target
            refs = info.get("reference") or []
            items.append({
                "type": "finding",
                "asset": url,
                "finding": {
                    "title": info.get("name") or row.get("template-id", "Nuclei match"),
                    "severity": info.get("severity", "info"),
                    "confidence": "Medium",
                    "url": url,
                    "method": (row.get("type") == "http" and "GET") or "GET",
                    "description": (info.get("description") or "").strip()
                    + f"\n\nTemplate: {row.get('template-id', '')}"
                    + (f" (matcher: {row['matcher-name']})" if row.get("matcher-name") else ""),
                    "references": refs if isinstance(refs, list) else [str(refs)],
                    "remediation": (info.get("remediation") or "").strip(),
                    "evidence": [f"nuclei template {row.get('template-id', '')} matched at {url}"],
                },
            })
        return items
