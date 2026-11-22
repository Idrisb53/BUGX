"""Trivy – dependency vulnerability analysis of an authorized local source tree."""

import json
from pathlib import Path

from bugx.core.adapters import RunContext, ToolAdapter


class TrivyAdapter(ToolAdapter):
    key = "trivy"
    name = "Trivy"
    module = "vulnerability_analysis"
    category = "Dependency analysis"
    purpose = "Scan a local project directory for vulnerable dependencies"
    binaries = ("trivy",)
    version_args = ("--version",)
    install = {
        "linux": "sudo apt install trivy (Aqua repo) or see aquasecurity.github.io/trivy",
        "windows": "choco install trivy  |  release .zip",
        "darwin": "brew install trivy",
    }
    input_kind = "path"
    sends_traffic = False
    http = False
    default_timeout = 1800

    def _report(self, ctx):
        return ctx.work_dir / "trivy.json"

    def build_args(self, ctx: RunContext, target):
        if not Path(target).is_dir():
            raise ValueError(f"Directory not found: {target}")
        return ["fs", "--scanners", "vuln", "--format", "json", "--quiet", "--output", str(self._report(ctx)), target]

    def evidence_files(self, ctx, target):
        return [self._report(ctx)]

    def parse(self, ctx, stdout, stderr, target):
        path = self._report(ctx)
        if not path.is_file():
            return []
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
        items = []
        for result in data.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                items.append({
                    "type": "finding",
                    "finding": {
                        "title": f"{vuln.get('VulnerabilityID')} in {vuln.get('PkgName')} {vuln.get('InstalledVersion')}",
                        "severity": vuln.get("Severity", "unknown"),
                        "confidence": "High",
                        "category": "outdated_component",
                        "url": f"{target}/{result.get('Target', '')}",
                        "description": vuln.get("Title") or vuln.get("Description", ""),
                        "remediation": f"Upgrade to {vuln.get('FixedVersion')}" if vuln.get("FixedVersion") else "No fixed version published yet.",
                        "references": [vuln["PrimaryURL"]] if vuln.get("PrimaryURL") else [],
                    },
                })
        return items
