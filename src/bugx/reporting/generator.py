"""BUGX report generator: Markdown, HTML, JSON and PDF.

Reports are built only from saved scan records and findings; nothing is
invented. When there are no findings the report says so explicitly.
PDF output prints the HTML report with a locally installed Chromium/Chrome/Edge
in headless mode; if none is available the PDF is skipped with a message.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from bugx import __version__
from bugx.core.authorization import Session
from bugx.core.findings import SEVERITIES
from bugx.core.results_manager import ResultsManager
from bugx.core.runner import ToolRunner
from bugx.integrations.playwright.browser import find_browser

TEMPLATE_DIR = Path(__file__).parent / "templates"
FORMATS = ("markdown", "html", "json", "pdf")

METHODOLOGY = [
    "Program profile, policy and scope reviewed; authorization confirmed for the session.",
    "Every tool input and every discovered asset classified by the BUGX Scope Engine (fail-closed).",
    "Passive reconnaissance first, then rate-limited active discovery of in-scope assets only.",
    "Scanner output stored as 'Needs Review'; only manually reproduced issues are marked 'Validated'.",
    "No destructive payloads, data extraction, denial-of-service or credential attacks.",
]

LIMITATIONS = [
    "Automated tools produce false positives and negatives; unvalidated findings are leads, not confirmed vulnerabilities.",
    "Only assets explicitly in scope were tested; unverified and out-of-scope assets were recorded but not tested.",
    "Coverage depends on which external tools were installed and on configured rate limits and timeouts.",
]


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        # Scanner output contains attacker-controlled text: always escape HTML.
        autoescape=lambda name: bool(name) and name.endswith((".html", ".html.j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def build_context(session: Session, results: ResultsManager, include_unvalidated: bool = True) -> dict:
    scans = results.load_scans(session.program_id, ("recon", "enumeration", "vulnerability_analysis"))
    findings = results.load_findings(session.program_id)
    findings = [f for f in findings if include_unvalidated or f.validation_status == "Validated"]
    findings = [f for f in findings if f.validation_status not in ("False Positive", "Not Reproducible")]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order.get(f.severity, 99), f.title))

    tools = sorted({(s.get("tool"), s.get("tool_version") or "") for s in scans if s.get("status") in ("success", "partial")})
    in_scope, out_scope, unverified = set(), set(), set()
    module_counts: Counter = Counter()
    for scan in scans:
        in_scope.update(scan.get("scope", {}).get("in_scope", []))
        out_scope.update(scan.get("scope", {}).get("out_of_scope", []))
        unverified.update(scan.get("scope", {}).get("unverified", []))
        module_counts[scan.get("module")] += 1

    def bucket(module: str) -> list[dict]:
        return [
            {"tool": s.get("tool"), "status": s.get("status"), "timestamp": s.get("timestamp"),
             "target": s.get("target"), "results": len(s.get("results", [])),
             "in_scope": len(s.get("scope", {}).get("in_scope", [])), "errors": s.get("errors", [])}
            for s in scans if s.get("module") == module
        ]

    severity_counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    validated = sum(1 for f in findings if f.validation_status == "Validated")
    program = session.profile.get("program", {})
    scope = session.profile.get("scope", {})
    return {
        "title": f"BUGX Security Assessment – {session.program_name}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "bugx_version": __version__,
        "program": {"name": session.program_name, "id": session.program_id, "platform": session.platform,
                    "policy_url": program.get("policy_url", ""), "program_url": program.get("program_url", "")},
        "target": session.target,
        "authorization": {"confirmed_at": session.authorized_at or "", "profile_confirmation": session.profile.get("authorization", {})},
        "scope_assets": scope.get("assets", []),
        "scope_exclusions": scope.get("excluded_assets", []),
        "attack_surface": {"in_scope": sorted(in_scope), "out_of_scope": sorted(out_scope), "unverified": sorted(unverified)},
        "recon": bucket("recon"),
        "enumeration": bucket("enumeration"),
        "analysis": bucket("vulnerability_analysis"),
        "tools": [{"name": t, "version": v} for t, v in tools],
        "module_counts": dict(module_counts),
        "findings": [f.to_dict() for f in findings],
        "severity_counts": severity_counts,
        "validated_count": validated,
        "methodology": METHODOLOGY,
        "limitations": LIMITATIONS,
        "scan_count": len(scans),
    }


def _write_pdf(html_path: Path, pdf_path: Path, settings: dict) -> str | None:
    browser = find_browser(settings)
    if not browser:
        return "No Chromium/Chrome/Edge found; PDF skipped (see INSTALLATION.md)."
    args = ["--headless", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()]
    if shutil.which("id") and Path("/proc/self").exists():
        import os

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.insert(0, "--no-sandbox")
    result = ToolRunner.run(browser, args, timeout=120)
    if result.error or not pdf_path.is_file():
        return f"PDF generation failed: {result.error or result.stderr[-300:]}"
    return None


def generate_report(session: Session, results: ResultsManager | None = None,
                    formats: tuple[str, ...] = FORMATS, include_unvalidated: bool = True) -> dict:
    """Write the requested formats and return {format: path or error message}."""
    results = results or ResultsManager()
    context = build_context(session, results, include_unvalidated)
    out_dir = results.reports_dir(session.program_id)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = out_dir / f"bugx_report_{stamp}"
    env = _env()
    written: dict[str, str] = {}

    if "json" in formats:
        path = base.with_suffix(".json")
        path.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
        written["json"] = str(path)
    if "markdown" in formats:
        path = base.with_suffix(".md")
        path.write_text(env.get_template("report.md.j2").render(**context), encoding="utf-8")
        written["markdown"] = str(path)
    if "html" in formats or "pdf" in formats:
        path = base.with_suffix(".html")
        path.write_text(env.get_template("report.html.j2").render(**context), encoding="utf-8")
        written["html"] = str(path)
        if "pdf" in formats:
            pdf = base.with_suffix(".pdf")
            error = _write_pdf(path, pdf, session.settings)
            written["pdf"] = error or str(pdf)
    return written
