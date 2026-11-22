import json
from pathlib import Path

from bugx.core.findings import Finding
from bugx.core.results_manager import ScanRecord
from bugx.reporting import generator


def _scan(results, session, tool="subfinder", module="recon"):
    record = ScanRecord(program_id=session.program_id, platform="hackerone", target="example.com",
                        module=module, tool=tool, status="success", tool_version="2.16.0")
    record.scope = {"in_scope": ["www.example.com"], "out_of_scope": ["admin.example.com"], "unverified": ["evil.com"]}
    results.save_scan(record)


def test_no_findings_report_says_so(results, session, monkeypatch):
    monkeypatch.setattr(generator, "find_browser", lambda settings=None: None)
    _scan(results, session)
    written = generator.generate_report(session, results)
    md = Path(written["markdown"]).read_text()
    html = Path(written["html"]).read_text()
    assert "No vulnerabilities were identified" in md and "No vulnerabilities were identified" in html
    assert "BUGX-" not in md  # no invented findings
    assert "PDF skipped" in written["pdf"]
    data = json.loads(Path(written["json"]).read_text())
    assert data["findings"] == [] and data["attack_surface"]["out_of_scope"] == ["admin.example.com"]
    assert data["tools"] == [{"name": "subfinder", "version": "2.16.0"}]


def test_findings_rendered_and_escaped(results, session, monkeypatch):
    monkeypatch.setattr(generator, "find_browser", lambda settings=None: None)
    evil = Finding(title='XSS <script>alert(1)</script>', severity="high", url="https://www.example.com/?q=1",
                   source_tool="dalfox", parameter="q", description="desc")
    fp = Finding(title="Noise", severity="low", url="https://www.example.com/x", source_tool="nikto")
    results.upsert_findings(session.program_id, [evil, fp])
    results.update_finding_status(session.program_id, fp.finding_id, "False Positive", note="n")
    written = generator.generate_report(session, results, ("html", "markdown", "json"))
    html = Path(written["html"]).read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    md = Path(written["markdown"]).read_text()
    assert evil.finding_id in md and "Noise" not in md  # false positives excluded
    assert "A03:2021" in md and "not scored (insufficient evidence)" in md
    data = json.loads(Path(written["json"]).read_text())
    assert data["severity_counts"]["High"] == 1


def test_validated_only(results, session):
    a = Finding(title="A", severity="medium", url="https://www.example.com/a", source_tool="t")
    b = Finding(title="B", severity="medium", url="https://www.example.com/b", source_tool="t")
    results.upsert_findings(session.program_id, [a, b])
    results.update_finding_status(session.program_id, a.finding_id, "Validated", note="ok")
    ctx = generator.build_context(session, results, include_unvalidated=False)
    assert [f["title"] for f in ctx["findings"]] == ["A"]


def test_pdf_with_headless_browser(results, session, monkeypatch):
    monkeypatch.setattr(generator, "find_browser", lambda settings=None: "/usr/bin/chromium")
    from bugx.core.runner import ToolResult

    def fake_run(tool, args, timeout=180, **kw):
        out = [a for a in args if a.startswith("--print-to-pdf=")][0].split("=", 1)[1]
        Path(out).write_bytes(b"%PDF-1.4")
        assert "--headless" in args
        return ToolResult(tool=tool, success=True, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(generator.ToolRunner, "run", staticmethod(fake_run))
    written = generator.generate_report(session, results, ("pdf",))
    assert written["pdf"].endswith(".pdf") and Path(written["pdf"]).read_bytes().startswith(b"%PDF")
