import pytest

from bugx.core.findings import Finding
from bugx.modules.validation import engine


def _store(results, session, **kw):
    data = dict(title="Reflected XSS", severity="medium", url="https://www.example.com/s?q=1", source_tool="dalfox", parameter="q")
    data.update(kw)
    finding = Finding(**data)
    results.upsert_findings(session.program_id, [finding])
    return finding


def test_guidance_by_category(results, session):
    assert "marker" in " ".join(engine.guidance_for(_store(results, session)))
    assert engine.guidance_for(Finding(title="weird", severity="low", url="x", source_tool="t"))


def test_scope_recheck(results, session):
    assert engine.recheck_scope(session, _store(results, session))["allowed"] is True
    out = Finding(title="x", severity="low", url="https://admin.example.com/", source_tool="t")
    assert engine.recheck_scope(session, out)["allowed"] is False
    local = Finding(title="x", severity="low", url="/src/app.py:3", source_tool="semgrep")
    assert engine.recheck_scope(session, local)["status"] == "local"


def test_safe_replay_single_get(results, session, monkeypatch):
    finding = _store(results, session)
    calls = []

    def fake_fetch(sess, url, timeout=15):
        calls.append(url)
        return 200, {"Content-Type": "text/html"}, b"<html>bugx</html>"

    monkeypatch.setattr(engine, "fetch", fake_fetch)
    outcome = engine.safe_replay(session, finding, results)
    assert calls == [finding.url] and outcome["status_code"] == 200
    assert "GET https://www.example.com/s?q=1" in open(outcome["evidence"]).read()


def test_replay_refused_out_of_scope_or_non_get(results, session, monkeypatch):
    monkeypatch.setattr(engine, "fetch", lambda *a, **k: pytest.fail("must not send"))
    with pytest.raises(PermissionError):
        engine.safe_replay(session, Finding(title="x", severity="low", url="https://evil.com/", source_tool="t"), results)
    with pytest.raises(PermissionError):
        engine.safe_replay(session, Finding(title="x", severity="low", url="https://example.com/", source_tool="t", method="POST"), results)


def test_status_workflow(results, session):
    finding = _store(results, session)
    with pytest.raises(ValueError):
        engine.set_status(session, results, finding.finding_id, "Validated")
    with pytest.raises(ValueError):
        engine.set_status(session, results, finding.finding_id, "Totally real")
    updated = engine.set_status(session, results, finding.finding_id, "Validated", note="alert fired in test account")
    assert updated.validation_status == "Validated" and updated.confidence == "High"
    fp = engine.set_status(session, results, finding.finding_id, "False Positive", note="WAF reflection only")
    assert [h["to"] for h in fp.validation_history] == ["Validated", "False Positive"]
