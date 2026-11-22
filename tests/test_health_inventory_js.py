import json
import urllib.error

import pytest

from bugx.core import health
from bugx.core.results_manager import ScanRecord
from bugx.modules.enumeration import inventory, js_collector


def test_health_structure(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGX_OUTPUT_DIR", str(tmp_path / "out"))
    report = health.run_health()
    items = {row["item"]: row for section in ("system", "configuration", "browser") for row in report[section]}
    assert items["Python"]["status"] == "Installed"
    assert items["Output directory"]["status"] == "Installed"
    assert "python: typer" in items


def test_output_dir_not_writable(monkeypatch, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("BUGX_OUTPUT_DIR", str(blocker / "sub"))
    assert health.output_checks()[0]["status"] == "Error"


def test_invalid_profile_reported(monkeypatch, tmp_path):
    from bugx.core import config

    (tmp_path / "hackerone").mkdir()
    (tmp_path / "hackerone" / "bad.yaml").write_text("program: {}\n")
    monkeypatch.setattr(config, "PROGRAMS_DIR", tmp_path)
    row = [r for r in health.config_checks() if r["item"] == "Program profiles"][0]
    assert row["status"] == "Error" and "bad.yaml" in row["detail"]


def test_inventory_tags_and_dedup(results, session):
    record = ScanRecord(program_id=session.program_id, platform="h1", target="example.com", module="enumeration", tool="katana", status="success")
    record.results = [
        {"type": "url", "asset": "https://www.example.com/login?next=/a#frag", "method": "GET"},
        {"type": "url", "asset": "https://WWW.example.com:443/login?b=1", "method": "POST"},
        {"type": "path", "asset": "https://www.example.com/api/v1/users", "status_code": 200, "content_type": "application/json; charset=utf-8"},
        {"type": "url", "asset": "https://www.example.com/static/app.js"},
        {"type": "url", "asset": "https://evil.com/x"},
    ]
    results.save_scan(record)
    inv = inventory.build_inventory(session, results)
    rows = {e["url"]: e for e in inv["endpoints"]}
    login = rows["https://www.example.com/login"]
    assert login["methods"] == ["GET", "POST"] and login["parameters"] == ["b", "next"]
    assert "login" in login["tags"] and "parameters" in login["tags"]
    assert rows["https://www.example.com/api/v1/users"]["content_types"] == ["application/json"]
    assert "javascript" in rows["https://www.example.com/static/app.js"]["tags"]
    assert rows["https://evil.com/x"]["scope_status"] == "unverified"
    _, path = inventory.save_inventory(session, results)
    assert json.loads(path.read_text())["tool"] == "endpoint-inventory"


def test_js_collector_scope_and_headers(results, session, monkeypatch):
    session.profile["policy"] = {"required_headers": {"X-HackerOne-Research": "idris4hack"}, "rate_limit": 100}
    from bugx.core.policy import load_policy

    session.policy = load_policy(session.profile)
    seen = []

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "application/javascript"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"var a=1;"

    class FakeOpener:
        def open(self, request, timeout=15):
            seen.append((request.full_url, dict(request.header_items())))
            return FakeResponse()

    monkeypatch.setattr(js_collector, "_opener", lambda s: FakeOpener())
    record, _, out_dir = js_collector.collect_js(
        session, ["https://www.example.com/a.js", "https://evil.com/b.js", "https://www.example.com/page"], results)
    assert [u for u, _ in seen] == ["https://www.example.com/a.js"]
    assert seen[0][1]["X-hackerone-research"] == "idris4hack"
    assert len(list(out_dir.glob("*.js"))) == 1
    assert record["blocked_targets"][0]["target"] == "https://evil.com/b.js"


def test_scoped_redirect_handler_blocks(session):
    handler = js_collector._ScopedRedirect(session)
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.com/")


def test_preflight_redirect_results(session, monkeypatch):
    def blocked(sess, url, timeout=15):
        raise urllib.error.HTTPError("https://evil.com/", 302, "Redirect out of scope blocked: https://evil.com/", {}, None)

    monkeypatch.setattr(js_collector, "fetch", blocked)
    assert js_collector.preflight_redirects(session, "https://example.com/out")["status"] == "redirected_out_of_scope"

    def not_found(sess, url, timeout=15):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(js_collector, "fetch", not_found)
    assert js_collector.preflight_redirects(session, "https://example.com/x")["allowed"] is True
