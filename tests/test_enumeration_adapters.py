"""Command construction and output parsing for the 10 enumeration adapters."""

import json

import pytest

from bugx.modules.enumeration.registry import ENUMERATION_ADAPTERS

A = {a.key: a for a in ENUMERATION_ADAPTERS}
H1 = {"required_headers": {"X-HackerOne-Research": "idris4hack"}, "rate_limit": 3, "concurrency": 2}


@pytest.fixture
def wordlist(tmp_path, settings):
    path = tmp_path / "words.txt"
    path.write_text("admin\nlogin\n")
    settings["wordlists"]["directories"] = [str(path)]
    return str(path)


def test_registry_has_ten_unique_tools():
    assert [a.key for a in ENUMERATION_ADAPTERS] == [
        "ffuf", "feroxbuster", "dirsearch", "arjun", "paramspider", "kiterunner",
        "linkfinder", "secretfinder", "hakrawler", "gowitness"]


def test_wordlist_required(settings):
    settings["wordlists"]["directories"] = ["/nonexistent/list.txt"]
    ok, message = A["ffuf"].config_status(settings)
    assert not ok and "wordlist" in message


def test_ffuf(ctx, wordlist):
    c = ctx(policy=H1)
    args = A["ffuf"].build_args(c, "https://example.com/")
    assert args[:4] == ["-u", "https://example.com/FUZZ", "-w", wordlist]
    assert args[args.index("-rate") + 1] == "3" and "-H" in args
    row = {"url": "https://example.com/admin", "status": 403, "length": 12, "content-type": "text/html"}
    assert A["ffuf"].parse(c, json.dumps(row), "", None)[0]["status_code"] == 403


def test_feroxbuster(ctx, wordlist):
    c = ctx(policy={**H1, "user_agent": "UA"})
    args = A["feroxbuster"].build_args(c, "https://example.com")
    assert "--no-state" in args and args[args.index("-d") + 1] == "2" and "-a" in args
    rows = '{"type":"response","url":"https://example.com/login","status":200,"method":"GET","headers":{"content-type":"text/html"}}\n{"type":"statistics"}'
    assert [i["asset"] for i in A["feroxbuster"].parse(c, rows, "", None)] == ["https://example.com/login"]


def test_dirsearch_report(ctx):
    c = ctx(policy=H1)
    args = A["dirsearch"].build_args(c, "https://example.com")
    assert "--max-rate" in args and "-H" in args
    A["dirsearch"]._out(c, "https://example.com").write_text(json.dumps(
        {"results": [{"url": "https://example.com/.git/", "status": 403, "content-length": 10}]}))
    assert A["dirsearch"].parse(c, "", "", "https://example.com")[0]["asset"] == "https://example.com/.git/"


def test_arjun(ctx):
    c = ctx(policy=H1)
    args = A["arjun"].build_args(c, "https://example.com/search")
    assert args[args.index("--headers") + 1] == "X-HackerOne-Research: idris4hack"
    A["arjun"]._out(c, "https://example.com/search").write_text(json.dumps(
        {"https://example.com/search": {"params": ["q", "debug"], "method": "GET"}}))
    assert [i["parameter"] for i in A["arjun"].parse(c, "", "", "https://example.com/search")] == ["q", "debug"]


def test_paramspider_passive(ctx):
    c = ctx()
    assert A["paramspider"].sends_traffic is False
    out = "[INFO] start\nhttps://example.com/p?id=FUZZ&x=FUZZ\nhttps://example.com/no-params\n"
    items = A["paramspider"].parse(c, out, "", "example.com")
    assert len(items) == 1 and items[0]["parameters"] == ["id", "x"]


def test_kiterunner_needs_routes(ctx, settings, tmp_path):
    assert A["kiterunner"].config_status(settings)[0] is False
    routes = tmp_path / "routes.kite"
    routes.write_text("x")
    settings["wordlists"]["api_routes"] = str(routes)
    assert A["kiterunner"].config_status(settings)[0] is True
    c = ctx(policy=H1)
    assert A["kiterunner"].build_args(c, "https://example.com")[:2] == ["scan", "https://example.com"]
    out = '{"method":"GET","path":"/api/v1/users","status":200}'
    assert A["kiterunner"].parse(c, out, "", "https://example.com")[0]["asset"] == "https://example.com/api/v1/users"


def test_linkfinder_resolves_relative(ctx):
    c = ctx()
    out = "/api/v2/me\nhttps://cdn.other.net/x.js\nRunning against: x\n"
    assets = [i["asset"] for i in A["linkfinder"].parse(c, out, "", "https://example.com/app.js")]
    assert assets == ["https://example.com/api/v2/me", "https://cdn.other.net/x.js"]


def test_secretfinder_redacts(ctx):
    c = ctx()
    out = "google_api -> AIzaSyD-THIS-IS-A-FAKE-KEY-123456\n"
    items = A["secretfinder"].parse(c, out, "", "https://example.com/app.js")
    dumped = json.dumps(items)
    assert "THIS-IS-A-FAKE-KEY" not in dumped and "AIza" in dumped
    finding = [i for i in items if i["type"] == "finding"][0]["finding"]
    assert finding["confidence"] == "Tentative" and finding["category"] == "secrets"


def test_hakrawler_stdin_headers(ctx):
    c = ctx(policy={**H1, "user_agent": "UA"})
    assert A["hakrawler"].stdin(c, "https://example.com") == "https://example.com\n"
    args = A["hakrawler"].build_args(c, "https://example.com")
    assert args[args.index("-h") + 1] == "X-HackerOne-Research: idris4hack;;User-Agent: UA"
    out = "[href] https://example.com/a\nhttps://example.com/b\njunk\n"
    assert [i["asset"] for i in A["hakrawler"].parse(c, out, "", "https://example.com")] == [
        "https://example.com/a", "https://example.com/b"]


def test_gowitness_versions_and_screenshots(ctx):
    c = ctx(options={"tool_version": "3.0.5"}, policy=H1)
    assert A["gowitness"].build_args(c, "https://example.com")[:2] == ["scan", "single"]
    c2 = ctx(options={"tool_version": "2.5.1"})
    assert A["gowitness"].build_args(c2, "https://example.com")[0] == "single"
    (A["gowitness"]._shots(c) / "https-example.com.png").write_bytes(b"\x89PNG")
    assert A["gowitness"].parse(c, "", "", "https://example.com")[0]["type"] == "screenshot"
