"""Playwright MCP integration: availability, parsing and scope enforcement (MCP mocked)."""

import sys
import types
from contextlib import asynccontextmanager

from bugx.integrations.playwright import browser

NAV = """### Page
- Page URL: {url}
- Page Title: Mock Target
"""
SNAP = """### Page
- Page URL: {url}
- Page Title: Mock Target
### Snapshot
```yaml
- generic [ref=e1]:
  - link "Login" [ref=e3]:
    - /url: /login
  - link "Admin" [ref=e4]:
    - /url: https://admin.example.com/
  - link "Ext" [ref=e5]:
    - /url: https://evil.net/x
  - textbox "Email" [ref=e6]
  - button "Go" [ref=e7]
```"""
CONSOLE = "### Result\nTotal messages: 1 (Errors: 1, Warnings: 0)\n\n[ERROR] boom @ https://example.com/:4\n"


def test_parsers():
    text = SNAP.format(url="https://example.com/")
    assert browser.parse_page_url(text) == "https://example.com/"
    assert browser.parse_title(text) == "Mock Target"
    assert browser.parse_links(text, "https://example.com/") == [
        "https://admin.example.com/", "https://evil.net/x", "https://example.com/login"]
    assert browser.parse_form_controls(text) == ['textbox "Email"']
    assert browser.parse_console(CONSOLE) == ["[ERROR] boom @ https://example.com/:4"]


def test_availability_reports_missing(settings, monkeypatch):
    monkeypatch.setattr(browser, "sdk_available", lambda: False)
    monkeypatch.setattr(browser, "command_available", lambda cmd: False)
    monkeypatch.setattr(browser, "find_browser", lambda s=None: None)
    state = browser.availability(settings)
    assert state["available"] is False and len(state["missing"]) == 3


def test_inspection_skipped_when_unavailable(session, results, monkeypatch):
    monkeypatch.setattr(browser, "availability", lambda s: {"available": False, "missing": ["npx"]})
    record, _ = browser.inspect_pages(session, ["https://example.com/"], results)
    assert record["status"] == "skipped"


def test_inspection_requires_session_and_scope(session, results, monkeypatch):
    monkeypatch.setattr(browser, "availability", lambda s: {"available": True, "missing": []})
    record, _ = browser.inspect_pages(session, ["https://evil.net/"], results)
    assert record["status"] == "blocked"
    session.session_authorized = False
    record, _ = browser.inspect_pages(session, ["https://example.com/"], results)
    assert record["status"] == "blocked"


class _Content:
    def __init__(self, text):
        self.text = text


class _Result:
    def __init__(self, text, error=False):
        self.content = [_Content(text)]
        self.is_error = error


def _install_fake_mcp(monkeypatch, calls, redirect_to=None):
    class FakeClient:
        def __init__(self, read, write):
            self.url = "about:blank"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def initialize(self):
            return None

        async def call_tool(self, name, args):
            calls.append((name, args))
            if name == "browser_navigate":
                self.url = args["url"]
                if redirect_to and args["url"] != "about:blank":
                    self.url = redirect_to
                return _Result(NAV.format(url=self.url))
            if name == "browser_snapshot":
                return _Result(SNAP.format(url=self.url))
            if name == "browser_console_messages":
                return _Result(CONSOLE)
            return _Result("ok")

    @asynccontextmanager
    async def fake_stdio(params):
        calls.append(("spawn", params.args))
        yield (None, None)

    mcp_mod = types.ModuleType("mcp")
    mcp_mod.ClientSession = FakeClient
    mcp_mod.StdioServerParameters = lambda **kw: types.SimpleNamespace(**kw)
    stdio_mod = types.ModuleType("mcp.client.stdio")
    stdio_mod.stdio_client = fake_stdio
    monkeypatch.setitem(sys.modules, "mcp", mcp_mod)
    monkeypatch.setitem(sys.modules, "mcp.client", types.ModuleType("mcp.client"))
    monkeypatch.setitem(sys.modules, "mcp.client.stdio", stdio_mod)
    monkeypatch.setattr(browser, "availability", lambda s: {"available": True, "missing": []})
    monkeypatch.setattr(browser.time, "sleep", lambda s: None)
    monkeypatch.setattr(browser, "preflight_redirects", lambda sess, url: {"allowed": True, "status": 200, "reason": "ok"})


def test_inspection_collects_and_classifies(session, results, monkeypatch):
    calls = []
    _install_fake_mcp(monkeypatch, calls)
    session.profile["policy"] = {"required_headers": {"X-HackerOne-Research": "idris4hack"}}
    from bugx.core.policy import load_policy

    session.policy = load_policy(session.profile)
    record, _ = browser.inspect_pages(session, ["https://example.com/"], results, max_pages=3, follow_links=True)
    assert record["status"] == "success"
    page = [r for r in record["results"] if r["type"] == "page"][0]
    assert page["links_in_scope"] == ["https://example.com/login"]
    assert page["links_out_of_scope"] == ["https://admin.example.com/"]
    assert page["links_unverified"] == ["https://evil.net/x"]
    navigated = [a["url"] for n, a in calls if n == "browser_navigate"]
    assert "https://admin.example.com/" not in navigated and "https://evil.net/x" not in navigated
    used = {n for n, _ in calls if n != "spawn"}
    assert used <= browser.ALLOWED_TOOLS
    spawn_args = [a for n, a in calls if n == "spawn"][0]
    assert "--isolated" in spawn_args and "--config" in spawn_args
    config_file = spawn_args[spawn_args.index("--config") + 1]
    assert "X-HackerOne-Research" in open(config_file).read()


def test_redirect_out_of_scope_is_abandoned(session, results, monkeypatch):
    calls = []
    _install_fake_mcp(monkeypatch, calls, redirect_to="https://evil.net/landing")
    record, _ = browser.inspect_pages(session, ["https://example.com/"], results)
    page = [r for r in record["results"] if r["type"] == "page"][0]
    assert page["status"] == "redirected_out_of_scope"
    assert ("browser_snapshot", {}) not in calls  # nothing collected from the out-of-scope page
    assert ("browser_navigate", {"url": "about:blank"}) in calls


def test_server_redirect_caught_by_preflight(session, results, monkeypatch):
    calls = []
    _install_fake_mcp(monkeypatch, calls)
    monkeypatch.setattr(browser, "preflight_redirects", lambda sess, url: {
        "allowed": False, "status": "redirected_out_of_scope", "reason": "Redirect out of scope blocked: https://evil.net/"})
    record, _ = browser.inspect_pages(session, ["https://example.com/out"], results)
    page = [r for r in record["results"] if r["type"] == "page"][0]
    assert page["status"] == "redirected_out_of_scope"
    assert not [c for c in calls if c[0] == "browser_navigate"]  # browser never navigated
