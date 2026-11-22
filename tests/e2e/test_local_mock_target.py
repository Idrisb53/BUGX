"""Phase 11 end-to-end tests: REAL installed tools against a LOCAL mock target.

Everything runs against http://localhost:<random port>; no external traffic.
Each test is skipped when its tool is not installed. The mock server records
request headers so we can prove the program's required header is sent.

Run only these:  pytest -m e2e
"""

import json
import shutil
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from bugx.core.adapters import run_adapter
from bugx.core.authorization import Session
from bugx.core.config import DEFAULT_SETTINGS
from bugx.modules.analysis.registry import ANALYSIS_ADAPTERS
from bugx.modules.enumeration.registry import ENUMERATION_ADAPTERS
from bugx.modules.recon.registry import RECON_ADAPTERS

pytestmark = pytest.mark.e2e

ADAPTERS = {a.key: a for a in [*RECON_ADAPTERS, *ENUMERATION_ADAPTERS, *ANALYSIS_ADAPTERS]}
HEADER = ("X-HackerOne-Research", "bugx-e2e")

PAGES = {
    "/": ("text/html", 200, '<html><head><title>Mock Target</title><script src="/static/app.js"></script></head><body>'
          '<a href="/login">Login</a> <a href="/api/v1/users">API</a> <a href="/search?q=test">Search</a>'
          '<a href="https://evil.example.net/x">External</a>'
          '<form action="/search" method="get"><input name="q"><button>Go</button></form></body></html>'),
    "/login": ("text/html", 200, "<html><title>Login</title><form method=post><input name=user><input type=password name=pw></form></html>"),
    "/admin": ("text/html", 403, "forbidden"),
    "/api/v1/users": ("application/json", 200, '{"users": []}'),
    "/static/app.js": ("application/javascript", 200, 'fetch("/api/v1/profile"); var u="/internal/debug";'),
    "/robots.txt": ("text/plain", 200, "User-agent: *\nDisallow: /admin\n"),
}


class Handler(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Handler.seen.append({"path": self.path, "header": self.headers.get(HEADER[0]), "ua": self.headers.get("User-Agent")})
        parts = urlsplit(self.path)
        if parts.path == "/out":
            self.send_response(302)
            self.send_header("Location", "https://evil.example.net/landing")
            self.end_headers()
            return
        if parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            body = "<html><title>Search</title>Results for " + q.replace("<", "&lt;").replace(">", "&gt;") + "</html>"
            content = ("text/html", 200, body)
        else:
            content = PAGES.get(parts.path, ("text/html", 404, "not found"))
        ctype, status, body = content
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


@pytest.fixture(scope="module")
def server():
    """Mock target on localhost only (both ::1 and 127.0.0.1, same port)."""
    servers = []
    for _ in range(20):
        try:
            v4 = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            port = v4.server_address[1]
            servers = [v4]
            try:
                servers.append(V6Server(("::1", port), Handler))
            except OSError:
                pass  # no IPv6 loopback available
            break
        except OSError:
            for srv in servers:
                srv.server_close()
            servers = []
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{port}"
    for srv in servers:
        srv.shutdown()


@pytest.fixture
def e2e_session(tmp_path):
    import copy

    settings = copy.deepcopy(DEFAULT_SETTINGS)
    words = tmp_path / "words.txt"
    words.write_text("login\nadmin\napi\nstatic\nrobots.txt\nnothere\n")
    settings["wordlists"]["directories"] = [str(words)]
    profile = {
        "program": {"id": "mock-local", "name": "Mock", "platform": "custom",
                    "program_url": "http://localhost", "policy_url": "http://localhost/policy"},
        "authorization": {"user_confirmed": True, "policy_reviewed": True},
        "scope": {"assets": [{"type": "domain", "value": "localhost", "match": "exact", "eligible": True}],
                  "excluded_assets": []},
        "policy": {"required_headers": {HEADER[0]: HEADER[1]}, "rate_limit": 20, "concurrency": 2,
                   "automated_scanning": True},
    }
    session = Session(profile=profile, profile_path="mock.yaml", target="localhost", settings=settings)
    session.confirm_authorization()
    Handler.seen.clear()
    return session


def _need(key, settings):
    status = ADAPTERS[key].status(settings)
    if status.status != "Installed":
        pytest.skip(f"{key}: {status.status} {status.message}")


def _run(key, session, results, targets, **options):
    record, _ = run_adapter(ADAPTERS[key], session, targets, results=results, options={"timeout": 240, **options})
    assert record["status"] == "success", record["errors"]
    return record


def _header_seen():
    return any(r["header"] == HEADER[1] for r in Handler.seen) and all(r["header"] == HEADER[1] for r in Handler.seen)


def test_httpx_probe(server, e2e_session, results):
    _need("httpx", e2e_session.settings)
    record = _run("httpx", e2e_session, results, [server.split("//")[1]])
    urls = [r["asset"] for r in record["results"]]
    assert any(u.startswith("http://localhost") for u in urls)
    assert record["results"][0]["title"] == "Mock Target"
    assert _header_seen()


def test_katana_crawl_stays_in_scope(server, e2e_session, results):
    _need("katana", e2e_session.settings)
    record = _run("katana", e2e_session, results, [server + "/"], depth=2)
    assets = {r["asset"] for r in record["results"]}
    assert any(a.endswith("/login") for a in assets)
    assert not any("evil.example.net" in p["path"] for p in Handler.seen)
    assert _header_seen()


@pytest.mark.parametrize("tool", ["ffuf", "feroxbuster"])
def test_content_discovery(tool, server, e2e_session, results):
    _need(tool, e2e_session.settings)
    record = _run(tool, e2e_session, results, [server + "/"])
    found = {r["asset"].rstrip("/").rsplit("/", 1)[-1]: r["status_code"] for r in record["results"]}
    assert found.get("login") == 200 and found.get("admin") == 403
    assert "nothere" not in found
    assert _header_seen()


def test_whatweb(server, e2e_session, results):
    _need("whatweb", e2e_session.settings)
    record = _run("whatweb", e2e_session, results, [server + "/"])
    assert record["results"] and "Title" in record["results"][0]["technologies"]
    assert _header_seen()


def test_nmap_localhost(server, e2e_session, results):
    _need("nmap", e2e_session.settings)
    port = int(server.rsplit(":", 1)[1])
    record = _run("nmap", e2e_session, results, ["localhost"], top_ports=1000)
    assert isinstance(record["results"], list)  # random high port may not be in top ports
    assert record["exit_code"] == 0 and port > 0


def test_nuclei_with_local_template(server, e2e_session, results, tmp_path):
    _need("nuclei", e2e_session.settings)
    template = tmp_path / "mock-title.yaml"
    template.write_text(
        "id: bugx-mock-title\ninfo:\n  name: BUGX mock title detected\n  author: bugx\n  severity: info\n"
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: word\n"
        "        words:\n          - \"Mock Target\"\n")
    e2e_session.settings["nuclei"]["templates"] = [str(template)]
    e2e_session.active_scanning_confirmed = True
    record = _run("nuclei", e2e_session, results, [server + "/"])
    findings = results.load_findings("mock-local")
    assert record["findings"] and findings[0].title == "BUGX mock title detected"
    assert findings[0].validation_status == "Needs Review"
    assert _header_seen()


def test_sqlmap_detection_only_finds_nothing(server, e2e_session, results):
    _need("sqlmap", e2e_session.settings)
    e2e_session.active_scanning_confirmed = True
    record = _run("sqlmap", e2e_session, results, [server + "/search?q=test"])
    assert record["findings"] == []
    assert any(r["header"] == HEADER[1] for r in Handler.seen)
    assert not any("dump" in arg for arg in record["command"])


def test_out_of_scope_never_contacted(server, e2e_session, results):
    _need("httpx", e2e_session.settings)
    record, _ = run_adapter(ADAPTERS["httpx"], e2e_session, ["127.0.0.1", "evil.example.net"], results=results)
    assert record["status"] == "blocked" and Handler.seen == []


def test_playwright_mcp_real_browser(server, e2e_session, results):
    from bugx.integrations.playwright.browser import availability, inspect_pages

    state = availability(e2e_session.settings)
    if not state["available"] or not shutil.which("npx"):
        pytest.skip("Playwright MCP not available: " + "; ".join(state["missing"]))
    record, _ = inspect_pages(e2e_session, [server + "/", server + "/out"], results, max_pages=3)
    pages = {p["requested_url"]: p for p in record["results"] if p["type"] == "page"}
    home = pages[server + "/"]
    assert home["status"] == "inspected" and home["title"] == "Mock Target"
    assert any(link.endswith("/login") for link in home["links_in_scope"])
    assert "https://evil.example.net/x" in home["links_unverified"]
    assert home["screenshot"] and home["form_controls"]
    assert pages[server + "/out"]["status"] == "redirected_out_of_scope"
    assert all(r["header"] == HEADER[1] for r in Handler.seen if not r["path"].startswith("/favicon"))


def test_full_pipeline_report(server, e2e_session, results):
    _need("httpx", e2e_session.settings)
    _need("katana", e2e_session.settings)
    _run("httpx", e2e_session, results, ["localhost:" + server.rsplit(":", 1)[1]])
    _run("katana", e2e_session, results, [server + "/"], depth=2)
    from bugx.modules.enumeration.inventory import build_inventory
    from bugx.reporting.generator import generate_report

    inventory = build_inventory(e2e_session, results)
    assert inventory["summary"]["login"] >= 1
    written = generate_report(e2e_session, results, ("markdown", "json", "html"))
    data = json.loads(open(written["json"]).read())
    assert {t["name"] for t in data["tools"]} >= {"httpx", "katana"}
    assert data["findings"] == []
    assert "No vulnerabilities were identified" in open(written["markdown"]).read()
