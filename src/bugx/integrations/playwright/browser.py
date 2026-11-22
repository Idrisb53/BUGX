"""Scope-restricted browser inspection through the Playwright MCP server.

BUGX starts ``@playwright/mcp`` itself (stdio) and only ever calls this
allow-list of tools::

    browser_navigate, browser_snapshot, browser_take_screenshot,
    browser_console_messages, browser_close

It never calls form-filling, typing, clicking, file upload, JavaScript
evaluation or ``browser_run_code_unsafe``. Playwright's ``--allowed-origins``
is *not* a security boundary and does not cover redirects, so:

1. before each navigation BUGX sends one scope-checked preflight GET whose
   redirect handler refuses out-of-scope locations (server-side redirects are
   caught before the browser ever starts the navigation), and
2. after navigation the final page URL is re-checked (client-side redirects);
   out-of-scope pages are left immediately and nothing is collected from them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlsplit

from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager, ScanRecord
from bugx.integrations.mcp.client import command_available, is_error, sdk_available, text_of
from bugx.modules.enumeration.js_collector import preflight_redirects

log = logging.getLogger("bugx.browser")

ALLOWED_TOOLS = frozenset(
    {"browser_navigate", "browser_snapshot", "browser_take_screenshot", "browser_console_messages", "browser_close"}
)
FORM_ROLES = ("textbox", "searchbox", "combobox", "checkbox", "radio", "spinbutton", "slider", "switch")

BROWSER_CANDIDATES = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "msedge", "microsoft-edge",
)
WINDOWS_BROWSERS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)

_PAGE_URL = re.compile(r"^- Page URL:\s*(\S+)", re.M)
_PAGE_TITLE = re.compile(r"^- Page Title:\s*(.*)$", re.M)
_LINK_URL = re.compile(r"^\s*- /url:\s*(\S+)\s*$", re.M)
_CONSOLE = re.compile(r"^\[(ERROR|WARNING)\]\s*(.+)$", re.M)


def find_browser(settings: dict | None = None) -> str | None:
    configured = ((settings or {}).get("playwright_mcp") or {}).get("executable_path")
    if configured and Path(configured).is_file():
        return configured
    for name in BROWSER_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    for path in WINDOWS_BROWSERS:
        if Path(path).is_file():
            return path
    return None


def availability(settings: dict) -> dict:
    """Report whether browser inspection can run (no network access)."""
    cfg = settings.get("playwright_mcp") or {}
    command = list(cfg.get("command") or [])
    status = {
        "mcp_sdk": sdk_available(),
        "launcher": command_available(command),
        "launcher_command": " ".join(command),
        "browser": find_browser(settings),
    }
    missing = []
    if not status["mcp_sdk"]:
        missing.append("Python MCP SDK (pip install 'bugx-cli[browser]')")
    if not status["launcher"]:
        missing.append(f"{command[0] if command else 'npx'} (install Node.js 18+)")
    if not status["browser"]:
        missing.append("Chromium/Chrome/Edge (or set playwright_mcp.executable_path)")
    status["available"] = not missing
    status["missing"] = missing
    return status


@dataclass
class PageReport:
    requested_url: str
    final_url: str = ""
    title: str = ""
    status: str = "pending"  # inspected | blocked | redirected_out_of_scope | error
    reason: str = ""
    links_in_scope: list[str] = field(default_factory=list)
    links_out_of_scope: list[str] = field(default_factory=list)
    links_unverified: list[str] = field(default_factory=list)
    form_controls: list[str] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    screenshot: str = ""
    snapshot_file: str = ""


def parse_page_url(text: str) -> str:
    match = _PAGE_URL.search(text or "")
    return match.group(1) if match else ""


def parse_title(text: str) -> str:
    match = _PAGE_TITLE.search(text or "")
    return match.group(1).strip() if match else ""


def parse_links(snapshot: str, base_url: str) -> list[str]:
    links = set()
    for raw in _LINK_URL.findall(snapshot or ""):
        absolute, _ = urldefrag(urljoin(base_url, raw))
        if urlsplit(absolute).scheme in ("http", "https"):
            links.add(absolute)
    return sorted(links)


def parse_form_controls(snapshot: str) -> list[str]:
    controls = []
    for line in (snapshot or "").splitlines():
        stripped = line.strip().lstrip("- ").strip()
        for role in FORM_ROLES:
            if stripped.startswith(role + " ") or stripped.startswith(role + "[") or stripped == role:
                controls.append(stripped.split(" [ref=")[0])
                break
    return controls


def parse_console(text: str) -> list[str]:
    return [f"[{level}] {message.strip()}" for level, message in _CONSOLE.findall(text or "")]


def _server_args(settings: dict, session: Session, out_dir: Path, config_path: Path) -> list[str]:
    cfg = settings.get("playwright_mcp") or {}
    args = list(cfg.get("command") or ["npx", "-y", "@playwright/mcp@0.0.86"])[1:]
    args += ["--isolated", "--output-dir", str(out_dir), "--config", str(config_path), "--block-service-workers"]
    if cfg.get("headless", True):
        args.append("--headless")
    browser = find_browser(settings)
    if browser:
        args += ["--executable-path", browser]
    return args


def _write_config(session: Session, path: Path) -> None:
    context: dict = {}
    if session.policy.required_headers:
        context["extraHTTPHeaders"] = dict(session.policy.required_headers)
    if session.policy.user_agent:
        context["userAgent"] = session.policy.user_agent
    path.write_text(json.dumps({"browser": {"contextOptions": context}}), encoding="utf-8")


async def _inspect(session: Session, urls: list[str], out_dir: Path, settings: dict, max_pages: int, follow_links: bool) -> list[PageReport]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    gate = session.gate()
    config_path = out_dir / "playwright-mcp.json"
    _write_config(session, config_path)
    command = list((settings.get("playwright_mcp") or {}).get("command") or ["npx"])
    params = StdioServerParameters(
        command=command[0], args=_server_args(settings, session, out_dir, config_path), cwd=str(out_dir)
    )
    delay = 1.0 / max(1, session.policy.rate_limit)
    queue = list(dict.fromkeys(urls))
    visited: set[str] = set()
    reports: list[PageReport] = []

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()

            async def call(tool: str, arguments: dict):
                if tool not in ALLOWED_TOOLS:
                    raise PermissionError(f"Browser tool not allowed: {tool}")
                return await client.call_tool(tool, arguments)

            while queue and len(reports) < max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                report = PageReport(requested_url=url)
                reports.append(report)

                check = gate.check(url)
                if check.get("allowed") is not True:
                    report.status, report.reason = "blocked", str(check.get("reason"))
                    continue

                pre = preflight_redirects(session, url)
                if pre.get("allowed") is not True:
                    report.status, report.reason = str(pre.get("status")), str(pre.get("reason"))
                    continue

                result = await call("browser_navigate", {"url": url})
                text = text_of(result)
                report.final_url = parse_page_url(text) or url
                if is_error(result):
                    report.status, report.reason = "error", text[:300]
                    continue

                # Re-validate after redirects / client-side navigation.
                final_check = gate.check(report.final_url)
                if final_check.get("allowed") is not True:
                    report.status = "redirected_out_of_scope"
                    report.reason = f"Landed on {report.final_url}: {final_check.get('reason')}"
                    await call("browser_navigate", {"url": "about:blank"})
                    continue

                snapshot = text_of(await call("browser_snapshot", {}))
                report.title = parse_title(snapshot) or parse_title(text)
                snap_file = out_dir / f"snapshot_{len(reports)}.txt"
                snap_file.write_text(snapshot, encoding="utf-8")
                report.snapshot_file = str(snap_file)

                buckets = gate.classify_many(parse_links(snapshot, report.final_url))
                report.links_in_scope = buckets["in_scope"]
                report.links_out_of_scope = buckets["out_of_scope"]
                report.links_unverified = buckets["unverified"]
                report.form_controls = parse_form_controls(snapshot)
                report.console_errors = parse_console(text_of(await call("browser_console_messages", {"level": "error"})))

                shot_name = f"screenshot_{len(reports)}.png"
                await call("browser_take_screenshot", {"filename": shot_name, "type": "png"})
                if (out_dir / shot_name).is_file():
                    report.screenshot = str(out_dir / shot_name)
                report.status = "inspected"

                if follow_links:
                    queue.extend(link for link in report.links_in_scope if link not in visited)
                time.sleep(delay)

            await call("browser_close", {})
    return reports


def inspect_pages(
    session: Session,
    urls: list[str],
    results: ResultsManager | None = None,
    max_pages: int = 5,
    follow_links: bool = False,
) -> tuple[dict, Path]:
    """Inspect authorized pages and save a ScanRecord (module: enumeration)."""
    results = results or ResultsManager()
    settings = session.settings
    record = ScanRecord(
        program_id=session.program_id, platform=session.platform,
        target=", ".join(urls[:5]), module="enumeration", tool="playwright-mcp",
    )
    out_dir = results.evidence_dir(session.program_id, record.scan_id)

    def finish(status: str, error: str | None = None):
        record.status = status
        if error:
            record.errors.append(error)
        return record.to_dict(), results.save_scan(record)

    if not session.session_authorized:
        return finish("blocked", "Session authorization has not been confirmed.")
    state = availability(settings)
    if not state["available"]:
        return finish("skipped", "Playwright MCP unavailable: " + "; ".join(state["missing"]))
    allowed, blocked = session.gate().filter_allowed(urls)
    record.blocked_targets = blocked
    if not allowed:
        return finish("blocked", "No requested URL passed the authorization/scope gate.")

    record.tool_version = " ".join((settings.get("playwright_mcp") or {}).get("command", [])[-1:])
    started = time.monotonic()
    try:
        reports = asyncio.run(_inspect(session, allowed, out_dir, settings, max_pages, follow_links))
    except Exception as error:  # noqa: BLE001 - MCP/browser failures are recorded, not raised
        record.duration = round(time.monotonic() - started, 3)
        log.exception("browser inspection failed")
        return finish("error", f"Browser inspection failed: {error}")
    record.duration = round(time.monotonic() - started, 3)

    for report in reports:
        data = asdict(report)
        record.results.append({"type": "page", "asset": report.final_url or report.requested_url, **data})
        for link in report.links_in_scope:
            record.results.append({"type": "url", "asset": link, "method": "GET", "source": "browser"})
        if report.screenshot:
            record.evidence.append(report.screenshot)
        if report.snapshot_file:
            record.evidence.append(report.snapshot_file)
    record.scope = session.gate().classify_many(r["asset"] for r in record.results if r.get("asset"))
    return finish("success" if any(r.status == "inspected" for r in reports) else "failed")
