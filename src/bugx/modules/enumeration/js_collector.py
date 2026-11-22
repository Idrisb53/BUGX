"""Download in-scope JavaScript files (for Retire.js / manual review).

Each request is scope-checked, carries the program's required headers, is
rate limited, follows redirects only when the new location is in scope, and
is capped in size. Only ``GET`` is used.
"""

from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request

from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager, ScanRecord

MAX_BYTES = 5 * 1024 * 1024


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, session: Session):
        self.gate = session.gate()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.gate.is_allowed(newurl):
            raise urllib.error.HTTPError(newurl, code, f"{REDIRECT_BLOCKED}: {newurl}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(session: Session):
    return urllib.request.build_opener(_ScopedRedirect(session))


def fetch(session: Session, url: str, timeout: int = 15) -> tuple[int, dict, bytes]:
    """Scope-checked GET. Raises PermissionError when the URL is not allowed."""
    session.require_session_authorization()
    session.gate().require(url)
    headers = dict(session.policy.required_headers)
    headers["User-Agent"] = session.policy.user_agent or "BUGX"
    request = urllib.request.Request(url, headers=headers, method="GET")
    with _opener(session).open(request, timeout=timeout) as response:  # noqa: S310 - scheme checked by gate
        body = response.read(MAX_BYTES + 1)[:MAX_BYTES]
        return response.status, dict(response.headers), body


REDIRECT_BLOCKED = "Redirect out of scope blocked"


def preflight_redirects(session: Session, url: str, timeout: int = 15) -> dict:
    """Follow server-side redirects with the scope gate before a browser visits ``url``.

    Returns ``{"allowed": bool, "status": ..., "reason": ...}``. Out-of-scope
    redirect targets are never requested.
    """
    try:
        status, _, _ = fetch(session, url, timeout=timeout)
        return {"allowed": True, "status": status, "reason": "ok"}
    except urllib.error.HTTPError as error:
        if REDIRECT_BLOCKED in str(error.msg):
            return {"allowed": False, "status": "redirected_out_of_scope", "reason": str(error.msg)}
        return {"allowed": True, "status": error.code, "reason": f"HTTP {error.code}"}
    except PermissionError as error:
        return {"allowed": False, "status": "blocked", "reason": str(error)}
    except (urllib.error.URLError, OSError, ValueError) as error:
        return {"allowed": False, "status": "error", "reason": str(error)}


def collect_js(session: Session, urls: list[str], results: ResultsManager | None = None, limit: int = 50):
    results = results or ResultsManager()
    record = ScanRecord(program_id=session.program_id, platform=session.platform,
                        target=session.target, module="enumeration", tool="js-collector")
    out_dir = results.evidence_dir(session.program_id, record.scan_id) / "js"
    out_dir.mkdir(parents=True, exist_ok=True)
    allowed, blocked = session.gate().filter_allowed([u for u in urls if ".js" in u.split("?")[0].lower()])
    record.blocked_targets = blocked
    delay = 1.0 / max(1, session.policy.rate_limit)
    started = time.monotonic()
    for url in allowed[:limit]:
        try:
            status, headers, body = fetch(session, url)
        except (urllib.error.URLError, PermissionError, OSError, ValueError) as error:
            record.errors.append(f"{url}: {error}")
            continue
        name = hashlib.sha256(url.encode()).hexdigest()[:16] + ".js"
        (out_dir / name).write_bytes(body)
        record.results.append({"type": "javascript", "asset": url, "status_code": status, "file": str(out_dir / name),
                               "content_type": headers.get("Content-Type", ""), "bytes": len(body)})
        time.sleep(delay)
    record.duration = round(time.monotonic() - started, 3)
    record.evidence.append(str(out_dir))
    record.scope = session.gate().classify_many(r["asset"] for r in record.results)
    record.status = "success" if record.results or not allowed else "failed"
    return record.to_dict(), results.save_scan(record), out_dir
