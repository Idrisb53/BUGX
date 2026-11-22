"""Safe Validation engine.

Lets the operator review potential findings, re-check scope/authorization,
read category-specific *safe* validation steps, optionally perform a single
scope-checked GET replay of the affected URL (after explicit confirmation),
and record a validation status with timestamped evidence.

Nothing here sends payloads, submits forms, or exploits anything; the only
active action is :func:`safe_replay`, a plain GET of the stored URL.
"""

from __future__ import annotations

import hashlib
import urllib.error
from pathlib import Path

from bugx.core.authorization import Session
from bugx.core.findings import VALIDATION_STATUSES, Finding
from bugx.core.results_manager import ResultsManager, utcnow
from bugx.modules.enumeration.js_collector import fetch

GUIDANCE: dict[str, list[str]] = {
    "xss": [
        "Confirm the URL and parameter are in scope and the program accepts XSS reports.",
        "In your own browser (logged into a TEST account only), request the URL with a harmless marker such as bugx<'\"> instead of a script payload.",
        "Inspect the response/DOM: is the marker reflected unencoded in an executable context?",
        "If needed, prove execution with a benign alert(document.domain) on your own test session only.",
        "Capture request/response and a screenshot. Never target other users.",
    ],
    "sql_injection": [
        "Do not run additional sqlmap options; never dump data.",
        "Compare responses for a boolean pair (e.g. id=1 AND 1=1 vs id=1 AND 1=2) manually in Burp at low rate.",
        "Record response length/status differences as evidence; stop as soon as the behaviour is demonstrated.",
        "Report without extracting any database content.",
    ],
    "tls": [
        "Re-run testssl.sh or check with your browser that the weak protocol/cipher is still offered.",
        "Note the exact host:port, protocol and cipher in the evidence.",
    ],
    "misconfiguration": [
        "Request the affected URL once and confirm the missing/insecure header or setting.",
        "Check whether it has real security impact for this application (many programs exclude header-only reports).",
    ],
    "exposed_files": [
        "Request the file once. Do not download large files or follow links to further data.",
        "If it contains sensitive data, stop, redact the evidence and report immediately.",
    ],
    "outdated_component": [
        "Confirm the version from the file/banner and that the CVE affects the used functionality.",
        "Programs usually require a demonstrated impact, not just a version number.",
    ],
    "secrets": [
        "Do NOT use the credential. Confirm only that it looks like a real key (format, context).",
        "Report the location; let the program verify and rotate it.",
    ],
    "open_redirect": [
        "Use a domain you control or a harmless one (example.com) as the redirect target.",
        "Confirm the redirect happens without user interaction beyond the click.",
    ],
    "default": [
        "Confirm the asset is still in scope and the vulnerability class is accepted by the program.",
        "Reproduce manually with the minimum number of requests, using test accounts only.",
        "Capture request, response and screenshots. Do not modify or access other users' data.",
    ],
}


def guidance_for(finding: Finding) -> list[str]:
    return GUIDANCE.get(finding.category, GUIDANCE["default"])


def recheck_scope(session: Session, finding: Finding) -> dict:
    """Authorization + scope re-check for the finding URL (local files are not network targets)."""
    if not finding.url.startswith(("http://", "https://")):
        return {"allowed": True, "status": "local", "reason": "Local source finding (no network target)"}
    return session.gate().check(finding.url)


def safe_replay(session: Session, finding: Finding, results: ResultsManager) -> dict:
    """One scope-checked GET of ``finding.url``; stores status/headers/body hash as evidence."""
    check = recheck_scope(session, finding)
    if check.get("allowed") is not True or check.get("status") == "local":
        raise PermissionError(f"Replay not permitted: {check.get('reason')}")
    if finding.method.upper() != "GET":
        raise PermissionError("Only GET findings can be replayed automatically; validate others manually.")
    evidence_dir = results.evidence_dir(session.program_id, f"validation-{finding.finding_id}")
    try:
        status, headers, body = fetch(session, finding.url)
        outcome = {"status_code": status, "headers": headers, "bytes": len(body),
                   "sha256": hashlib.sha256(body).hexdigest()}
    except urllib.error.HTTPError as error:
        outcome = {"status_code": error.code, "error": str(error)}
    except (urllib.error.URLError, OSError) as error:
        outcome = {"error": str(error)}
    path = Path(evidence_dir) / f"replay_{utcnow().replace(':', '')}.txt"
    lines = [f"GET {finding.url}", f"time: {utcnow()}"] + [f"{k}: {v}" for k, v in outcome.items() if k != "headers"]
    lines += [f"< {k}: {v}" for k, v in (outcome.get("headers") or {}).items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    outcome["evidence"] = str(path)
    return outcome


def set_status(session: Session, results: ResultsManager, finding_id: str, status: str,
               note: str = "", evidence: list[str] | None = None) -> Finding:
    if status not in VALIDATION_STATUSES:
        raise ValueError(f"Status must be one of: {', '.join(VALIDATION_STATUSES)}")
    if status == "Validated" and not (note.strip() or evidence):
        raise ValueError("A Validated status needs a note or evidence describing the manual reproduction.")
    confidence = "High" if status == "Validated" else None
    return results.update_finding_status(session.program_id, finding_id, status, note=note,
                                         evidence=evidence, confidence=confidence)
