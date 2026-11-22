"""Endpoint inventory built from saved recon/enumeration results.

Pure post-processing of stored results: normalises and deduplicates URLs,
merges parameters, methods, status codes and content types, and tags
login/registration, API, JavaScript, admin, upload and GraphQL endpoints.
No requests are sent.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager, ScanRecord

URL_TYPES = {"url", "path", "endpoint", "api_endpoint", "http_service", "parameter", "page"}

TAGS = [
    ("login", re.compile(r"(log[-_]?in|sign[-_]?in|auth|sso|oauth|session)", re.I)),
    ("registration", re.compile(r"(register|sign[-_]?up|create[-_]?account|join)", re.I)),
    ("password_reset", re.compile(r"(forgot|reset[-_]?password|recover)", re.I)),
    ("api", re.compile(r"(/api/|/v[0-9]+/|/rest/|\.json$)", re.I)),
    ("graphql", re.compile(r"graphql", re.I)),
    ("javascript", re.compile(r"\.m?js(\?|$)", re.I)),
    ("admin", re.compile(r"(admin|dashboard|manage|console)", re.I)),
    ("upload", re.compile(r"upload", re.I)),
]


def normalize_url(url: str) -> str:
    """Lower-case scheme/host, drop fragment and default port, sort query keys."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    host = parts.hostname.lower()
    port = parts.port
    if port and not ((parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((parts.scheme.lower(), host, parts.path or "/", query, ""))


def build_inventory(session: Session, results: ResultsManager) -> dict:
    gate = session.gate()
    endpoints: dict[str, dict] = {}
    for scan in results.load_scans(session.program_id, ("recon", "enumeration")):
        for item in scan.get("results", []):
            if item.get("type") not in URL_TYPES or not isinstance(item.get("asset"), str):
                continue
            url = normalize_url(item["asset"])
            if not url:
                continue
            base, _, query = url.partition("?")
            entry = endpoints.setdefault(base, {
                "url": base, "methods": set(), "parameters": set(), "status_codes": set(),
                "content_types": set(), "sources": set(), "tags": set(),
            })
            entry["methods"].add(str(item.get("method") or "GET").upper())
            entry["parameters"].update(k for k, _ in parse_qsl(query, keep_blank_values=True))
            entry["parameters"].update(item.get("parameters") or [])
            if item.get("parameter"):
                entry["parameters"].add(item["parameter"])
            if item.get("status_code") not in (None, ""):
                entry["status_codes"].add(str(item["status_code"]))
            if item.get("content_type"):
                entry["content_types"].add(str(item["content_type"]).split(";")[0].strip())
            entry["sources"].add(scan.get("tool", ""))
    for entry in endpoints.values():
        for tag, pattern in TAGS:
            if pattern.search(entry["url"]):
                entry["tags"].add(tag)
        if entry["parameters"]:
            entry["tags"].add("parameters")
        entry["scope_status"] = gate.classify(entry["url"])
        for key in ("methods", "parameters", "status_codes", "content_types", "sources", "tags"):
            entry[key] = sorted(entry[key])
    rows = sorted(endpoints.values(), key=lambda e: e["url"])
    summary = {tag: sum(1 for e in rows if tag in e["tags"]) for tag, _ in TAGS}
    summary["parameters"] = sum(1 for e in rows if e["parameters"])
    summary["total"] = len(rows)
    return {"endpoints": rows, "summary": summary}


def save_inventory(session: Session, results: ResultsManager | None = None):
    results = results or ResultsManager()
    inventory = build_inventory(session, results)
    record = ScanRecord(
        program_id=session.program_id, platform=session.platform, target=session.target,
        module="enumeration", tool="endpoint-inventory", status="success",
    )
    record.results = [{"type": "endpoint", "asset": e["url"], **e} for e in inventory["endpoints"]]
    record.scope = session.gate().classify_many(e["url"] for e in inventory["endpoints"])
    record.notes.append(f"summary: {inventory['summary']}")
    return inventory, results.save_scan(record)
