"""Centralised, append-only JSON results storage.

Layout (under ``config.output_root()``)::

    recon/<program_id>/<scan_id>_<tool>.json
    enumeration/<program_id>/...
    vulnerability_analysis/<program_id>/...
    validation/<program_id>/<finding_id>_<timestamp>.json
    findings/<program_id>/findings.json      (deduplicated finding index)
    evidence/<program_id>/<scan_id>/          (raw tool output, screenshots)
    reports/<program_id>/<report files>
    logs/bugx.log

Scan files are created with exclusive mode and are never overwritten.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from bugx.core import config
from bugx.core.findings import VALIDATION_STATUSES, Finding

MODULES = ("recon", "enumeration", "vulnerability_analysis", "validation", "reports", "logs")

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(value: str) -> str:
    cleaned = _SAFE.sub("_", value or "").strip("._")
    return cleaned[:120] or "unknown"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


@dataclass
class ScanRecord:
    """One execution of one tool (or module operation)."""

    program_id: str
    platform: str
    target: str
    module: str
    tool: str
    scan_id: str = field(default_factory=new_scan_id)
    tool_version: str = ""
    timestamp: str = field(default_factory=utcnow)
    status: str = "pending"  # success | failed | blocked | error | timeout | skipped
    duration: float = 0.0
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    scope: dict[str, list[str]] = field(default_factory=dict)
    blocked_targets: list[dict] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    stderr_tail: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResultsManager:
    """Read/write BUGX results for all modules."""

    def __init__(self, root: Path | str | None = None):
        self.root = Path(root) if root else config.output_root()

    # ------------------------------------------------------------------ paths
    def module_dir(self, module: str, program_id: str) -> Path:
        if module not in MODULES:
            raise ValueError(f"Unknown results module: {module}")
        path = self.root / module / safe_name(program_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def evidence_dir(self, program_id: str, scan_id: str) -> Path:
        path = self.root / "evidence" / safe_name(program_id) / safe_name(scan_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def reports_dir(self, program_id: str) -> Path:
        return self.module_dir("reports", program_id)

    def findings_path(self, program_id: str) -> Path:
        path = self.root / "findings" / safe_name(program_id)
        path.mkdir(parents=True, exist_ok=True)
        return path / "findings.json"

    # ------------------------------------------------------------- scan files
    def save_scan(self, record: ScanRecord) -> Path:
        directory = self.module_dir(record.module, record.program_id)
        base = f"{safe_name(record.scan_id)}_{safe_name(record.tool)}"
        for attempt in range(100):
            name = f"{base}.json" if attempt == 0 else f"{base}-{attempt}.json"
            path = directory / name
            try:
                with path.open("x", encoding="utf-8") as handle:
                    json.dump(record.to_dict(), handle, indent=2, ensure_ascii=False)
                return path
            except FileExistsError:
                continue
        raise RuntimeError("Could not allocate a unique scan file name.")

    def load_scan(self, path: Path | str) -> dict:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "scan_id" not in data:
            raise ValueError(f"Not a BUGX scan file: {path}")
        return data

    def list_scans(
        self,
        program_id: str | None = None,
        modules: Iterable[str] = ("recon", "enumeration", "vulnerability_analysis"),
    ) -> list[dict]:
        """Return scan summaries (newest first) without loading results."""
        summaries: list[dict] = []
        for module in modules:
            base = self.root / module
            if not base.is_dir():
                continue
            dirs = [base / safe_name(program_id)] if program_id else [p for p in base.iterdir() if p.is_dir()]
            for directory in dirs:
                if not directory.is_dir():
                    continue
                for path in directory.glob("*.json"):
                    try:
                        data = self.load_scan(path)
                    except (ValueError, OSError, json.JSONDecodeError):
                        continue
                    summaries.append(
                        {
                            "path": str(path),
                            "scan_id": data.get("scan_id"),
                            "module": data.get("module"),
                            "tool": data.get("tool"),
                            "target": data.get("target"),
                            "status": data.get("status"),
                            "timestamp": data.get("timestamp"),
                            "results": len(data.get("results", [])),
                            "findings": len(data.get("findings", [])),
                        }
                    )
        summaries.sort(key=lambda s: s.get("timestamp") or "", reverse=True)
        return summaries

    def load_scans(self, program_id: str, modules: Iterable[str] = ("recon", "enumeration", "vulnerability_analysis")) -> list[dict]:
        return [self.load_scan(s["path"]) for s in self.list_scans(program_id, modules)]

    def in_scope_assets(self, program_id: str, module: str | None = None) -> list[str]:
        """Union of in-scope assets recorded by successful scans."""
        assets: set[str] = set()
        modules = (module,) if module else ("recon", "enumeration")
        for scan in self.load_scans(program_id, modules):
            assets.update(scan.get("scope", {}).get("in_scope", []))
        return sorted(assets)

    # --------------------------------------------------------------- findings
    def _write_json_atomic(self, path: Path, data: Any) -> None:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def load_findings(self, program_id: str) -> list[Finding]:
        path = self.findings_path(program_id)
        if not path.is_file():
            return []
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return [Finding.from_dict(item) for item in raw if isinstance(item, dict)]

    def upsert_findings(self, program_id: str, findings: Iterable[Finding]) -> list[str]:
        """Add findings, merging duplicates by fingerprint. Returns finding IDs."""
        existing = {f.finding_id: f for f in self.load_findings(program_id)}
        ids: list[str] = []
        for finding in findings:
            current = existing.get(finding.finding_id)
            if current:
                # Keep the validation state; merge new evidence only.
                for item in finding.evidence:
                    if item not in current.evidence:
                        current.evidence.append(item)
                current.updated_at = utcnow()
            else:
                existing[finding.finding_id] = finding
            ids.append(finding.finding_id)
        self._write_json_atomic(
            self.findings_path(program_id), [f.to_dict() for f in existing.values()]
        )
        return ids

    def get_finding(self, program_id: str, finding_id: str) -> Finding | None:
        for finding in self.load_findings(program_id):
            if finding.finding_id == finding_id:
                return finding
        return None

    def update_finding_status(
        self,
        program_id: str,
        finding_id: str,
        status: str,
        note: str = "",
        evidence: list[str] | None = None,
        confidence: str | None = None,
    ) -> Finding:
        if status not in VALIDATION_STATUSES:
            raise ValueError(f"Invalid validation status: {status}")
        findings = self.load_findings(program_id)
        for finding in findings:
            if finding.finding_id != finding_id:
                continue
            entry = {
                "timestamp": utcnow(),
                "from": finding.validation_status,
                "to": status,
                "note": note,
                "evidence": list(evidence or []),
            }
            finding.validation_history.append(entry)
            finding.validation_status = status
            finding.evidence.extend(e for e in (evidence or []) if e not in finding.evidence)
            if confidence:
                finding.confidence = confidence
            finding.updated_at = entry["timestamp"]
            self._write_json_atomic(self.findings_path(program_id), [f.to_dict() for f in findings])
            record_path = self.module_dir("validation", program_id) / (
                f"{safe_name(finding_id)}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.json"
            )
            with record_path.open("x", encoding="utf-8") as handle:
                json.dump({"finding_id": finding_id, **entry}, handle, indent=2)
            return finding
        raise KeyError(f"Finding not found: {finding_id}")


EDITABLE_FINDING_FIELDS = ("reproduction_steps", "impact", "remediation", "cvss_score", "cvss_vector", "references")


def _validate_fields(fields: dict) -> None:
    unknown = set(fields) - set(EDITABLE_FINDING_FIELDS)
    if unknown:
        raise ValueError(f"Fields not editable: {', '.join(sorted(unknown))}")
    score = fields.get("cvss_score")
    if score is not None and (not isinstance(score, (int, float)) or not 0 <= score <= 10):
        raise ValueError("CVSS score must be between 0.0 and 10.0")
    if score is not None and not str(fields.get("cvss_vector", "")).startswith("CVSS:"):
        raise ValueError("A CVSS score requires a CVSS vector string (CVSS:3.1/... or CVSS:4.0/...).")


def update_finding_fields(manager: "ResultsManager", program_id: str, finding_id: str, **fields) -> Finding:
    """Edit report fields of a finding (used by Safe Validation)."""
    _validate_fields(fields)
    findings = manager.load_findings(program_id)
    for finding in findings:
        if finding.finding_id == finding_id:
            for key, value in fields.items():
                setattr(finding, key, value)
            finding.updated_at = utcnow()
            manager._write_json_atomic(manager.findings_path(program_id), [f.to_dict() for f in findings])
            return finding
    raise KeyError(f"Finding not found: {finding_id}")


def setup_logging(root: Path | None = None) -> Path:
    """Configure file logging to ``output/logs/bugx.log`` (idempotent)."""
    log_dir = (root or config.output_root()) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "bugx.log"
    logger = logging.getLogger("bugx")
    if not any(isinstance(h, logging.FileHandler) and Path(h.baseFilename) == log_path for h in logger.handlers):
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return log_path
