"""Common tool-adapter framework.

Every external tool used by Recon, Enumeration and Vulnerability Analysis is
wrapped by a :class:`ToolAdapter` subclass and executed through
:func:`run_adapter`, which enforces – in this order – session authorization,
OS support, tool availability/configuration, program request policy, explicit
active-scan confirmation and the Scope Engine gate. Nothing here builds a shell
string; commands are argument lists executed with ``shell=False``.
"""

from __future__ import annotations

import json
import logging
import platform
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from bugx.core.authorization import Session
from bugx.core.exceptions import PolicyViolation
from bugx.core.findings import Finding
from bugx.core.results_manager import ResultsManager, ScanRecord, safe_name
from bugx.core.runner import ToolRunner
from bugx.core.scope import parse_target

log = logging.getLogger("bugx.adapters")

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:[-.#][0-9A-Za-z]+)?)")

STATUS_INSTALLED = "Installed"
STATUS_MISSING = "Missing"
STATUS_ERROR = "Error"
STATUS_NOT_CONFIGURED = "Not Configured"
STATUS_UNSUPPORTED = "Unsupported OS"


def current_os() -> str:
    system = platform.system().lower()
    return {"windows": "windows", "darwin": "darwin"}.get(system, "linux")


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text or "")


def to_host(target: str) -> str:
    info = parse_target(target)
    return info["hostname"] if info else target


def to_host_port(target: str) -> str:
    """``host`` or ``host:port`` (scheme and path removed)."""
    info = parse_target(target)
    if not info:
        return target
    if "://" not in target and ":" in target.split("/", 1)[0]:
        port = target.split("/", 1)[0].rsplit(":", 1)[1]
        if port.isdigit():
            return f"{info['hostname']}:{port}"
    if info.get("port"):
        return f"{info['hostname']}:{info['port']}"
    return info["hostname"]


def to_url(target: str) -> str:
    """Return ``target`` as a URL (bare hosts become ``https://host``)."""
    if "://" in target:
        return target
    return f"https://{to_host(target)}"


def json_lines(text: str) -> list[dict]:
    """Parse JSON-lines output, ignoring non-JSON lines (banners, logs)."""
    rows: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def redact(value: str, keep: int = 4) -> str:
    """Redact a sensitive value, keeping only a short prefix."""
    value = str(value)
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(len(value) - keep, 12)


@dataclass
class ToolStatus:
    key: str
    name: str
    module: str
    status: str
    executable: str | None = None
    version: str = ""
    message: str = ""
    install_hint: str = ""


@dataclass
class RunContext:
    session: Session
    targets: list[str]
    settings: dict
    work_dir: Path
    options: dict = field(default_factory=dict)

    @property
    def policy(self):
        return self.session.policy

    def header_args(self, flag: str = "-H") -> list[str]:
        args: list[str] = []
        for header in self.policy.header_list():
            args += [flag, header]
        return args

    def tool_settings(self, key: str) -> dict:
        return dict((self.settings.get("tools") or {}).get(key) or {})

    def wordlist(self, kind: str = "directories") -> str:
        """Return a configured wordlist path or raise ValueError."""
        from bugx.core.config import first_existing

        value = (self.settings.get("wordlists") or {}).get(kind)
        found = first_existing(value if isinstance(value, list) else [value])
        if not found:
            raise ValueError(f"No {kind} wordlist configured/found (config/bugx.yaml -> wordlists.{kind}).")
        return found


class ToolAdapter:
    """Base class. Subclasses describe one tool and how to parse it."""

    key: ClassVar[str] = ""
    name: ClassVar[str] = ""
    module: ClassVar[str] = ""
    category: ClassVar[str] = ""
    purpose: ClassVar[str] = ""
    binaries: ClassVar[tuple[str, ...]] = ()
    version_args: ClassVar[tuple[str, ...]] = ("-version",)
    install: ClassVar[dict[str, str]] = {}
    supported_os: ClassVar[frozenset[str]] = frozenset({"linux", "darwin", "windows"})

    input_kind: ClassVar[str] = "host"  # domain | host | url | path | none
    batch: ClassVar[bool] = False  # all targets in a single run (stdin / list)
    sends_traffic: ClassVar[bool] = True  # contacts the target at all
    http: ClassVar[bool] = True  # sends HTTP requests to the target
    supports_headers: ClassVar[bool] = True
    intrusive: ClassVar[bool] = False  # active vulnerability testing
    default_timeout: ClassVar[int] = 600
    ok_returncodes: ClassVar[tuple[int, ...]] = (0,)

    # ---------------------------------------------------------------- hooks
    def build_args(self, ctx: RunContext, target: str | None) -> list[str]:
        raise NotImplementedError

    def stdin(self, ctx: RunContext, target: str | None) -> str | None:
        return None

    def parse(self, ctx: RunContext, stdout: str, stderr: str, target: str | None) -> list[dict]:
        raise NotImplementedError

    def config_status(self, settings: dict) -> tuple[bool, str]:
        """Return (configured, message) for tool-specific prerequisites."""
        return True, ""

    def verify_binary(self, executable: str, version_output: str) -> str | None:
        """Return an error message if the binary is not the expected tool."""
        return None

    def evidence_files(self, ctx: RunContext, target: str | None) -> list[Path]:
        """Files the tool writes itself (collected as evidence)."""
        return []

    # ------------------------------------------------------------- helpers
    def install_hint(self) -> str:
        os_name = current_os()
        return self.install.get(os_name) or self.install.get("any") or self.install.get("linux", "")

    def resolve_executable(self, settings: dict | None = None) -> str | None:
        override = ((settings or {}).get("tools") or {}).get(self.key, {}) or {}
        custom = override.get("path") if isinstance(override, dict) else None
        if custom:
            return shutil.which(custom) or (custom if Path(custom).is_file() else None)
        for binary in self.binaries:
            found = shutil.which(binary)
            if found:
                return found
        return None

    def detect_version(self, executable: str, timeout: int = 20) -> tuple[str, str, str | None]:
        """Return (version, raw_output, error)."""
        if not self.version_args:
            return "", "", None
        result = ToolRunner.run(executable, list(self.version_args), timeout=timeout)
        output = strip_ansi((result.stdout or "") + "\n" + (result.stderr or ""))
        if result.error:
            return "", output, result.error
        if "password is required" in output or "a terminal is required" in output:
            return "", output, "Tool wrapper requested sudo/interactive input."
        match = VERSION_RE.search(output)
        return (match.group(1) if match else ""), output, None

    def status(self, settings: dict | None = None, check_version: bool = True) -> ToolStatus:
        settings = settings or {}
        base = dict(key=self.key, name=self.name, module=self.module, install_hint=self.install_hint())
        if current_os() not in self.supported_os:
            return ToolStatus(status=STATUS_UNSUPPORTED, message=f"{self.name} does not run natively on {current_os()}.", **base)
        executable = self.resolve_executable(settings)
        if not executable:
            return ToolStatus(status=STATUS_MISSING, message="Not found in PATH.", **base)
        version, raw, error = ("", "", None)
        if check_version:
            timeout = int((settings.get("defaults") or {}).get("version_timeout", 20))
            version, raw, error = self.detect_version(executable, timeout=timeout)
            if error is None:
                error = self.verify_binary(executable, raw)
        if error:
            return ToolStatus(status=STATUS_ERROR, executable=executable, version=version, message=error, **base)
        configured, message = self.config_status(settings)
        if not configured:
            return ToolStatus(status=STATUS_NOT_CONFIGURED, executable=executable, version=version, message=message, **base)
        return ToolStatus(status=STATUS_INSTALLED, executable=executable, version=version, message=message, **base)

    def describe(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "module": self.module,
            "category": self.category,
            "purpose": self.purpose,
            "sends_traffic": self.sends_traffic,
            "intrusive": self.intrusive,
        }


def _target_for(adapter: ToolAdapter, target: str) -> str:
    if adapter.input_kind in ("domain", "host"):
        return to_host(target)
    if adapter.input_kind == "url":
        return to_url(target)
    return target


def _redact_command(command: list[str], ctx: RunContext) -> list[str]:
    secrets = set(ctx.policy.header_list())
    return ["<header redacted>" if part in secrets else part for part in command]


def run_adapter(
    adapter: ToolAdapter,
    session: Session,
    targets: list[str] | None = None,
    results: ResultsManager | None = None,
    settings: dict | None = None,
    options: dict | None = None,
) -> tuple[dict, Path]:
    """Execute ``adapter`` safely and persist a :class:`ScanRecord`.

    Returns ``(record_dict, record_path)``. Never raises for tool failures;
    every outcome (success, failure, blocked) is recorded.
    """
    results = results or ResultsManager()
    settings = settings if settings is not None else session.settings
    options = dict(options or {})
    requested = [t for t in (targets or [session.target]) if isinstance(t, str) and t.strip()]

    record = ScanRecord(
        program_id=session.program_id,
        platform=session.platform,
        target=", ".join(requested[:5]) + (" ..." if len(requested) > 5 else ""),
        module=adapter.module,
        tool=adapter.key,
    )
    work_dir = results.evidence_dir(session.program_id, record.scan_id)
    gate = session.gate()

    def finish(status: str, error: str | None = None) -> tuple[dict, Path]:
        record.status = status
        if error:
            record.errors.append(error)
        path = results.save_scan(record)
        log.info("scan %s tool=%s status=%s errors=%s", record.scan_id, adapter.key, status, record.errors)
        return record.to_dict(), path

    # 1. Session authorization
    try:
        session.require_session_authorization()
    except PolicyViolation as error:
        return finish("blocked", str(error))

    # 2. Tool availability
    tool_status = adapter.status(settings)
    record.tool_version = tool_status.version
    if tool_status.status != STATUS_INSTALLED:
        hint = f" Install: {tool_status.install_hint}" if tool_status.install_hint else ""
        return finish("skipped", f"{adapter.name}: {tool_status.status}. {tool_status.message}{hint}".strip())

    # 3. Program request policy
    policy = session.policy
    if adapter.sends_traffic and adapter.http and policy.requires_headers and not adapter.supports_headers:
        return finish(
            "blocked",
            f"{adapter.name} cannot send the program's required headers/User-Agent; blocked by policy.",
        )
    if adapter.intrusive:
        if policy.automated_scanning is False:
            return finish("blocked", "Program policy forbids automated scanning.")
        if not session.active_scanning_confirmed:
            return finish("blocked", "Active scanning was not explicitly confirmed for this session.")

    # 4. Scope gate (local-path tools are not network targets)
    if adapter.input_kind in ("path", "none"):
        allowed = requested
    else:
        allowed, blocked = gate.filter_allowed(requested)
        record.blocked_targets = blocked
        if not allowed:
            return finish("blocked", "No requested target passed the authorization/scope gate.")

    options.setdefault("tool_version", tool_status.version)
    ctx = RunContext(session=session, targets=allowed, settings=settings, work_dir=work_dir, options=options)
    executable = tool_status.executable or ""
    timeout = int(options.get("timeout") or ctx.tool_settings(adapter.key).get("timeout") or adapter.default_timeout)

    run_targets: list[str | None] = [None] if adapter.batch else list(allowed)
    statuses: list[str] = []
    items: list[dict] = []

    for target in run_targets:
        tool_target = _target_for(adapter, target) if target else None
        try:
            args = adapter.build_args(ctx, tool_target)
        except (ValueError, PolicyViolation) as error:
            record.errors.append(f"{target or 'batch'}: {error}")
            statuses.append("error")
            continue
        record.command = _redact_command([executable, *map(str, args)], ctx)
        result = ToolRunner.run(executable, args, timeout=timeout, input_text=adapter.stdin(ctx, tool_target), cwd=str(work_dir))
        record.duration = round(record.duration + result.duration, 3)
        record.exit_code = result.returncode

        raw_name = f"raw_{safe_name(tool_target or 'batch')}.txt"
        raw_path = work_dir / raw_name
        raw_path.write_text(result.stdout or "", encoding="utf-8")
        record.evidence.append(str(raw_path))
        for extra in adapter.evidence_files(ctx, tool_target):
            if extra.exists():
                record.evidence.append(str(extra))
        record.stderr_tail = strip_ansi(result.stderr or "")[-2000:]

        if result.error:
            record.errors.append(result.error)
            statuses.append("timeout" if "timed out" in result.error else "error")
            continue
        if result.returncode not in adapter.ok_returncodes:
            record.errors.append(f"{adapter.name} exited with code {result.returncode}.")
            statuses.append("failed")
        else:
            statuses.append("success")
        try:
            items.extend(adapter.parse(ctx, result.stdout or "", result.stderr or "", tool_target))
        except Exception as error:  # noqa: BLE001 - parser bugs must not lose the record
            record.errors.append(f"Output parsing failed: {error}")

    # 5. Normalise, deduplicate and classify every discovered asset
    seen: set[str] = set()
    unique: list[dict] = []
    for item in items:
        fingerprint = json.dumps(item, sort_keys=True, default=str)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        asset = item.get("asset")
        item["scope_status"] = gate.classify(asset) if asset else "n/a"
        unique.append(item)
    record.results = unique
    record.scope = gate.classify_many(i["asset"] for i in unique if i.get("asset"))

    # 6. Findings (always Needs Review – never auto-validated)
    findings: list[Finding] = []
    for item in unique:
        if item.get("type") != "finding":
            continue
        data = dict(item.get("finding") or {})
        data.setdefault("source_tool", adapter.key)
        data.setdefault("url", item.get("asset", ""))
        data["scan_id"] = record.scan_id
        data["scope_status"] = item["scope_status"]
        data["validation_status"] = "Needs Review"
        data.setdefault("evidence", []).append(str(work_dir))
        try:
            findings.append(Finding(**data))
        except TypeError as error:
            record.errors.append(f"Invalid finding from parser: {error}")
    if findings:
        record.findings = results.upsert_findings(session.program_id, findings)

    if statuses and all(s == "success" for s in statuses):
        status = "success"
    elif "success" in statuses:
        status = "partial"
    elif "timeout" in statuses:
        status = "timeout"
    else:
        status = "failed"
    return finish(status)
