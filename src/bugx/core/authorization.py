"""Authorization and scope gate shared by every BUGX module and adapter.

This module adds no new scope rules. All decisions are delegated to
``bugx.core.scope.can_test_target`` / ``classify_target`` so behaviour stays
identical to the original Scope Engine. It only adds:

* a :class:`Session` holding the validated profile and session confirmations,
* fail-closed helpers (``require``, ``filter_allowed``),
* redirect re-validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urljoin

from bugx.core.exceptions import PolicyViolation, ScopeViolation
from bugx.core.policy import RequestPolicy, load_policy
from bugx.core.scope import can_test_target, classify_target

STATUSES = ("in_scope", "out_of_scope", "unverified")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Session:
    """A validated BUGX working session for one program profile."""

    profile: dict
    profile_path: str
    target: str
    platform: str = ""
    settings: dict = field(default_factory=dict)
    session_authorized: bool = False
    authorized_at: str | None = None
    active_scanning_confirmed: bool = False
    policy: RequestPolicy = field(init=False)

    def __post_init__(self) -> None:
        self.policy = load_policy(self.profile, self.settings)
        if not self.platform:
            self.platform = str(self.profile.get("program", {}).get("platform", ""))

    @property
    def program_id(self) -> str:
        return str(self.profile.get("program", {}).get("id", "unknown"))

    @property
    def program_name(self) -> str:
        return str(self.profile.get("program", {}).get("name", "Unknown"))

    def confirm_authorization(self) -> None:
        """Record the user's explicit per-session authorization confirmation."""
        self.session_authorized = True
        self.authorized_at = _utcnow()

    def gate(self) -> "ScopeGate":
        return ScopeGate(self.profile)

    def require_session_authorization(self) -> None:
        if not self.session_authorized:
            raise PolicyViolation("Session authorization has not been confirmed.")


class ScopeGate:
    """Fail-closed wrapper around the Scope Engine for one profile."""

    def __init__(self, profile: dict):
        self.profile = profile

    def check(self, target: str) -> dict:
        try:
            result = can_test_target(target, self.profile)
        except Exception as error:  # noqa: BLE001 - fail closed on any engine error
            return {"allowed": False, "status": "error", "reason": f"Scope Engine error: {error}"}
        if not isinstance(result, dict):
            return {"allowed": False, "status": "error", "reason": "Unexpected Scope Engine result"}
        return result

    def is_allowed(self, target: str) -> bool:
        return self.check(target).get("allowed") is True

    def require(self, target: str) -> dict:
        """Return the gate result or raise :class:`ScopeViolation`."""
        result = self.check(target)
        if result.get("allowed") is not True:
            raise ScopeViolation(
                target,
                str(result.get("status", "unverified")),
                str(result.get("reason", "Target not authorized")),
            )
        return result

    def classify(self, target: str) -> str:
        try:
            status = classify_target(target, self.profile).get("status")
        except Exception:  # noqa: BLE001 - fail closed
            return "unverified"
        return status if status in STATUSES else "unverified"

    def classify_many(self, targets: Iterable[str]) -> dict[str, list[str]]:
        """Deduplicate and bucket targets into in/out/unverified."""
        buckets: dict[str, set[str]] = {status: set() for status in STATUSES}
        for target in targets:
            if not isinstance(target, str) or not target.strip():
                continue
            buckets[self.classify(target.strip())].add(target.strip())
        return {status: sorted(values) for status, values in buckets.items()}

    def filter_allowed(self, targets: Iterable[str]) -> tuple[list[str], list[dict]]:
        """Split targets into allowed ones and blocked ones (with reasons)."""
        allowed: list[str] = []
        blocked: list[dict] = []
        seen: set[str] = set()
        for target in targets:
            if target in seen:
                continue
            seen.add(target)
            result = self.check(target)
            if result.get("allowed") is True:
                allowed.append(target)
            else:
                blocked.append({"target": target, **result})
        return allowed, blocked

    def validate_redirect(self, current_url: str, location: str) -> dict:
        """Resolve a redirect ``Location`` and re-run the gate on the result."""
        resolved = urljoin(current_url, location)
        result = self.check(resolved)
        return {"url": resolved, **result}
