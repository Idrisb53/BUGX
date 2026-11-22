"""Per-program request policy (headers, user agent, rate limits, scanner permission).

Stored in an optional ``policy:`` block of a program profile::

    policy:
      required_headers:
        X-HackerOne-Research: idris4hack
      user_agent: ""
      rate_limit: 2
      concurrency: 2
      automated_scanning: false   # true / false / omitted (= unknown)

The policy never changes scope; it only constrains how tools send traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bugx.core.exceptions import ConfigurationError


@dataclass
class RequestPolicy:
    required_headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    rate_limit: int = 5
    concurrency: int = 5
    automated_scanning: bool | None = None

    def header_list(self) -> list[str]:
        """Headers as ``Name: value`` strings (user agent included)."""
        headers = [f"{name}: {value}" for name, value in self.required_headers.items()]
        if self.user_agent:
            headers.append(f"User-Agent: {self.user_agent}")
        return headers

    @property
    def requires_headers(self) -> bool:
        return bool(self.required_headers or self.user_agent)

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_headers": dict(self.required_headers),
            "user_agent": self.user_agent,
            "rate_limit": self.rate_limit,
            "concurrency": self.concurrency,
            "automated_scanning": self.automated_scanning,
        }


def _positive_int(value: Any, name: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigurationError(f"policy.{name} must be a positive integer.")
    return value


def load_policy(profile: dict, settings: dict | None = None) -> RequestPolicy:
    """Build a :class:`RequestPolicy` from a profile (missing block = defaults)."""
    defaults = (settings or {}).get("defaults", {})
    raw = profile.get("policy") if isinstance(profile, dict) else None

    if raw is None:
        return RequestPolicy(
            rate_limit=int(defaults.get("rate_limit", 5)),
            concurrency=int(defaults.get("concurrency", 5)),
        )

    if not isinstance(raw, dict):
        raise ConfigurationError("policy must be a mapping.")

    headers = raw.get("required_headers") or {}
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and k.strip() and "\n" not in k + v
        for k, v in headers.items()
    ):
        raise ConfigurationError("policy.required_headers must map header names to strings.")

    user_agent = raw.get("user_agent") or ""
    if not isinstance(user_agent, str) or "\n" in user_agent:
        raise ConfigurationError("policy.user_agent must be a single-line string.")

    scanning = raw.get("automated_scanning")
    if scanning is not None and not isinstance(scanning, bool):
        raise ConfigurationError("policy.automated_scanning must be true or false.")

    return RequestPolicy(
        required_headers={k.strip(): v.strip() for k, v in headers.items()},
        user_agent=user_agent.strip(),
        rate_limit=_positive_int(raw.get("rate_limit"), "rate_limit", int(defaults.get("rate_limit", 5))),
        concurrency=_positive_int(raw.get("concurrency"), "concurrency", int(defaults.get("concurrency", 5))),
        automated_scanning=scanning,
    )
