"""Finding model, severity/confidence normalisation and OWASP mapping."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
CONFIDENCES = ("High", "Medium", "Low", "Tentative")

VALIDATION_STATUSES = (
    "Needs Review",
    "Potential",
    "Validated",
    "False Positive",
    "Not Reproducible",
)

_SEVERITY_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
    "information": "Informational",
    "none": "Informational",
    "unknown": "Informational",
    "ok": "Informational",
    "warn": "Low",
}

# OWASP Top 10 (2021) and OWASP API Security Top 10 (2023) per category.
TAXONOMY: dict[str, dict[str, str]] = {
    "xss": {"owasp": "A03:2021 Injection", "api": ""},
    "sql_injection": {"owasp": "A03:2021 Injection", "api": ""},
    "injection": {"owasp": "A03:2021 Injection", "api": ""},
    "ssrf": {"owasp": "A10:2021 Server-Side Request Forgery", "api": "API7:2023 Server Side Request Forgery"},
    "idor": {"owasp": "A01:2021 Broken Access Control", "api": "API1:2023 Broken Object Level Authorization"},
    "access_control": {"owasp": "A01:2021 Broken Access Control", "api": "API5:2023 Broken Function Level Authorization"},
    "open_redirect": {"owasp": "A01:2021 Broken Access Control", "api": ""},
    "csrf": {"owasp": "A01:2021 Broken Access Control", "api": ""},
    "misconfiguration": {"owasp": "A05:2021 Security Misconfiguration", "api": "API8:2023 Security Misconfiguration"},
    "exposed_files": {"owasp": "A05:2021 Security Misconfiguration", "api": "API8:2023 Security Misconfiguration"},
    "information_disclosure": {"owasp": "A05:2021 Security Misconfiguration", "api": "API8:2023 Security Misconfiguration"},
    "outdated_component": {"owasp": "A06:2021 Vulnerable and Outdated Components", "api": "API9:2023 Improper Inventory Management"},
    "tls": {"owasp": "A02:2021 Cryptographic Failures", "api": "API8:2023 Security Misconfiguration"},
    "authentication": {"owasp": "A07:2021 Identification and Authentication Failures", "api": "API2:2023 Broken Authentication"},
    "secrets": {"owasp": "A02:2021 Cryptographic Failures", "api": ""},
    "code_issue": {"owasp": "A04:2021 Insecure Design", "api": ""},
    "other": {"owasp": "", "api": ""},
}

_CATEGORY_KEYWORDS = [
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("sql_injection", ("sqli", "sql injection", "sql-injection", "injectable")),
    ("ssrf", ("ssrf", "server-side request", "server side request")),
    ("open_redirect", ("open redirect", "open-redirect", "redirect")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("idor", ("idor", "insecure direct object")),
    ("tls", ("tls", "ssl", "certificate", "cipher", "heartbleed", "hsts")),
    ("outdated_component", ("outdated", "vulnerable version", "cve-", "retire", "vulnerable library")),
    ("exposed_files", ("exposure", "exposed", "backup", ".git", ".env", "directory listing", "file disclosure")),
    ("authentication", ("login", "authentication", "default credentials")),
    ("secrets", ("secret", "api key", "token")),
    ("misconfiguration", ("misconfig", "header", "cors", "cookie", "method", "clickjacking")),
    ("injection", ("injection", "crlf", "xxe", "ldap")),
]


def normalize_severity(value: Any) -> str:
    if isinstance(value, str) and value.strip().lower() in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[value.strip().lower()]
    if isinstance(value, str) and value.strip().title() in SEVERITIES:
        return value.strip().title()
    return "Informational"


def categorize(*texts: str) -> str:
    joined = " ".join(t for t in texts if isinstance(t, str)).lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(keyword in joined for keyword in keywords):
            return category
    return "other"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    """A potential or validated security finding.

    Scanner output is always stored as ``Needs Review``/``Potential``; only
    the Safe Validation module may set ``Validated``.
    """

    title: str
    severity: str
    url: str
    source_tool: str
    description: str = ""
    confidence: str = "Low"
    method: str = "GET"
    parameter: str = ""
    category: str = ""
    owasp: str = ""
    owasp_api: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    evidence: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    validation_status: str = "Needs Review"
    validation_history: list[dict] = field(default_factory=list)
    scope_status: str = "unverified"
    scan_id: str = ""
    finding_id: str = ""
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if self.confidence not in CONFIDENCES:
            self.confidence = "Low"
        if self.validation_status not in VALIDATION_STATUSES:
            self.validation_status = "Needs Review"
        if not self.category:
            self.category = categorize(self.title, self.description)
        mapping = TAXONOMY.get(self.category, TAXONOMY["other"])
        self.owasp = self.owasp or mapping["owasp"]
        self.owasp_api = self.owasp_api or mapping["api"]
        # CVSS is only kept when a vector justifies it.
        if self.cvss_score is not None and not self.cvss_vector:
            self.cvss_score = None
        if not self.finding_id:
            self.finding_id = "BUGX-" + self.fingerprint()[:10].upper()

    def fingerprint(self) -> str:
        key = "|".join(
            [
                self.source_tool.lower(),
                self.title.strip().lower(),
                self.url.strip().lower(),
                self.method.upper(),
                self.parameter.strip().lower(),
            ]
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})
