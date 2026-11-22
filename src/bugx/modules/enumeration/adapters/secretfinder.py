"""SecretFinder – flag *potential* secrets in JavaScript.

Matched values are redacted before storage. A match is only a lead that must
be reviewed manually; BUGX never uses or tests discovered secrets.
"""

import re

from bugx.core.adapters import RunContext, ToolAdapter, redact, strip_ansi

_LINE = re.compile(r"^\s*([A-Za-z0-9_ .-]{2,60}?)\s*(?:->|:|\t)\s*(\S.*)$")


class SecretFinderAdapter(ToolAdapter):
    key = "secretfinder"
    name = "SecretFinder"
    module = "enumeration"
    category = "JavaScript analysis"
    purpose = "Flag potential secrets in JavaScript files (values redacted)"
    binaries = ("secretfinder", "SecretFinder.py", "secretfinder.py")
    version_args = ()
    install = {"any": "git clone https://github.com/m4ll0k/SecretFinder && pip install -r SecretFinder/requirements.txt"}
    input_kind = "url"
    supports_headers = False
    default_timeout = 300

    def build_args(self, ctx: RunContext, target):
        return ["-i", target, "-o", "cli"]

    def parse(self, ctx, stdout, stderr, target):
        items = []
        for line in strip_ansi(stdout).splitlines():
            match = _LINE.match(line)
            if not match or match.group(1).lower().startswith(("[", "url", "http")):
                continue
            kind, value = match.group(1).strip(), match.group(2).strip()
            items.append({"type": "secret_candidate", "asset": target, "kind": kind, "value_redacted": redact(value)})
            items.append({
                "type": "finding",
                "asset": target,
                "finding": {
                    "title": f"Potential {kind} exposed in JavaScript",
                    "severity": "Informational",
                    "confidence": "Tentative",
                    "category": "secrets",
                    "description": f"SecretFinder matched a {kind} pattern in {target}. Value redacted: {redact(value)}",
                    "impact": "If the value is a live credential it could grant unauthorised access. Unverified.",
                    "remediation": "Remove secrets from client-side code and rotate any exposed credential.",
                },
            })
        return items
