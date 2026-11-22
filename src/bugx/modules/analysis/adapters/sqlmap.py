"""SQLmap – SQL injection DETECTION ONLY.

Hard-coded safe settings: level 1, risk 1, boolean/error/union techniques
only (no time-based or stacked queries), one thread, batch mode. BUGX never
passes enumeration/extraction options (--dump, --dbs, --tables, --os-*,
--file-*, --sql-query, ...); :data:`FORBIDDEN` is checked on every command.
"""

import re

from bugx.core.adapters import RunContext, ToolAdapter, strip_ansi

FORBIDDEN = (
    "--dump", "--dump-all", "--dbs", "--tables", "--columns", "--schema", "--passwords",
    "--users", "--privileges", "--roles", "--sql-query", "--sql-shell", "--os-shell",
    "--os-cmd", "--os-pwn", "--file-read", "--file-write", "--file-dest", "--forms",
    "--crawl", "--search", "--common-tables", "--eval", "--tamper", "--sqlmap-shell",
)

_PARAM = re.compile(r"^Parameter:\s+(?P<name>.+?)\s+\((?P<place>[A-Z]+)\)\s*$")
_TYPE = re.compile(r"^\s*Type:\s+(?P<type>.+)$")
_TITLE = re.compile(r"^\s*Title:\s+(?P<title>.+)$")


class SqlmapAdapter(ToolAdapter):
    key = "sqlmap"
    name = "SQLmap"
    module = "vulnerability_analysis"
    category = "SQL injection detection"
    purpose = "Detection only (level 1, risk 1, no data extraction)"
    binaries = ("sqlmap", "sqlmap.py")
    version_args = ("--version",)
    install = {
        "linux": "sudo apt install sqlmap",
        "windows": "pipx install sqlmap  (or git clone https://github.com/sqlmapproject/sqlmap)",
        "darwin": "brew install sqlmap",
    }
    input_kind = "url"
    intrusive = True
    default_timeout = 1800

    def build_args(self, ctx: RunContext, target):
        if "?" not in target:
            raise ValueError("SQLmap needs a URL with query parameters (e.g. from enumeration results).")
        delay = round(1 / max(1, ctx.policy.rate_limit), 2)
        args = [
            "-u", target, "--batch", "--level=1", "--risk=1", "--technique=BEU",
            "--threads=1", f"--delay={delay}", "--timeout=15", "--retries=1",
            f"--output-dir={ctx.work_dir}", "--disable-coloring",
            "--answers=crawl=N,follow=N,quit=Y",
        ]
        if ctx.policy.required_headers:
            args.append("--headers=" + "\n".join(f"{k}: {v}" for k, v in ctx.policy.required_headers.items()))
        if ctx.policy.user_agent:
            args.append(f"--user-agent={ctx.policy.user_agent}")
        check_safe(args)
        return args

    def parse(self, ctx, stdout, stderr, target):
        items = []
        current = None
        for line in strip_ansi(stdout).splitlines():
            param = _PARAM.match(line.strip())
            if param:
                current = {"name": param.group("name"), "place": param.group("place"), "types": []}
                items.append(current)
                continue
            if current is not None:
                kind = _TYPE.match(line)
                if kind:
                    current["types"].append(kind.group("type").strip())
        findings = []
        for entry in items:
            findings.append({
                "type": "finding",
                "asset": target,
                "finding": {
                    "title": f"Potential SQL injection in parameter '{entry['name']}'",
                    "severity": "High",
                    "confidence": "Medium",
                    "category": "sql_injection",
                    "url": target,
                    "method": "POST" if entry["place"] == "POST" else "GET",
                    "parameter": entry["name"],
                    "description": "sqlmap (detection mode) reported the parameter as injectable. Techniques: "
                    + ", ".join(entry["types"]),
                    "impact": "May allow reading or modifying database contents. Not exploited by BUGX.",
                    "remediation": "Use parameterised queries / prepared statements for all database access.",
                    "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                    "evidence": [f"sqlmap technique: {t}" for t in entry["types"]],
                },
            })
        if not findings and re.search(r"might be injectable|appears to be .* injectable", stdout, re.I):
            findings.append({
                "type": "finding",
                "asset": target,
                "finding": {
                    "title": "SQL injection heuristic signal",
                    "severity": "Medium",
                    "confidence": "Tentative",
                    "category": "sql_injection",
                    "url": target,
                    "description": "sqlmap heuristics flagged a parameter but did not confirm injection.",
                },
            })
        return findings


def check_safe(args: list[str]) -> None:
    """Raise ValueError if any argument enables data extraction or higher risk."""
    for arg in args:
        name, _, value = arg.partition("=")
        name = name.lower()
        if name in FORBIDDEN:
            raise ValueError(f"Forbidden sqlmap option: {arg}")
        if name == "--risk" and value != "1":
            raise ValueError(f"Forbidden sqlmap option: {arg}")
        if name == "--level" and value not in ("1", "2"):
            raise ValueError(f"Forbidden sqlmap option: {arg}")
        if name == "--technique" and any(t in value.upper() for t in "ST"):
            raise ValueError(f"Forbidden sqlmap option: {arg}")
