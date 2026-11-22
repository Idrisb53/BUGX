"""Shared wordlist check for content-discovery adapters."""

from bugx.core.config import first_existing


def wordlist_status(settings: dict, kind: str = "directories") -> tuple[bool, str]:
    value = (settings.get("wordlists") or {}).get(kind)
    found = first_existing(value if isinstance(value, list) else [value])
    if not found:
        return False, f"No {kind} wordlist found; set wordlists.{kind} in config/bugx.yaml."
    return True, f"wordlist: {found}"
