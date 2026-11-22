"""Pick default targets for a tool from the session and saved results.

Only assets previously classified ``in_scope`` (or the session target) are
offered, and every candidate is passed through the scope gate again.
"""

from __future__ import annotations

from bugx.core.adapters import ToolAdapter, to_host, to_url
from bugx.core.authorization import Session
from bugx.core.results_manager import ResultsManager


def discovered_in_scope(session: Session, results: ResultsManager) -> tuple[list[str], list[str]]:
    """Return (hosts, urls) recorded as in scope for this program."""
    assets = results.in_scope_assets(session.program_id)
    hosts = sorted({to_host(a) for a in assets} | {to_host(session.target)})
    urls = sorted({a.split("#", 1)[0] for a in assets if "://" in a})
    return hosts, urls


def candidate_targets(
    session: Session,
    results: ResultsManager,
    adapter: ToolAdapter,
    use_discovered: bool = False,
    need_params: bool = False,
) -> list[str]:
    """Targets for ``adapter`` (session target by default, or discovered assets)."""
    if adapter.input_kind in ("path", "none"):
        return []
    if adapter.input_kind == "domain" or not use_discovered:
        base = [to_url(session.target)] if adapter.input_kind == "url" else [to_host(session.target)]
        candidates = base
    else:
        hosts, urls = discovered_in_scope(session, results)
        if adapter.input_kind == "host":
            candidates = hosts
        else:
            candidates = urls or [to_url(session.target)]
    if need_params:
        candidates = [c for c in candidates if "?" in c]
    allowed, _ = session.gate().filter_allowed(candidates)
    return allowed


def parameter_urls(session: Session, results: ResultsManager) -> list[str]:
    """In-scope URLs that carry query parameters (for Dalfox / SQLmap)."""
    _, urls = discovered_in_scope(session, results)
    allowed, _ = session.gate().filter_allowed([u for u in urls if "?" in u])
    return allowed
