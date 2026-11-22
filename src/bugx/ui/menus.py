"""Module menus for the BUGX Control Center.

Same visual language as ``bugx.cli``: bright-yellow borders/headers, white
text, ``[!]`` red errors, ``[+]`` yellow success. Every action goes through
the shared Session (authorization), ScopeGate and ResultsManager.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bugx.core.adapters import ToolAdapter, run_adapter
from bugx.core.authorization import Session
from bugx.core.findings import VALIDATION_STATUSES
from bugx.core.results_manager import ResultsManager, update_finding_fields
from bugx.modules.targeting import candidate_targets, discovered_in_scope, parameter_urls

YELLOW = "bold bright_yellow"
WHITE = "bold white"

console = Console()

STATUS_STYLE = {
    "Installed": "[bold bright_yellow]INSTALLED[/bold bright_yellow]",
    "Missing": "[bold red]MISSING[/bold red]",
    "Error": "[bold red]ERROR[/bold red]",
    "Not Configured": "[bold cyan]NOT CONFIGURED[/bold cyan]",
    "Unsupported OS": "[bold cyan]UNSUPPORTED OS[/bold cyan]",
}

RUN_STYLE = {
    "success": "[bold bright_yellow]SUCCESS[/bold bright_yellow]",
    "partial": "[bold bright_yellow]PARTIAL[/bold bright_yellow]",
    "blocked": "[bold red]BLOCKED[/bold red]",
    "skipped": "[bold cyan]SKIPPED[/bold cyan]",
}


def print_error(message: str) -> None:
    console.print(f"\n[bold red][!] {message}[/bold red]")


def print_success(message: str) -> None:
    console.print(f"\n[bold bright_yellow][+] {message}[/bold bright_yellow]")


def ask(prompt: str) -> str:
    return console.input(f"[bold bright_yellow]{prompt}[/bold bright_yellow]").strip()


def pause() -> None:
    console.input("\n[bold white]Press ENTER to continue...[/bold white]")


def confirm_yes(prompt: str) -> bool:
    return ask(f"{prompt} Type YES: ") == "YES"


# =========================================================
# TOOL MENUS
# =========================================================

def tool_table(title: str, adapters: list[ToolAdapter], statuses: dict, extras: list[tuple[str, str, str]] = ()) -> None:
    table = Table(title=title, border_style="bright_yellow", header_style=YELLOW, show_lines=True, expand=True)
    table.add_column("OPTION", style=YELLOW, width=8)
    table.add_column("TOOL", style=WHITE)
    table.add_column("PURPOSE", style=WHITE)
    table.add_column("STATUS", style=WHITE)
    for number, adapter in enumerate(adapters, start=1):
        status = statuses.get(adapter.key)
        label = STATUS_STYLE.get(status.status, status.status) if status else "-"
        table.add_row(str(number), adapter.name, adapter.purpose, label)
    for option, name, purpose in extras:
        table.add_row(option, name, purpose, "-")
    table.add_row("R", "Refresh tool status", "-", "-")
    table.add_row("0", "Back to Control Center", "-", "-")
    console.print(table)


def _choose_targets(session: Session, results: ResultsManager, adapter: ToolAdapter) -> list[str] | None:
    if adapter.input_kind == "none":
        return [session.target]
    if adapter.input_kind == "path":
        path = ask("Local path to analyse (directory or file): ")
        if not path or not Path(path).expanduser().exists():
            print_error("Path not found.")
            return None
        if adapter.key in ("semgrep", "trivy") and not confirm_yes(
            "Confirm this source code belongs to the program/you are authorized to analyse it."
        ):
            print_error("Source authorization not confirmed.")
            return None
        return [str(Path(path).expanduser())]

    needs_params = adapter.key in ("dalfox", "sqlmap")
    hosts, urls = discovered_in_scope(session, results)
    discovered = parameter_urls(session, results) if needs_params else (hosts if adapter.input_kind == "host" else urls)
    console.print(Panel(
        f"[bold bright_yellow]TARGET SELECTION – {adapter.name}[/bold bright_yellow]\n\n"
        f"[bold white][1] Session target ({session.target})[/bold white]\n"
        f"[bold white][2] Discovered in-scope assets ({len(discovered)})[/bold white]\n"
        "[bold white][3] Enter target manually[/bold white]",
        border_style="bright_yellow",
    ))
    choice = ask("Select targets: ")
    if choice == "1":
        targets = candidate_targets(session, results, adapter)
        if needs_params:
            print_error(f"{adapter.name} needs URLs with parameters; choose option 2 or 3.")
            return None
    elif choice == "2":
        targets = discovered if needs_params else candidate_targets(session, results, adapter, use_discovered=True)
    elif choice == "3":
        manual = ask("Target(s), comma separated: ")
        targets = [t.strip() for t in manual.split(",") if t.strip()]
    else:
        print_error("Invalid choice.")
        return None
    return targets


def _scope_review(session: Session, targets: list[str]) -> list[str]:
    allowed, blocked = session.gate().filter_allowed(targets)
    table = Table(title="SCOPE REVIEW", border_style="bright_yellow", header_style=YELLOW, expand=True)
    table.add_column("TARGET", style=WHITE)
    table.add_column("STATUS", style=WHITE)
    table.add_column("REASON", style=WHITE)
    for target in allowed[:25]:
        table.add_row(target, "[bold bright_yellow]IN SCOPE[/bold bright_yellow]", "Authorized")
    if len(allowed) > 25:
        table.add_row(f"... {len(allowed) - 25} more", "", "")
    for item in blocked[:25]:
        table.add_row(item["target"], f"[bold red]{str(item.get('status', '')).upper()}[/bold red]", str(item.get("reason", "")))
    console.print(table)
    return allowed


def show_run_summary(record: dict, path: Path) -> None:
    scope = record.get("scope", {})
    table = Table(title=f"{record.get('tool', '').upper()} RESULT", border_style="bright_yellow", header_style=YELLOW)
    table.add_column("RESULT", style=WHITE)
    table.add_column("VALUE", style=YELLOW)
    table.add_row("Status", RUN_STYLE.get(record.get("status"), f"[bold red]{str(record.get('status')).upper()}[/bold red]"))
    table.add_row("Tool version", record.get("tool_version") or "-")
    table.add_row("Duration (s)", str(record.get("duration")))
    table.add_row("Results", str(len(record.get("results", []))))
    table.add_row("In scope", str(len(scope.get("in_scope", []))))
    table.add_row("Out of scope (not tested)", str(len(scope.get("out_of_scope", []))))
    table.add_row("Unverified (not tested)", str(len(scope.get("unverified", []))))
    table.add_row("Findings (Needs Review)", str(len(record.get("findings", []))))
    console.print(table)
    for error in record.get("errors", [])[:5]:
        print_error(error)
    console.print(f"[white]Saved: {path}[/white]")


def run_tool_flow(session: Session, adapter: ToolAdapter, results: ResultsManager) -> None:
    console.print(Panel(
        f"[bold bright_yellow]{adapter.name}[/bold bright_yellow]\n\n"
        f"[white]{adapter.purpose}[/white]\n"
        f"[white]Sends traffic to target: {'yes' if adapter.sends_traffic and adapter.input_kind not in ('path', 'none') else 'no'}[/white]\n"
        f"[white]Active vulnerability testing: {'yes' if adapter.intrusive else 'no'}[/white]",
        border_style="bright_yellow",
    ))
    targets = _choose_targets(session, results, adapter)
    if not targets:
        return
    if adapter.input_kind not in ("path", "none"):
        targets = _scope_review(session, targets)
        if not targets:
            print_error("No target passed the scope gate. Nothing was executed.")
            return

    if adapter.intrusive:
        if session.policy.automated_scanning is False:
            print_error("This program's policy forbids automated scanning. Blocked.")
            return
        warning = "" if session.policy.automated_scanning else (
            "\n[bold red]The profile does not state whether automated scanning is allowed. "
            "Check the program policy before continuing.[/bold red]"
        )
        console.print(Panel(
            "[bold bright_yellow]ACTIVE VULNERABILITY SCAN[/bold bright_yellow]\n\n"
            f"[white]{len(targets)} in-scope target(s), rate limit {session.policy.rate_limit} req/s.[/white]\n"
            "[white]Safe, non-destructive settings are enforced.[/white]" + warning,
            border_style="bright_yellow",
        ))
        if not confirm_yes("Start active scanning on these targets?"):
            print_error("Active scanning not confirmed.")
            return
        session.active_scanning_confirmed = True
    elif adapter.sends_traffic and adapter.input_kind not in ("path", "none"):
        if not confirm_yes(f"Run {adapter.name} against {len(targets)} target(s)?"):
            print_error("Execution cancelled.")
            return

    try:
        with console.status(f"[bold bright_yellow]Running {adapter.name}...[/bold bright_yellow]", spinner="dots"):
            record, path = run_adapter(adapter, session, targets, results=results)
    finally:
        session.active_scanning_confirmed = False
    show_run_summary(record, path)


def tool_menu(session: Session, results: ResultsManager, title: str, adapters: list[ToolAdapter],
              extras: list[tuple[str, str, str]] = (), extra_handler=None) -> None:
    statuses = {}
    while True:
        if not statuses:
            with console.status("[bold bright_yellow]Checking tools...[/bold bright_yellow]", spinner="dots"):
                statuses = {a.key: a.status(session.settings) for a in adapters}
        console.print()
        tool_table(title, adapters, statuses, extras)
        choice = ask("Select a tool: ").upper()
        if choice == "0":
            return
        if choice == "R":
            statuses = {}
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(adapters):
            adapter = adapters[int(choice) - 1]
            status = statuses[adapter.key]
            if status.status != "Installed":
                print_error(f"{adapter.name}: {status.status}. {status.message}")
                if status.install_hint:
                    console.print(f"[white]Install: {status.install_hint}[/white]")
            else:
                run_tool_flow(session, adapter, results)
            pause()
            continue
        if extra_handler and any(choice == option for option, _, _ in extras):
            extra_handler(choice)
            pause()
            continue
        print_error("Invalid choice.")


# =========================================================
# MODULE MENUS
# =========================================================

def recon_menu(session: Session, results: ResultsManager) -> None:
    from bugx.modules.recon.registry import RECON_ADAPTERS

    tool_menu(session, results, "BUGX RECONNAISSANCE MODULE", RECON_ADAPTERS)


def enumeration_menu(session: Session, results: ResultsManager) -> None:
    from bugx.modules.enumeration.registry import ENUMERATION_ADAPTERS

    extras = [
        ("11", "Endpoint inventory", "Merge saved results: endpoints, parameters, login/API/JS tags"),
        ("12", "Collect JavaScript", "Download in-scope .js files (for Retire.js / review)"),
        ("13", "Browser inspection", "Playwright MCP: pages, links, forms, console, screenshots"),
    ]

    def handler(choice: str) -> None:
        if choice == "11":
            show_inventory(session, results)
        elif choice == "12":
            collect_javascript(session, results)
        elif choice == "13":
            browser_inspection(session, results)

    tool_menu(session, results, "BUGX ENUMERATION MODULE", ENUMERATION_ADAPTERS, extras, handler)


def analysis_menu(session: Session, results: ResultsManager) -> None:
    from bugx.modules.analysis.registry import ANALYSIS_ADAPTERS

    tool_menu(session, results, "BUGX VULNERABILITY ANALYSIS MODULE", ANALYSIS_ADAPTERS)


def show_inventory(session: Session, results: ResultsManager) -> None:
    from bugx.modules.enumeration.inventory import save_inventory

    inventory, path = save_inventory(session, results)
    summary = inventory["summary"]
    table = Table(title="ENDPOINT INVENTORY", border_style="bright_yellow", header_style=YELLOW)
    table.add_column("CATEGORY", style=WHITE)
    table.add_column("COUNT", style=YELLOW)
    for key, value in summary.items():
        table.add_row(key.replace("_", " ").title(), str(value))
    console.print(table)
    interesting = [e for e in inventory["endpoints"] if set(e["tags"]) & {"login", "registration", "api", "graphql", "admin", "upload", "parameters"}]
    if interesting:
        detail = Table(title="NOTABLE ENDPOINTS", border_style="bright_yellow", header_style=YELLOW, expand=True)
        detail.add_column("URL", style=WHITE)
        detail.add_column("TAGS", style=YELLOW)
        detail.add_column("PARAMS", style=WHITE)
        for entry in interesting[:30]:
            detail.add_row(entry["url"], ", ".join(entry["tags"]), ", ".join(entry["parameters"])[:60])
        console.print(detail)
    console.print(f"[white]Saved: {path}[/white]")


def collect_javascript(session: Session, results: ResultsManager) -> None:
    from bugx.modules.enumeration.js_collector import collect_js

    _, urls = discovered_in_scope(session, results)
    js_urls = [u for u in urls if ".js" in u.split("?")[0].lower()]
    if not js_urls:
        print_error("No in-scope JavaScript URLs in saved results. Run Katana/Hakrawler first.")
        return
    if not confirm_yes(f"Download {min(len(js_urls), 50)} in-scope JavaScript file(s)?"):
        return
    with console.status("[bold bright_yellow]Downloading JavaScript...[/bold bright_yellow]", spinner="dots"):
        record, path, out_dir = collect_js(session, js_urls, results)
    show_run_summary(record, path)
    console.print(f"[white]JavaScript saved to: {out_dir} (use as path for Retire.js)[/white]")


def browser_inspection(session: Session, results: ResultsManager) -> None:
    from bugx.integrations.playwright.browser import availability, inspect_pages

    state = availability(session.settings)
    if not state["available"]:
        console.print(Panel(
            "[bold bright_yellow]PLAYWRIGHT MCP NOT AVAILABLE[/bold bright_yellow]\n\n"
            + "\n".join(f"[white]- {m}[/white]" for m in state["missing"])
            + "\n\n[white]See INSTALLATION.md. All other BUGX modules keep working.[/white]",
            border_style="bright_yellow",
        ))
        return
    raw = ask(f"URL(s) to inspect, comma separated [default {session.target}]: ") or f"https://{session.target}"
    urls = [u.strip() if "://" in u else f"https://{u.strip()}" for u in raw.split(",") if u.strip()]
    urls = _scope_review(session, urls)
    if not urls:
        print_error("No URL passed the scope gate.")
        return
    follow = ask("Follow in-scope links? (y/N): ").lower() == "y"
    if not confirm_yes(f"Open {len(urls)} page(s) in a headless browser?"):
        return
    with console.status("[bold bright_yellow]Inspecting pages...[/bold bright_yellow]", spinner="dots"):
        record, path = inspect_pages(session, urls, results, max_pages=10 if follow else len(urls), follow_links=follow)
    table = Table(title="BROWSER INSPECTION", border_style="bright_yellow", header_style=YELLOW, expand=True)
    for column in ("URL", "STATUS", "TITLE", "LINKS (IN/OUT/UNV)", "FORM CONTROLS", "CONSOLE ERRORS"):
        table.add_column(column, style=WHITE)
    for row in record.get("results", []):
        if row.get("type") != "page":
            continue
        table.add_row(row.get("final_url") or row.get("requested_url"), row.get("status"), row.get("title", "")[:40],
                      f"{len(row['links_in_scope'])}/{len(row['links_out_of_scope'])}/{len(row['links_unverified'])}",
                      str(len(row["form_controls"])), str(len(row["console_errors"])))
    console.print(table)
    show_run_summary(record, path)


# =========================================================
# SAFE VALIDATION
# =========================================================

def findings_table(findings) -> None:
    table = Table(title="FINDINGS", border_style="bright_yellow", header_style=YELLOW, show_lines=True, expand=True)
    for column in ("#", "ID", "SEVERITY", "CONFIDENCE", "STATUS", "TITLE", "URL"):
        table.add_column(column, style=WHITE)
    for number, finding in enumerate(findings, start=1):
        table.add_row(str(number), finding.finding_id, finding.severity, finding.confidence,
                      finding.validation_status, finding.title[:60], finding.url[:60])
    console.print(table)


def validation_menu(session: Session, results: ResultsManager) -> None:
    from bugx.modules.validation import engine

    while True:
        findings = results.load_findings(session.program_id)
        console.print()
        if not findings:
            console.print(Panel(
                "[bold bright_yellow]SAFE VALIDATION[/bold bright_yellow]\n\n"
                "[white]No findings recorded yet. Run Vulnerability Analysis first.[/white]",
                border_style="bright_yellow",
            ))
            return
        findings_table(findings)
        choice = ask("Select finding number (0 = back): ")
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(findings):
            print_error("Invalid choice.")
            continue
        finding = findings[int(choice) - 1]
        check = engine.recheck_scope(session, finding)
        scope_line = (
            "[bold bright_yellow]Authorized and in scope[/bold bright_yellow]" if check.get("allowed")
            else f"[bold red]BLOCKED: {check.get('status')} – {check.get('reason')}[/bold red]"
        )
        console.print(Panel(
            f"[bold bright_yellow]{finding.finding_id} – {finding.title}[/bold bright_yellow]\n\n"
            f"[white]URL: {finding.url}[/white]\n[white]Method: {finding.method}   Parameter: {finding.parameter or '-'}[/white]\n"
            f"[white]Severity: {finding.severity}   Confidence: {finding.confidence}   Status: {finding.validation_status}[/white]\n"
            f"[white]Category: {finding.category}   OWASP: {finding.owasp or '-'}[/white]\n"
            f"[white]Source: {finding.source_tool}[/white]\n\n[white]{finding.description[:800]}[/white]\n\n"
            f"[white]Evidence: {', '.join(finding.evidence[:5]) or '-'}[/white]\n\nScope: {scope_line}",
            title="FINDING", border_style="bright_yellow",
        ))
        console.print(Panel(
            "\n".join(f"[white]{i}. {step}[/white]" for i, step in enumerate(engine.guidance_for(finding), start=1)),
            title="SAFE VALIDATION PROCEDURE", border_style="bright_yellow",
        ))
        console.print(
            "[bold white][1] Safe replay (single GET)  [2] Set validation status  "
            "[3] Add reproduction steps / impact  [4] Set CVSS  [0] Back[/bold white]"
        )
        action = ask("Action: ")
        try:
            if action == "1":
                if not check.get("allowed") or check.get("status") == "local":
                    print_error("Replay not permitted for this finding.")
                elif confirm_yes("Send ONE GET request to the affected URL?"):
                    outcome = engine.safe_replay(session, finding, results)
                    print_success(f"Replay status {outcome.get('status_code', '-')} – evidence {outcome['evidence']}")
                    if ask("Attach replay evidence to the finding? (y/N): ").lower() == "y":
                        engine.set_status(session, results, finding.finding_id, finding.validation_status,
                                          note="Safe replay evidence", evidence=[outcome["evidence"]])
            elif action == "2":
                for i, status in enumerate(VALIDATION_STATUSES, start=1):
                    console.print(f"[bold white][{i}] {status}[/bold white]")
                pick = ask("New status: ")
                if pick.isdigit() and 1 <= int(pick) <= len(VALIDATION_STATUSES):
                    note = ask("Note (what you did / observed): ")
                    evidence = [e.strip() for e in ask("Evidence file paths (comma separated, optional): ").split(",") if e.strip()]
                    updated = engine.set_status(session, results, finding.finding_id,
                                                VALIDATION_STATUSES[int(pick) - 1], note=note, evidence=evidence)
                    print_success(f"{updated.finding_id} -> {updated.validation_status}")
            elif action == "3":
                steps = [s.strip() for s in ask("Reproduction steps separated by ';': ").split(";") if s.strip()]
                impact = ask("Impact (blank = keep): ")
                fields = {"reproduction_steps": steps} if steps else {}
                if impact:
                    fields["impact"] = impact
                if fields:
                    update_finding_fields(results, session.program_id, finding.finding_id, **fields)
                    print_success("Finding updated.")
            elif action == "4":
                vector = ask("CVSS vector (e.g. CVSS:3.1/AV:N/...): ")
                score = ask("CVSS base score (0.0-10.0): ")
                update_finding_fields(results, session.program_id, finding.finding_id,
                                      cvss_vector=vector, cvss_score=float(score))
                print_success("CVSS recorded.")
        except (ValueError, KeyError, PermissionError) as error:
            print_error(str(error))
        pause()


# =========================================================
# REPORTS AND HISTORY
# =========================================================

def history_table(results: ResultsManager, program_id: str, limit: int = 30) -> None:
    scans = results.list_scans(program_id)
    table = Table(title="SCAN HISTORY", border_style="bright_yellow", header_style=YELLOW, expand=True)
    for column in ("TIME", "MODULE", "TOOL", "TARGET", "STATUS", "RESULTS", "FINDINGS"):
        table.add_column(column, style=WHITE)
    for scan in scans[:limit]:
        table.add_row(str(scan["timestamp"]), str(scan["module"]), str(scan["tool"]), str(scan["target"])[:40],
                      str(scan["status"]), str(scan["results"]), str(scan["findings"]))
    if not scans:
        table.add_row("-", "-", "-", "-", "No saved scans", "-", "-")
    console.print(table)


def report_menu(session: Session, results: ResultsManager) -> None:
    from bugx.reporting.generator import FORMATS, generate_report

    while True:
        console.print(Panel(
            "[bold bright_yellow]REPORT GENERATOR[/bold bright_yellow]\n\n"
            "[bold white][1] Generate full report (Markdown, HTML, JSON, PDF)[/bold white]\n"
            "[bold white][2] Generate report – validated findings only[/bold white]\n"
            "[bold white][3] View scan history[/bold white]\n"
            "[bold white][4] View findings[/bold white]\n"
            "[bold white][0] Back[/bold white]",
            border_style="bright_yellow",
        ))
        choice = ask("Select an option: ")
        if choice == "0":
            return
        if choice in ("1", "2"):
            with console.status("[bold bright_yellow]Generating report...[/bold bright_yellow]", spinner="dots"):
                written = generate_report(session, results, FORMATS, include_unvalidated=(choice == "1"))
            table = Table(title="REPORT FILES", border_style="bright_yellow", header_style=YELLOW, expand=True)
            table.add_column("FORMAT", style=YELLOW)
            table.add_column("FILE", style=WHITE)
            for fmt, value in written.items():
                table.add_row(fmt.upper(), value)
            console.print(table)
        elif choice == "3":
            history_table(results, session.program_id)
        elif choice == "4":
            findings = results.load_findings(session.program_id)
            if findings:
                findings_table(findings)
            else:
                console.print("[white]No findings recorded.[/white]")
        else:
            print_error("Invalid option.")
            continue
        pause()
