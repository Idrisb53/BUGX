
import platform
import sys
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bugx import __version__
from bugx.core.authorization import Session
from bugx.core.config import load_settings
from bugx.core.exceptions import ConfigurationError
from bugx.core.program_manager import list_programs
from bugx.core.profile_creator import create_program_profile
from bugx.core.results_manager import ResultsManager, setup_logging
from bugx.core.scope import can_test_target, classify_target
from bugx.core.tool_manager import ToolManager
from bugx.modules.recon.subdomains import run_subdomain_recon


# =========================================================
# BUGX CONFIGURATION
# =========================================================

VERSION = __version__
DEVELOPER = "IDRIS4HACK"

YELLOW = "bold bright_yellow"
WHITE = "bold white"

console = Console()

app = typer.Typer(
    name="BUGX",
    help="BUGX - Bug Bounty Automation Framework",
    add_completion=False,
    no_args_is_help=False,
)

PLATFORMS = {
    "1": "HackerOne",
    "2": "Bugcrowd",
    "3": "Intigriti",
    "4": "YesWeHack",
    "5": "Custom",
}

PLATFORM_KEYS = {
    "HackerOne": "hackerone",
    "Bugcrowd": "bugcrowd",
    "Intigriti": "intigriti",
    "YesWeHack": "yeswehack",
    "Custom": "custom",
}


# =========================================================
# RECONNAISSANCE TECHNIQUES
# =========================================================

# The 10 reconnaissance tools. "module" is the adapter key in
# bugx.modules.recon.registry. (Directory, parameter, JS and API
# discovery moved to the Enumeration module; GAU/Waybackurls removed.)
RECON_TECHNIQUES = {
    "1": {"name": "Subdomain Discovery", "tools": "Subfinder", "module": "subfinder"},
    "2": {"name": "Attack Surface Discovery", "tools": "Amass", "module": "amass"},
    "3": {"name": "DNS Resolution", "tools": "dnsx", "module": "dnsx"},
    "4": {"name": "HTTP Service Probing", "tools": "httpx", "module": "httpx"},
    "5": {"name": "Port and Service Discovery", "tools": "Nmap", "module": "nmap"},
    "6": {"name": "Port Scanning", "tools": "Naabu", "module": "naabu"},
    "7": {"name": "Web Crawling", "tools": "Katana", "module": "katana"},
    "8": {"name": "Technology Fingerprinting", "tools": "WhatWeb", "module": "whatweb"},
    "9": {"name": "TLS Discovery", "tools": "tlsx", "module": "tlsx"},
    "10": {"name": "Cloud Asset Discovery", "tools": "Cloudlist", "module": "cloudlist"},
}

# Session shared by the interactive menus (set by control_center()).
ACTIVE_SESSION = None


# =========================================================
# COMMON HELPERS
# =========================================================

def pause():
    console.input(
        "\n[bold white]Press ENTER to continue...[/bold white]"
    )


def normalize_target_url(value: str):
    value = value.strip()
    parsed = urlparse(value)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    try:
        hostname = (
            parsed.hostname
            .encode("idna")
            .decode("ascii")
            .lower()
            .rstrip(".")
        )
    except UnicodeError as error:
        raise ValueError("Invalid target hostname.") from error

    return value, hostname


def get_platform_key(platform_name: str):
    key = PLATFORM_KEYS.get(platform_name)

    if not key:
        raise ValueError(f"Unsupported platform: {platform_name}")

    return key


def load_profile_from_path(profile_path: str):
    from bugx.core.program_manager import (
        load_program_profile_from_path,
    )

    return load_program_profile_from_path(profile_path)


def get_profile_target(profile: dict):
    program = profile.get("program", {})
    target_url = program.get("program_url", "")

    if not target_url:
        raise ValueError(
            "Program profile does not contain a target URL."
        )

    return normalize_target_url(target_url)


def print_error(message: str):
    console.print(f"\n[bold red][!] {message}[/bold red]")


def print_success(message: str):
    console.print(
        f"\n[bold bright_yellow][+] {message}[/bold bright_yellow]"
    )


# =========================================================
# BUGX BANNER
# =========================================================

def show_banner():

    logo = r"""
 ____   _   _   ____ __  __
| __ ) | | | | / ___|\ \/ /
|  _ \ | | | || |  _  \  /
| |_) || |_| || |_| | /  \
|____/  \___/  \____|/_/\_\
"""

    console.print(
        Text(logo, style=YELLOW, justify="center")
    )

    console.print(
        Text(
            "B U G  B O U N T Y  A U T O M A T I O N",
            style=WHITE,
            justify="center",
        )
    )

    console.print(
        Text(
            f"DEVELOPED BY {DEVELOPER.upper()}",
            style=YELLOW,
            justify="center",
        )
    )

    console.print(
        Text(
            "FIND. ANALYZE. VALIDATE. REPORT.",
            style=WHITE,
            justify="center",
        )
    )

    console.print()


# =========================================================
# PHASE 1: PLATFORM SELECTION
# =========================================================

def select_platform():
    console.print(
        Panel(
            "[bold bright_yellow]SELECT YOUR BUG BOUNTY PLATFORM[/bold bright_yellow]\n\n"
            "[bold white][1] HackerOne[/bold white]\n"
            "[bold white][2] Bugcrowd[/bold white]\n"
            "[bold white][3] Intigriti[/bold white]\n"
            "[bold white][4] YesWeHack[/bold white]\n"
            "[bold white][5] Custom / Private Program[/bold white]",
            title="PLATFORM SELECTION",
            border_style="bright_yellow",
            padding=(1, 3),
        )
    )

    while True:
        choice = console.input(
            "\n[bold bright_yellow]Enter your choice [1-5]: [/bold bright_yellow]"
        ).strip()

        if choice in PLATFORMS:
            selected = PLATFORMS[choice]

            console.print(
                Panel(
                    "[bold bright_yellow]PLATFORM SELECTED[/bold bright_yellow]\n\n"
                    f"[bold white]{selected}[/bold white]",
                    border_style="bright_yellow",
                )
            )

            return selected

        print_error("Invalid choice. Select 1 to 5.")


# =========================================================
# PHASE 2: CREATE NEW PROGRAM PROFILE
# =========================================================

def create_program_from_cli(selected_platform: str):
    console.print()

    console.print(
        Panel(
            "[bold bright_yellow]CREATE NEW PROGRAM PROFILE[/bold bright_yellow]\n\n"
            f"[white]Platform: {selected_platform}[/white]\n"
            "[white]Enter your authorized program details.[/white]",
            title="BUGX PROGRAM CREATOR",
            border_style="bright_yellow",
            padding=(1, 2),
        )
    )

    program_name = console.input(
        "\n[bold bright_yellow]Program name: [/bold bright_yellow]"
    ).strip()

    target_url = console.input(
        "[bold bright_yellow]Program target URL: [/bold bright_yellow]"
    ).strip()

    policy_url = console.input(
        "[bold bright_yellow]Official policy URL: [/bold bright_yellow]"
    ).strip()

    asset_value = console.input(
        "[bold bright_yellow]Exact in-scope asset: [/bold bright_yellow]"
    ).strip()

    if not all(
        [program_name, target_url, policy_url, asset_value]
    ):
        print_error("All fields are required.")
        raise typer.Exit(code=1)

    try:
        normalize_target_url(target_url)
    except ValueError as error:
        print_error(str(error))
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold bright_yellow]POLICY REVIEW[/bold bright_yellow]\n\n"
            "[white]Review the official program policy.[/white]\n"
            "[white]Check eligible assets, exclusions and testing restrictions.[/white]\n\n"
            f"[white]Policy: {policy_url}[/white]",
            border_style="bright_yellow",
        )
    )

    policy_confirmation = console.input(
        "\n[bold bright_yellow]Have you reviewed the official policy? Type YES: [/bold bright_yellow]"
    ).strip()

    if policy_confirmation != "YES":
        print_error("Policy review not confirmed. Creation cancelled.")
        raise typer.Exit(code=1)

    authorization_confirmation = console.input(
        "[bold bright_yellow]Are you authorized to test this asset? Type YES: [/bold bright_yellow]"
    ).strip()

    if authorization_confirmation != "YES":
        print_error("Authorization not confirmed. Creation cancelled.")
        raise typer.Exit(code=1)

    try:
        profile_path = create_program_profile(
            program_name=program_name,
            target_url=target_url,
            policy_url=policy_url,
            asset_value=asset_value,
            platform_key=get_platform_key(selected_platform),
            policy_reviewed=True,
            user_confirmed=True,
        )

        profile_path = str(profile_path)
        profile = load_profile_from_path(profile_path)

        console.print(
            Panel(
                "[bold bright_yellow]PROGRAM PROFILE CREATED SUCCESSFULLY[/bold bright_yellow]\n\n"
                f"[white]Program: {program_name}[/white]\n"
                f"[white]Platform: {selected_platform}[/white]\n"
                f"[white]Profile: {profile_path}[/white]",
                title="BUGX SUCCESS",
                border_style="bright_yellow",
            )
        )

        return profile, profile_path

    except typer.Exit:
        raise

    except Exception as error:
        print_error(f"PROFILE CREATION FAILED: {error}")
        console.print(
            "[white]If this profile already exists, use a unique program name.[/white]"
        )
        raise typer.Exit(code=1)


# =========================================================
# PHASE 2: SELECT EXISTING OR CONFIGURE NEW PROGRAM
# =========================================================

def select_or_create_program(selected_platform: str):
    """Let the user load a saved profile for this platform or create one."""

    platform_key = get_platform_key(selected_platform)

    saved = [
        item for item in list_programs()
        if item.get("platform") == platform_key and item.get("id") != "invalid"
    ]

    console.print(
        Panel(
            "[bold bright_yellow]PROGRAM PROFILE[/bold bright_yellow]\n\n"
            f"[bold white][1] Select existing program profile ({len(saved)} saved)[/bold white]\n"
            "[bold white][2] Configure new program profile[/bold white]",
            title="PROGRAM CONFIGURATION",
            border_style="bright_yellow",
            padding=(1, 3),
        )
    )

    while True:
        choice = console.input(
            "\n[bold bright_yellow]Enter your choice [1-2]: [/bold bright_yellow]"
        ).strip()

        if choice == "2":
            return create_program_from_cli(selected_platform)

        if choice == "1":
            if not saved:
                print_error("No saved profiles for this platform. Configure a new one.")
                return create_program_from_cli(selected_platform)
            break

        print_error("Invalid choice. Select 1 or 2.")

    table = Table(
        title=f"SAVED {selected_platform.upper()} PROFILES",
        border_style="bright_yellow",
        header_style=YELLOW,
        show_lines=True,
        expand=True,
    )

    table.add_column("OPTION", style=YELLOW, width=8)
    table.add_column("PROGRAM", style=WHITE)
    table.add_column("PROFILE ID", style=WHITE)
    table.add_column("FILE", style=WHITE)

    for number, item in enumerate(saved, start=1):
        table.add_row(
            str(number),
            str(item["name"]),
            str(item["id"]),
            item["profile_path"].rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
        )

    console.print(table)

    while True:
        pick = console.input(
            "\n[bold bright_yellow]Select profile number: [/bold bright_yellow]"
        ).strip()

        if pick.isdigit() and 1 <= int(pick) <= len(saved):
            profile_path = saved[int(pick) - 1]["profile_path"]
            break

        print_error("Invalid profile number.")

    try:
        profile = load_profile_from_path(profile_path)
    except Exception as error:
        print_error(f"Could not load profile: {error}")
        raise typer.Exit(code=1)

    print_success(f"Loaded profile: {profile_path}")

    return profile, profile_path


# =========================================================
# PHASE 3: SCOPE REVIEW
# =========================================================

def review_scope(profile: dict):
    scope = profile.get("scope", {})

    table = Table(
        title="PROGRAM SCOPE",
        border_style="bright_yellow",
        header_style=YELLOW,
        show_lines=True,
        expand=True,
    )

    table.add_column("ASSET", style=WHITE)
    table.add_column("TYPE", style=WHITE)
    table.add_column("MATCH", style=WHITE)
    table.add_column("STATUS", style=YELLOW)

    for asset in scope.get("assets", []) or scope.get("allowed_domains", []):
        if isinstance(asset, str):
            asset = {"value": asset, "type": "domain", "match": "legacy", "eligible": True}
        eligible = asset.get("eligible") is True
        table.add_row(
            str(asset.get("value")),
            str(asset.get("type")),
            str(asset.get("match")),
            "[bold bright_yellow]INCLUDED[/bold bright_yellow]" if eligible else "[bold red]NOT ELIGIBLE[/bold red]",
        )

    for asset in scope.get("excluded_assets", []) or scope.get("excluded_domains", []):
        if isinstance(asset, str):
            asset = {"value": asset, "type": "domain", "match": "legacy"}
        table.add_row(
            str(asset.get("value")),
            str(asset.get("type")),
            str(asset.get("match")),
            "[bold red]EXCLUDED[/bold red]",
        )

    console.print(table)

    policy = profile.get("policy") or {}
    headers = policy.get("required_headers") or {}

    console.print(
        Panel(
            "[bold bright_yellow]REQUEST RULES[/bold bright_yellow]\n\n"
            f"[white]Required headers: {', '.join(f'{k}: {v}' for k, v in headers.items()) or 'none recorded'}[/white]\n"
            f"[white]User-Agent: {policy.get('user_agent') or 'default'}[/white]\n"
            f"[white]Rate limit: {policy.get('rate_limit', 'default')} req/s[/white]\n"
            f"[white]Automated scanning: {({True: 'allowed', False: 'NOT allowed'}).get(policy.get('automated_scanning'), 'unknown - check the policy')}[/white]",
            border_style="bright_yellow",
        )
    )


# =========================================================
# PHASE 4: AUTHORIZATION AND TARGET VALIDATION
# =========================================================

def confirm_session_authorization(profile: dict) -> bool:
    program = profile.get("program", {})

    console.print(
        Panel(
            "[bold bright_yellow]AUTHORIZATION CONFIRMATION[/bold bright_yellow]\n\n"
            f"[white]Program: {program.get('name', 'Unknown')}[/white]\n"
            f"[white]Policy: {program.get('policy_url', '-')}[/white]\n\n"
            "[white]Only the INCLUDED assets above may be tested, under the program rules.[/white]\n"
            "[white]Discovered assets are never tested unless they are explicitly in scope.[/white]",
            border_style="bright_yellow",
        )
    )

    answer = console.input(
        "\n[bold bright_yellow]Confirm you are authorized to test this program now. Type YES: [/bold bright_yellow]"
    ).strip()

    return answer == "YES"


def default_target(profile: dict) -> str:
    """Session target suggestion: profile target if in scope, else the first exact asset."""

    try:
        _, hostname = get_profile_target(profile)
        if can_test_target(hostname, profile).get("allowed"):
            return hostname
    except ValueError:
        pass

    for asset in profile.get("scope", {}).get("assets", []):
        value = str(asset.get("value", ""))
        if asset.get("eligible") is True and not value.startswith("*."):
            return value.split("://", 1)[-1].split("/", 1)[0]

    return ""


def select_target(profile: dict) -> str:
    suggestion = default_target(profile)

    for _ in range(3):
        value = console.input(
            f"\n[bold bright_yellow]Target URL/domain [{suggestion or 'required'}]: [/bold bright_yellow]"
        ).strip() or suggestion

        if not value:
            print_error("A target is required.")
            continue

        try:
            _, hostname = normalize_target_url(
                value if "://" in value else f"https://{value}"
            )
        except ValueError as error:
            print_error(str(error))
            continue

        result = can_test_target(hostname, profile)

        if result.get("allowed"):
            console.print(
                f"[white]Scope status: [bold bright_yellow]{classify_target(hostname, profile)['status'].upper()}[/bold bright_yellow][/white]"
            )
            return hostname

        print_error(f"Target blocked: {result.get('status')}")
        console.print(f"[white]Reason: {result.get('reason')}[/white]")

    print_error("No authorized target selected. BUGX stopped.")
    raise typer.Exit(code=1)


# =========================================================
# INTERNAL AUTHORIZATION AND SCOPE CHECK
# =========================================================

def ensure_target_authorized(target: str, profile: dict):
    """
    Internal authorization and scope gate.

    Blocks testing unless the Scope Engine explicitly allows it.
    """

    try:
        result = can_test_target(target, profile)
    except Exception as error:
        print_error(f"Scope Engine error: {error}")
        raise typer.Exit(code=1)

    if not isinstance(result, dict):
        print_error(
            "Scope Engine returned an unexpected result. Testing blocked."
        )
        raise typer.Exit(code=1)

    if not result.get("allowed", False):
        status = result.get("status", "unverified")
        reason = result.get("reason", "Target not authorized.")

        print_error(f"Testing blocked: {status}")
        console.print(f"[white]Reason: {reason}[/white]")
        console.print(f"[white]Target: {target}[/white]")

        raise typer.Exit(code=1)

    return True


# =========================================================
# SCOPE CHECK COMMAND DISPLAY
# =========================================================

def validate_target(target: str, profile: dict):
    ensure_target_authorized(target, profile)

    console.print(
        Panel(
            "[bold bright_yellow]SCOPE CHECK PASSED[/bold bright_yellow]\n\n"
            f"[white]Program: {profile.get('program', {}).get('name', 'Unknown')}[/white]\n"
            f"[white]Target: {target}[/white]\n"
            "[white]Authorization: Confirmed[/white]\n"
            "[white]Scope: In scope[/white]",
            title="BUGX SCOPE RESULT",
            border_style="bright_yellow",
        )
    )

    return True


# =========================================================
# TOOL MANAGER
# =========================================================

def get_tool_manager():
    try:
        return ToolManager()
    except Exception as error:
        print_error(f"Could not initialize Tool Manager: {error}")
        return None


def get_tool_status(tool_manager):
    """Run the Tool Manager detection routine."""

    if tool_manager is None:
        return []

    try:
        result = tool_manager.check_all()
        return result if result is not None else []
    except Exception as error:
        print_error(f"Tool detection failed: {error}")
        return []


# =========================================================
# SYSTEM HEALTH
# =========================================================

HEALTH_STATUS_STYLE = {
    "Installed": "[bold bright_yellow]INSTALLED[/bold bright_yellow]",
    "Missing": "[bold red]MISSING[/bold red]",
    "Error": "[bold red]ERROR[/bold red]",
    "Not Configured": "[bold cyan]NOT CONFIGURED[/bold cyan]",
    "Unsupported OS": "[bold cyan]UNSUPPORTED OS[/bold cyan]",
}


def show_health_section(title: str, rows: list):
    table = Table(
        title=title,
        border_style="bright_yellow",
        header_style=YELLOW,
        show_lines=True,
        expand=True,
    )

    table.add_column("CHECK", style=WHITE)
    table.add_column("STATUS", style=YELLOW)
    table.add_column("DETAIL", style=WHITE)

    for row in rows:
        table.add_row(
            row["item"],
            HEALTH_STATUS_STYLE.get(row["status"], row["status"]),
            str(row["detail"]),
        )

    console.print(table)


def check_dependencies():
    console.print(
        "\n[bold bright_yellow]BUGX SYSTEM HEALTH[/bold bright_yellow]"
    )

    from bugx.core.health import run_health

    try:
        settings = load_settings()
    except ValueError as error:
        print_error(str(error))
        settings = {}

    health = run_health(settings or None)

    show_health_section("SYSTEM", health["system"])
    show_health_section("CONFIGURATION", health["configuration"])
    show_health_section("BROWSER / PLAYWRIGHT MCP", health["browser"])

    manager = get_tool_manager()

    if manager is None:
        return

    try:
        tools = manager.check_all_detailed(settings)
    except Exception as error:
        print_error(f"Tool detection failed: {error}")
        tools = get_tool_status(manager)

    table = Table(
        title="TOOL INVENTORY",
        border_style="bright_yellow",
        header_style=YELLOW,
        show_lines=True,
        expand=True,
    )

    table.add_column("TOOL", style=WHITE)
    table.add_column("CATEGORY", style=WHITE)
    table.add_column("STATUS", style=YELLOW)
    table.add_column("VERSION", style=WHITE)
    table.add_column("EXECUTABLE / GUIDANCE", style=WHITE)

    installed_count = 0
    missing_count = 0
    external_count = 0

    for tool in tools:
        name = getattr(tool, "name", "Unknown")
        category = getattr(tool, "category", "-")
        installed = getattr(tool, "installed", False)
        executable = getattr(tool, "executable", None)
        detailed = getattr(tool, "status", "")

        normalized_category = str(category).strip().lower()
        guidance = str(executable or "-")

        # External integrations are not missing CLI tools.
        if normalized_category == "external":
            status = "[bold cyan]MANUAL / EXTERNAL[/bold cyan]"
            external_count += 1

        elif installed:
            status = "[bold bright_yellow]INSTALLED[/bold bright_yellow]"
            installed_count += 1

        else:
            status = HEALTH_STATUS_STYLE.get(detailed, "[bold red]MISSING[/bold red]")
            missing_count += 1
            message = getattr(tool, "message", "")
            hint = getattr(tool, "install_hint", "")
            guidance = " ".join(
                part for part in (
                    str(executable) if executable else "",
                    message,
                    f"Install: {hint}" if hint else "",
                ) if part
            ) or "-"

        table.add_row(
            str(name),
            str(category),
            status,
            str(getattr(tool, "version", "") or "-"),
            guidance,
        )

    # System information
    table.add_row(
        "Python",
        "System",
        "[bold bright_yellow]AVAILABLE[/bold bright_yellow]",
        sys.version.split()[0],
    )

    table.add_row(
        "Operating System",
        "System",
        "[bold bright_yellow]AVAILABLE[/bold bright_yellow]",
        platform.system(),
    )

    console.print(table)

    # Summary
    console.print(
        Panel(
            f"[bold bright_yellow]INSTALLED TOOLS: {installed_count}[/bold bright_yellow]\n"
            f"[white]MISSING TOOLS: {missing_count}[/white]\n"
            f"[bold cyan]EXTERNAL INTEGRATIONS: {external_count}[/bold cyan]",
            title="SYSTEM SUMMARY",
            border_style="bright_yellow",
        )
    )


# =========================================================
# RECONNAISSANCE: SUBDOMAIN ENUMERATION
# =========================================================

def execute_subdomain_recon(
    target: str,
    profile_path: str,
):
    console.print(
        Panel(
            "[bold bright_yellow]SUBDOMAIN ENUMERATION[/bold bright_yellow]\n"
            "[white]Engine: Subfinder[/white]\n"
            "[white]Mode: Passive discovery[/white]",
            border_style="bright_yellow",
        )
    )

    try:
        profile = load_profile_from_path(profile_path)

        # Authorization and scope check before execution.
        ensure_target_authorized(target, profile)

        result = run_subdomain_recon(
            domain=target,
            config_path=profile_path,
        )

        all_subdomains = result.get("all_subdomains", [])
        in_scope = result.get("accepted_hosts", [])
        out_of_scope = result.get("out_of_scope_hosts", [])
        unverified = result.get("unverified_hosts", [])

        total_discovered = result.get(
            "total_discovered",
            len(all_subdomains),
        )

        table = Table(
            title="SUBDOMAIN RECON RESULTS",
            border_style="bright_yellow",
            header_style=YELLOW,
        )

        table.add_column("RESULT", style=WHITE)
        table.add_column("COUNT", style=YELLOW)

        table.add_row("Total Discovered", str(total_discovered))
        table.add_row("In Scope", str(len(in_scope)))
        table.add_row("Out of Scope", str(len(out_of_scope)))
        table.add_row("Unverified", str(len(unverified)))

        console.print(table)

        console.print(
            Panel(
                "[bold bright_yellow]RECONNAISSANCE COMPLETED[/bold bright_yellow]\n\n"
                "[white]Discovered assets are not automatically authorized.[/white]\n"
                "[white]Only assets explicitly allowed by the program scope may be tested.[/white]",
                border_style="bright_yellow",
            )
        )

        # Keys returned by modules.recon.subdomains.save_results()
        if result.get("all_file"):
            console.print(
                f"[white]All discovered: {result['all_file']}[/white]"
            )

        if result.get("output_file"):
            console.print(
                f"[white]In scope: {result['output_file']}[/white]"
            )

        if result.get("out_of_scope_file"):
            console.print(
                f"[white]Out of scope: {result['out_of_scope_file']}[/white]"
            )

        if result.get("unverified_file"):
            console.print(
                f"[white]Unverified: {result['unverified_file']}[/white]"
            )

        return result

    except typer.Exit:
        raise

    except Exception as error:
        print_error(f"Subdomain reconnaissance failed: {error}")
        return None


# =========================================================
# RECONNAISSANCE CONTROL MENU
# =========================================================

def show_recon_menu():
    table = Table(
        title="BUGX RECONNAISSANCE MODULE",
        border_style="bright_yellow",
        header_style=YELLOW,
        show_lines=True,
        expand=True,
    )

    table.add_column("OPTION", style=YELLOW, width=8)
    table.add_column("TECHNIQUE", style=WHITE)
    table.add_column("TOOLS", style=WHITE)

    for number, technique in RECON_TECHNIQUES.items():
        table.add_row(
            number,
            technique["name"],
            technique["tools"],
        )

    table.add_row("0", "Back to Control Center", "-")

    console.print(table)


def execute_recon_technique(
    choice: str,
    target: str,
    profile_path: str,
    session=None,
):
    technique = RECON_TECHNIQUES.get(choice)

    if not technique:
        print_error("Invalid reconnaissance option.")
        return

    session = session or ACTIVE_SESSION

    if session is None:
        # No validated session: fall back to the original Subfinder flow,
        # which performs its own authorization and scope checks.
        if technique["module"] == "subfinder":
            execute_subdomain_recon(
                target=target,
                profile_path=profile_path,
            )
            return

        print_error("No authorized session. Start BUGX interactively to run this tool.")
        return

    from bugx.modules.recon.controller import get_adapter
    from bugx.ui.menus import print_error as menu_error
    from bugx.ui.menus import run_tool_flow

    adapter = get_adapter(technique["module"])
    status = adapter.status(session.settings)

    if status.status != "Installed":
        menu_error(f"{adapter.name}: {status.status}. {status.message}")
        if status.install_hint:
            console.print(f"[white]Install: {status.install_hint}[/white]")
        return

    run_tool_flow(session, adapter, ResultsManager())


def reconnaissance_menu(
    target: str,
    profile_path: str,
    session=None,
):
    while True:
        console.print()
        show_recon_menu()

        choice = console.input(
            "\n[bold bright_yellow]Select reconnaissance technique: [/bold bright_yellow]"
        ).strip()

        if choice == "0":
            return

        if choice not in RECON_TECHNIQUES:
            print_error("Invalid choice.")
            continue

        execute_recon_technique(
            choice=choice,
            target=target,
            profile_path=profile_path,
            session=session,
        )

        pause()


# =========================================================
# OTHER MODULE MENUS
# =========================================================

def show_module_placeholder(module_name: str, description: str):
    console.print(
        Panel(
            f"[bold bright_yellow]{module_name}[/bold bright_yellow]\n\n"
            f"[white]{description}[/white]\n\n"
            "[white]Module is planned but not yet connected to an execution engine.[/white]",
            title="BUGX MODULE",
            border_style="bright_yellow",
        )
    )


# =========================================================
# CONTROL CENTER
# =========================================================

def show_control_center():
    console.print(
        Panel(
            "[bold bright_yellow]BUGX CONTROL CENTER[/bold bright_yellow]\n\n"
            "[bold white][1] Reconnaissance[/bold white]\n"
            "[bold white][2] Enumeration[/bold white]\n"
            "[bold white][3] Vulnerability Analysis[/bold white]\n"
            "[bold white][4] Safe Validation[/bold white]\n"
            "[bold white][5] Report Generator[/bold white]\n"
            "[bold white][6] System Health[/bold white]\n"
            "[bold white][7] About BUGX[/bold white]\n"
            "[bold white][0] Exit[/bold white]",
            title="CONTROL CENTER",
            border_style="bright_yellow",
            padding=(1, 3),
        )
    )


def build_session(
    profile: dict,
    profile_path: str,
    target: str,
    platform_name: str = "",
    authorized: bool = False,
):
    try:
        settings = load_settings()
    except ValueError as error:
        print_error(str(error))
        settings = {}

    try:
        session = Session(
            profile=profile,
            profile_path=str(profile_path),
            target=target,
            platform=get_platform_key(platform_name) if platform_name in PLATFORM_KEYS else "",
            settings=settings,
        )
    except ConfigurationError as error:
        print_error(f"Invalid program policy: {error}")
        raise typer.Exit(code=1)

    if authorized:
        session.confirm_authorization()

    return session


def control_center(
    profile: dict,
    profile_path: str,
    target: str,
    session=None,
):
    global ACTIVE_SESSION

    from bugx.ui import menus

    # Without a confirmed session nothing can execute (fail-closed).
    session = session or build_session(profile, profile_path, target)
    ACTIVE_SESSION = session
    results = ResultsManager()
    setup_logging()

    while True:
        console.print(
            Panel(
                f"[bold bright_yellow]PROGRAM: {profile.get('program', {}).get('name', 'Unknown')}[/bold bright_yellow]\n"
                f"[white]TARGET: {target}[/white]\n"
                f"[white]PROFILE: {profile_path}[/white]",
                title="ACTIVE BUGX SESSION",
                border_style="bright_yellow",
            )
        )

        show_control_center()

        choice = console.input(
            "\n[bold bright_yellow]Select an option: [/bold bright_yellow]"
        ).strip()

        if choice == "1":
            reconnaissance_menu(target, profile_path, session=session)

        elif choice == "2":
            menus.enumeration_menu(session, results)

        elif choice == "3":
            menus.analysis_menu(session, results)

        elif choice == "4":
            menus.validation_menu(session, results)

        elif choice == "5":
            menus.report_menu(session, results)

        elif choice == "6":
            check_dependencies()
            pause()

        elif choice == "7":
            about()
            pause()

        elif choice == "0":
            console.print(
                "\n[bold bright_yellow]Thank you for using BUGX.[/bold bright_yellow]"
            )
            raise typer.Exit(code=0)

        else:
            print_error("Invalid option. Try again.")


# =========================================================
# ABOUT
# =========================================================

def about():
    console.print(
        Panel(
            f"[bold bright_yellow]BUGX v{VERSION}[/bold bright_yellow]\n\n"
            "[white]Bug Bounty Automation Framework[/white]\n"
            "[white]Modular reconnaissance and security testing workflow.[/white]\n\n"
            f"[bold bright_yellow]Developer: {DEVELOPER}[/bold bright_yellow]\n\n"
            "[white]FIND. ANALYZE. VALIDATE. REPORT.[/white]",
            title="ABOUT BUGX",
            border_style="bright_yellow",
            padding=(1, 3),
        )
    )


# =========================================================
# STARTUP WORKFLOW
# =========================================================

def startup():
    show_banner()

    # STEP 2 - Platform
    selected_platform = select_platform()

    # STEP 3 - Program and target configuration
    profile, profile_path = select_or_create_program(
        selected_platform
    )

    review_scope(profile)

    # STEP 4 - Authorization and scope validation
    if not confirm_session_authorization(profile):
        print_error("Authorization not confirmed. BUGX stopped.")
        raise typer.Exit(code=1)

    target = select_target(profile)

    session = build_session(
        profile,
        profile_path,
        target,
        platform_name=selected_platform,
        authorized=True,
    )

    console.print(
        Panel(
            "[bold bright_yellow]BUGX SESSION READY[/bold bright_yellow]\n\n"
            f"[white]Platform: {selected_platform}[/white]\n"
            f"[white]Program: {profile.get('program', {}).get('name', 'Unknown')}[/white]\n"
            f"[white]Target: {target}[/white]\n"
            f"[white]Rate limit: {session.policy.rate_limit} req/s[/white]\n"
            "[white]Authorization checks will run internally before testing.[/white]",
            title="BUGX INITIALIZATION",
            border_style="bright_yellow",
        )
    )

    # STEP 5/6 - Control Center and modules
    control_center(
        profile=profile,
        profile_path=profile_path,
        target=target,
        session=session,
    )


# =========================================================
# CLI COMMANDS
# =========================================================

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Start BUGX interactive mode when no command is supplied."""

    if ctx.invoked_subcommand is None:
        startup()


@app.command()
def version():
    """Display BUGX version."""

    console.print(
        f"[bold bright_yellow]BUGX v{VERSION}[/bold bright_yellow]"
    )


@app.command()
def about_command():
    """Display BUGX information."""

    about()


@app.command()
def programs():
    """List saved program profiles."""

    try:
        saved = list_programs()

        console.print(
            Panel(
                "[bold bright_yellow]SAVED PROGRAM PROFILES[/bold bright_yellow]",
                border_style="bright_yellow",
            )
        )

        table = Table(
            border_style="bright_yellow",
            header_style=YELLOW,
            show_lines=True,
            expand=True,
        )

        table.add_column("PLATFORM", style=WHITE)
        table.add_column("PROGRAM", style=WHITE)
        table.add_column("PROFILE ID", style=YELLOW)
        table.add_column("PATH", style=WHITE)

        for item in saved:
            table.add_row(
                str(item["platform"]),
                str(item["name"]),
                str(item["id"]),
                str(item["profile_path"]),
            )

        console.print(table)

    except Exception as error:
        print_error(f"Could not list profiles: {error}")


@app.command()
def doctor():
    """Check BUGX tools and system dependencies."""

    check_dependencies()


@app.command()
def scope_check(
    target: str = typer.Argument(
        ...,
        help="Target hostname or URL to check.",
    ),
    profile_path: str = typer.Argument(
        ...,
        help="Path to the program YAML profile.",
    ),
):
    """Check whether a target is authorized and in scope."""

    try:
        profile = load_profile_from_path(profile_path)
        validate_target(target, profile)

    except typer.Exit:
        raise

    except Exception as error:
        print_error(str(error))
        raise typer.Exit(code=1)


@app.command()
def recon(
    target: str = typer.Argument(
        ...,
        help="Authorized target domain.",
    ),
    profile_path: str = typer.Argument(
        ...,
        help="Path to the program YAML profile.",
    ),
):
    """Run passive subdomain reconnaissance."""

    try:
        profile = load_profile_from_path(profile_path)

        _, hostname = normalize_target_url(
            target if "://" in target else f"https://{target}"
        )

        ensure_target_authorized(hostname, profile)

        result = execute_subdomain_recon(
            target=hostname,
            profile_path=profile_path,
        )

        if result is None:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise

    except Exception as error:
        print_error(str(error))
        raise typer.Exit(code=1)


def _offline_session(profile_path: str):
    """Session for read-only commands (no traffic, not authorized)."""

    profile = load_profile_from_path(profile_path)
    target = default_target(profile) or "unknown"
    return build_session(profile, profile_path, target)


@app.command()
def history(
    profile_path: str = typer.Argument(
        ...,
        help="Path to the program YAML profile.",
    ),
    limit: int = typer.Option(30, help="Number of scans to show."),
):
    """Show saved scan history for a program."""

    from bugx.ui.menus import history_table

    try:
        session = _offline_session(profile_path)
        history_table(ResultsManager(), session.program_id, limit=limit)
    except typer.Exit:
        raise
    except Exception as error:
        print_error(str(error))
        raise typer.Exit(code=1)


@app.command()
def report(
    profile_path: str = typer.Argument(
        ...,
        help="Path to the program YAML profile.",
    ),
    formats: str = typer.Option(
        "markdown,html,json,pdf",
        "--formats",
        help="Comma separated: markdown,html,json,pdf",
    ),
    validated_only: bool = typer.Option(
        False,
        "--validated-only",
        help="Include only findings marked Validated.",
    ),
):
    """Generate a report from previously saved scans and findings."""

    from bugx.reporting.generator import FORMATS, generate_report

    selected = tuple(f.strip().lower() for f in formats.split(",") if f.strip())
    unknown = [f for f in selected if f not in FORMATS]

    if unknown or not selected:
        print_error(f"Unknown format(s): {', '.join(unknown) or '-'}. Use: {', '.join(FORMATS)}")
        raise typer.Exit(code=1)

    try:
        session = _offline_session(profile_path)
        written = generate_report(
            session,
            ResultsManager(),
            selected,
            include_unvalidated=not validated_only,
        )
    except typer.Exit:
        raise
    except Exception as error:
        print_error(f"Report generation failed: {error}")
        raise typer.Exit(code=1)

    table = Table(
        title="REPORT FILES",
        border_style="bright_yellow",
        header_style=YELLOW,
        expand=True,
    )

    table.add_column("FORMAT", style=YELLOW)
    table.add_column("FILE", style=WHITE)

    for fmt, value in written.items():
        table.add_row(fmt.upper(), value)

    console.print(table)


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    app()
