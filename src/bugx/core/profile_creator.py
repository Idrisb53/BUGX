
from datetime import date
from pathlib import Path
from urllib.parse import urlparse
import re

import yaml


# =========================================================
# BUGX CONFIGURATION
# =========================================================

from bugx.core.config import PROGRAMS_DIR, PROJECT_ROOT  # noqa: E402,F401

PLATFORMS = {
    "1": ("hackerone", "HackerOne"),
    "2": ("bugcrowd", "Bugcrowd"),
    "3": ("intigriti", "Intigriti"),
    "4": ("yeswehack", "YesWeHack"),
    "5": ("custom", "Custom / Private Program"),
}


# =========================================================
# COMMON HELPERS
# =========================================================

def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def validate_web_url(value: str) -> bool:
    try:
        parsed = urlparse(value.strip())

        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
        )

    except (ValueError, AttributeError):
        return False


def normalize_asset(value: str):
    """
    Return a normalized hostname or wildcard hostname.

    Examples:
        example.com       -> example.com
        *.example.com     -> *.example.com
        https://example.com -> example.com
    """

    value = value.strip().lower()

    if not value:
        return None

    wildcard = value.startswith("*.")

    if wildcard:
        value = value[2:]

    if "://" in value:

        if wildcard:
            return None

        parsed = urlparse(value)

        if parsed.scheme not in {"http", "https"}:
            return None

        hostname = parsed.hostname

    else:

        hostname = (
            value.split("/", 1)[0]
            .split("?", 1)[0]
        )

        if ":" in hostname:
            return None

    if not hostname:
        return None

    hostname = hostname.rstrip(".")

    try:
        hostname = (
            hostname.encode("idna")
            .decode("ascii")
            .lower()
        )

    except UnicodeError:
        return None

    labels = hostname.split(".")

    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
            for label in labels
        )
    ):
        return None

    return f"*.{hostname}" if wildcard else hostname


# =========================================================
# UNIQUE PROFILE GENERATOR
# =========================================================

def get_unique_profile_details(
    platform_dir: Path,
    program_id: str,
    platform_key: str,
):
    """
    Generate a unique profile filename and ID.

    Existing profiles are never overwritten.

    First profile:
        deriv.yaml
        deriv-hackerone

    Second profile:
        deriv-2.yaml
        deriv-hackerone-2
    """

    counter = 1

    while True:

        if counter == 1:

            filename = f"{program_id}.yaml"
            unique_id = f"{program_id}-{platform_key}"

        else:

            filename = f"{program_id}-{counter}.yaml"
            unique_id = (
                f"{program_id}-{platform_key}-{counter}"
            )

        profile_path = platform_dir / filename

        if not profile_path.exists():

            return unique_id, profile_path

        counter += 1


# =========================================================
# CREATE PROGRAM PROFILE
# =========================================================

def create_program_profile(
    program_name: str,
    target_url: str,
    policy_url: str,
    asset_value: str,
    platform_key: str,
    policy_reviewed: bool,
    user_confirmed: bool,
    additional_assets: list | None = None,
    excluded_assets: list | None = None,
    policy: dict | None = None,
) -> Path:
    """Create a new profile file (never overwrites).

    ``asset_value`` is the primary in-scope asset. ``additional_assets`` and
    ``excluded_assets`` are optional lists of hostnames / ``*.wildcards``;
    ``policy`` is an optional request-policy mapping (see bugx.core.policy).
    """

    # -----------------------------------------------------
    # INPUT VALIDATION
    # -----------------------------------------------------

    if platform_key not in {
        item[0] for item in PLATFORMS.values()
    }:

        raise ValueError(
            "Unsupported platform."
        )

    if not program_name.strip():

        raise ValueError(
            "Program name cannot be empty."
        )

    target_url = target_url.strip()
    policy_url = policy_url.strip()

    if not validate_web_url(target_url):

        raise ValueError(
            "Target URL must start with http:// or https://."
        )

    if not validate_web_url(policy_url):

        raise ValueError(
            "Policy URL must start with http:// or https://."
        )

    # -----------------------------------------------------
    # ASSET VALIDATION
    # -----------------------------------------------------

    asset = normalize_asset(asset_value)

    if not asset:

        raise ValueError(
            "Invalid in-scope hostname or wildcard."
        )

    extra_assets = []
    for value in additional_assets or []:
        normalized = normalize_asset(value)
        if not normalized:
            raise ValueError(f"Invalid in-scope asset: {value}")
        if normalized != asset and normalized not in extra_assets:
            extra_assets.append(normalized)

    exclusions = []
    for value in excluded_assets or []:
        normalized = normalize_asset(value)
        if not normalized:
            raise ValueError(f"Invalid excluded asset: {value}")
        if normalized not in exclusions:
            exclusions.append(normalized)

    if policy is not None:
        from bugx.core.policy import load_policy

        load_policy({"policy": policy})  # validates, raises ConfigurationError

    # -----------------------------------------------------
    # AUTHORIZATION CONFIRMATION
    # -----------------------------------------------------

    if not policy_reviewed or not user_confirmed:

        raise PermissionError(
            "Policy review and authorization confirmation are required."
        )

    # -----------------------------------------------------
    # PROGRAM IDENTIFICATION
    # -----------------------------------------------------

    program_id = slugify(program_name)

    if not program_id:

        raise ValueError(
            "Program name must contain letters or numbers."
        )

    # -----------------------------------------------------
    # CREATE PLATFORM DIRECTORY
    # -----------------------------------------------------

    platform_dir = PROGRAMS_DIR / platform_key

    platform_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # -----------------------------------------------------
    # GENERATE UNIQUE PROFILE ID AND PATH
    # -----------------------------------------------------

    profile_id, profile_path = get_unique_profile_details(
        platform_dir=platform_dir,
        program_id=program_id,
        platform_key=platform_key,
    )

    # -----------------------------------------------------
    # PROFILE DATA
    # -----------------------------------------------------

    profile = {
        "program": {
            "id": profile_id,
            "name": program_name.strip(),
            "platform": platform_key,
            "program_url": target_url,
            "policy_url": policy_url,
        },

        "authorization": {
            "user_confirmed": True,
            "policy_reviewed": True,
            "confirmation_date": date.today().isoformat(),
            "evidence_url": policy_url,
        },

        "scope": {
            "assets": [
                {
                    "type": "domain",
                    "value": value,
                    "match": (
                        "wildcard"
                        if value.startswith("*.")
                        else "exact"
                    ),
                    "eligible": True,
                }
                for value in [asset, *extra_assets]
            ],

            "excluded_assets": [
                {
                    "type": "domain",
                    "value": value,
                    "match": "wildcard" if value.startswith("*.") else "exact",
                }
                for value in exclusions
            ],
        },
    }

    if policy:
        profile["policy"] = policy

    # -----------------------------------------------------
    # SAVE PROFILE WITHOUT OVERWRITING
    # -----------------------------------------------------

    try:

        # Exclusive creation prevents overwriting an existing
        # profile, even if another process creates it meanwhile.
        with profile_path.open(
            "x",
            encoding="utf-8",
        ) as file:

            yaml.safe_dump(
                profile,
                file,
                sort_keys=False,
                allow_unicode=True,
            )

    except FileExistsError:

        # Another process may have created the same filename.
        # Retry with a new unique filename.
        return create_program_profile(
            program_name=program_name,
            target_url=target_url,
            policy_url=policy_url,
            asset_value=asset_value,
            platform_key=platform_key,
            policy_reviewed=policy_reviewed,
            user_confirmed=user_confirmed,
            additional_assets=additional_assets,
            excluded_assets=excluded_assets,
            policy=policy,
        )

    return profile_path


# =========================================================
# INTERACTIVE PROGRAM SETUP
# =========================================================

def interactive_program_setup() -> Path:

    print("\n========== BUGX PROGRAM SETUP ==========\n")

    print("Select bug bounty platform:")

    for number, (_, display_name) in PLATFORMS.items():

        print(f"[{number}] {display_name}")

    choice = input(
        "\nEnter choice [1-5]: "
    ).strip()

    if choice not in PLATFORMS:

        raise ValueError(
            "Invalid platform selection."
        )

    platform_key, platform_name = PLATFORMS[choice]

    print(
        f"\nSelected platform: {platform_name}"
    )

    program_name = input(
        "Program name: "
    ).strip()

    target_url = input(
        "Target URL: "
    ).strip()

    policy_url = input(
        "Program policy / scope URL: "
    ).strip()

    asset_value = input(
        "In-scope asset exactly as listed: "
    ).strip()

    print(
        "\nReview the official program policy and verify this asset."
    )

    reviewed = input(
        "Have you reviewed the policy? Type YES: "
    ).strip()

    confirmed = input(
        "Is this asset explicitly eligible and authorized? Type YES: "
    ).strip()

    if reviewed != "YES" or confirmed != "YES":

        raise PermissionError(
            "Authorization not confirmed. BUGX stopped."
        )

    path = create_program_profile(
        program_name=program_name,
        target_url=target_url,
        policy_url=policy_url,
        asset_value=asset_value,
        platform_key=platform_key,
        policy_reviewed=True,
        user_confirmed=True,
    )

    print(
        f"\n[+] Program profile created: {path}"
    )

    return path
