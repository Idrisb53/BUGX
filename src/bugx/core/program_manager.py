
from pathlib import Path

import yaml


# ==========================================
# BUGX PROGRAM MANAGER
# ==========================================

from bugx.core.config import PROGRAMS_DIR, PROJECT_ROOT  # noqa: E402,F401


# ==========================================
# LOAD YAML PROFILE
# ==========================================

def load_program_file(profile_path: Path) -> dict:

    if not profile_path.is_file():
        raise FileNotFoundError(
            f"Program profile not found: {profile_path}"
        )

    try:
        with profile_path.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

    except yaml.YAMLError as error:
        raise ValueError(f"Invalid YAML profile: {error}") from error

    if not isinstance(config, dict):
        raise ValueError("Program profile must contain a YAML mapping.")

    return config


# ==========================================
# VALIDATE PROGRAM PROFILE
# ==========================================

def validate_program_profile(config: dict) -> bool:

    program = config.get("program")
    authorization = config.get("authorization")
    scope = config.get("scope")

    if not isinstance(program, dict):
        raise ValueError("Missing or invalid program section.")

    if not isinstance(authorization, dict):
        raise ValueError("Missing or invalid authorization section.")

    if not isinstance(scope, dict):
        raise ValueError("Missing or invalid scope section.")

    required_program_fields = [
        "id",
        "name",
        "platform",
        "program_url",
        "policy_url",
    ]

    for field in required_program_fields:
        if not isinstance(program.get(field), str) or not program[field].strip():
            raise ValueError(f"Missing or invalid program field: {field}")

    supported_platforms = {
        "hackerone",
        "bugcrowd",
        "intigriti",
        "yeswehack",
        "custom",
    }

    if program["platform"].lower() not in supported_platforms:
        raise ValueError("Unsupported bug bounty platform.")

    if authorization.get("user_confirmed") is not True:
        raise ValueError("User authorization confirmation is missing.")

    if authorization.get("policy_reviewed") is not True:
        raise ValueError("Program policy review confirmation is missing.")

    assets = scope.get("assets")

    if not isinstance(assets, list) or not assets:
        raise ValueError("No scope assets configured.")

    for asset in assets:

        if not isinstance(asset, dict):
            raise ValueError("Invalid asset entry.")

        if not isinstance(asset.get("type"), str):
            raise ValueError("Asset type is missing.")

        if not isinstance(asset.get("value"), str) or not asset["value"].strip():
            raise ValueError("Asset value is missing.")

        if asset.get("match") not in {"exact", "wildcard"}:
            raise ValueError("Asset match must be exact or wildcard.")

        if not isinstance(asset.get("eligible"), bool):
            raise ValueError("Asset eligibility must be true or false.")

    excluded_assets = scope.get("excluded_assets", [])

    if not isinstance(excluded_assets, list):
        raise ValueError("Excluded assets must be a list.")

    for asset in excluded_assets:

        if not isinstance(asset, dict):
            raise ValueError("Invalid excluded asset entry.")

        if not isinstance(asset.get("type"), str):
            raise ValueError("Excluded asset type is missing.")

        if not isinstance(asset.get("value"), str) or not asset["value"].strip():
            raise ValueError("Excluded asset value is missing.")

        if asset.get("match") not in {"exact", "wildcard"}:
            raise ValueError("Excluded asset match must be exact or wildcard.")

    return True


# ==========================================
# LOAD PROGRAM BY FILE PATH
# ==========================================

def load_program_profile_from_path(profile_path: str) -> dict:

    path = Path(profile_path)

    config = load_program_file(path)

    validate_program_profile(config)

    return config


# ==========================================
# FIND PROGRAM BY ID
# ==========================================

def load_program_profile(program_id: str) -> dict:

    if not program_id or not program_id.strip():
        raise ValueError("Program ID cannot be empty.")

    if not PROGRAMS_DIR.is_dir():
        raise FileNotFoundError(
            f"Programs directory not found: {PROGRAMS_DIR}"
        )

    matches = []

    for profile_path in PROGRAMS_DIR.rglob("*.yaml"):

        config = load_program_file(profile_path)

        program = config.get("program", {})

        if program.get("id") == program_id:
            matches.append((profile_path, config))

    if not matches:
        raise FileNotFoundError(
            f"No program found with ID: {program_id}"
        )

    if len(matches) > 1:
        raise ValueError(
            f"Duplicate program ID found: {program_id}"
        )

    config = matches[0][1]

    validate_program_profile(config)

    return config


# ==========================================
# LIST ALL PROGRAMS
# ==========================================

def list_programs() -> list:

    programs = []

    if not PROGRAMS_DIR.is_dir():
        return programs

    for profile_path in sorted(PROGRAMS_DIR.rglob("*.yaml")):

        try:
            config = load_program_file(profile_path)
        except (ValueError, OSError) as error:
            programs.append({
                "id": "invalid",
                "name": f"INVALID: {error}",
                "platform": profile_path.parent.name,
                "profile_path": str(profile_path),
            })
            continue

        program = config.get("program", {})

        programs.append({
            "id": program.get("id", "unknown"),
            "name": program.get("name", "Unknown"),
            "platform": program.get("platform", "unknown"),
            "profile_path": str(profile_path),
        })

    return programs
