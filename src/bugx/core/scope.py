
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import re

import yaml


# =========================================================
# BUGX SCOPE VALIDATION ENGINE v2.0
# =========================================================

SUPPORTED_ASSET_TYPES = {"url", "domain"}
SUPPORTED_MATCH_TYPES = {"exact", "wildcard"}

HOSTNAME_LABEL_PATTERN = (
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)


# =========================================================
# LOAD CONFIGURATION
# =========================================================

def load_scope(config_path: str) -> dict:
    path = Path(config_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Configuration not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        raise ValueError("Invalid scope configuration.")

    return config


# =========================================================
# AUTHORIZATION CHECK
# =========================================================

def is_authorized(config: dict) -> bool:
    if not isinstance(config, dict):
        return False

    authorization = config.get("authorization", {})

    if not isinstance(authorization, dict):
        return False

    # Current profile format
    if "user_confirmed" in authorization:
        return (
            authorization.get("user_confirmed") is True
            and authorization.get("policy_reviewed") is True
        )

    # Legacy compatibility
    return authorization.get("authorized") is True


# =========================================================
# HOSTNAME NORMALIZATION
# =========================================================

def normalize_hostname(value: str):
    """
    Normalize a hostname.

    Supports:
        example.com
        example.com:443
        https://example.com
        *.example.com

    Returns None for invalid hostnames and IP addresses.
    """

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    wildcard = value.startswith("*.")

    if wildcard:
        value = value[2:]

    # URL input
    if "://" in value:
        try:
            parsed = urlsplit(value)

            if (
                parsed.scheme.lower() not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                return None

            hostname = parsed.hostname

        except ValueError:
            return None

    else:
        # Remove path, query and fragment
        hostname = re.split(
            r"[/#?]",
            value,
            maxsplit=1,
        )[0]

        if not hostname or "@" in hostname:
            return None

        # Handle bracketed IPv6
        if hostname.startswith("["):
            try:
                parsed = urlsplit("http://" + hostname)
                hostname = parsed.hostname
            except ValueError:
                return None

        # Remove a normal hostname port
        elif hostname.count(":") == 1:
            hostname = hostname.rsplit(":", 1)[0]

        # Bare IPv6 is not supported
        elif hostname.count(":") > 1:
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

    # IP scope is not implemented
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    if len(hostname) > 253:
        return None

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                HOSTNAME_LABEL_PATTERN,
                label,
            )
        ):
            return None

    if wildcard:
        return "*." + hostname

    return hostname


# =========================================================
# TARGET PARSING
# =========================================================

def parse_target(value: str):
    """
    Parse a URL or hostname.

    Returns:
        {
            "hostname": "...",
            "scheme": "https" or None,
            "port": 443 or None,
            "path": "/api" or "/",
            "is_url": True or False
        }

    Invalid inputs return None.
    """

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    is_url = "://" in value

    try:
        if is_url:
            parsed = urlsplit(value)

            if parsed.scheme.lower() not in ("http", "https"):
                return None

            if (
                not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                return None

            hostname = normalize_hostname(parsed.hostname)

            if not hostname or hostname.startswith("*."):
                return None

            port = parsed.port

            if port is not None and not (1 <= port <= 65535):
                return None

            path = normalize_path(parsed.path or "/")

            if path is None:
                return None

            return {
                "hostname": hostname,
                "scheme": parsed.scheme.lower(),
                "port": port,
                "path": path,
                "is_url": True,
            }

        # Bare hostname or hostname:port
        hostname = normalize_hostname(value)

        if not hostname or hostname.startswith("*."):
            return None

        return {
            "hostname": hostname,
            "scheme": None,
            "port": None,
            "path": "/",
            "is_url": False,
        }

    except (ValueError, UnicodeError):
        return None


# =========================================================
# URL PATH NORMALIZATION
# =========================================================

def normalize_path(path: str):
    """
    Normalize URL paths conservatively.

    - Requires a leading slash.
    - Rejects backslashes and control characters.
    - Rejects malformed percent escapes.
    - Rejects dot segments, including encoded dot segments.
    - Preserves path case and trailing slash.
    """

    if not isinstance(path, str):
        return None

    if not path:
        return "/"

    if not path.startswith("/"):
        return None

    if "\\" in path:
        return None

    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return None

    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        return None

    # Reject literal and percent-encoded dot segments.
    for segment in path.split("/"):
        decoded_segment = re.sub(
            r"%2e",
            ".",
            segment,
            flags=re.IGNORECASE,
        )

        if decoded_segment in (".", ".."):
            return None

    # Normalize percent-escape hex casing.
    path = re.sub(
        r"%[0-9a-fA-F]{2}",
        lambda match: match.group(0).upper(),
        path,
    )

    return path


# =========================================================
# DOMAIN MATCHING
# =========================================================

def hostname_matches(
    target_hostname: str,
    asset_hostname: str,
    match_type: str,
) -> bool:

    normalized_asset = normalize_hostname(asset_hostname)

    if not normalized_asset:
        return False

    if match_type == "exact":

        if normalized_asset.startswith("*."):
            return False

        return target_hostname == normalized_asset

    if match_type == "wildcard":

        if not normalized_asset.startswith("*."):
            return False

        base_domain = normalized_asset[2:]

        # Wildcard does not include apex domain.
        return (
            target_hostname != base_domain
            and target_hostname.endswith("." + base_domain)
        )

    return False


# =========================================================
# URL PATH MATCHING
# =========================================================

def path_matches(
    target_path: str,
    asset_path: str,
) -> bool:

    normalized_target = normalize_path(target_path)
    normalized_asset = normalize_path(asset_path)

    if normalized_target is None or normalized_asset is None:
        return False

    # A trailing /* means this path and its descendants.
    if normalized_asset.endswith("/*"):

        base_path = normalized_asset[:-2]

        if not base_path:
            base_path = "/"

        return (
            normalized_target == base_path
            or normalized_target.startswith(base_path + "/")
            or (
                base_path == "/"
                and normalized_target.startswith("/")
            )
        )

    # Otherwise require exact path equality.
    return normalized_target == normalized_asset


# =========================================================
# ASSET MATCHING
# =========================================================

def asset_matches(target: str, asset: dict) -> bool:
    """
    Match a target against one scope asset.

    Domain assets:
        Exact and wildcard hostname matching.

    URL assets:
        Scheme, hostname, port and path matching.
    """

    if not isinstance(asset, dict):
        return False

    asset_type = asset.get("type")
    match_type = asset.get("match")
    asset_value = asset.get("value")

    if asset_type not in SUPPORTED_ASSET_TYPES:
        return False

    if match_type not in SUPPORTED_MATCH_TYPES:
        return False

    target_info = parse_target(target)

    if not target_info:
        return False

    # -----------------------------------------------------
    # DOMAIN ASSET
    # -----------------------------------------------------

    if asset_type == "domain":

        asset_hostname = normalize_hostname(asset_value)

        if not asset_hostname:
            return False

        return hostname_matches(
            target_info["hostname"],
            asset_hostname,
            match_type,
        )

    # -----------------------------------------------------
    # URL ASSET
    # -----------------------------------------------------

    if asset_type == "url":

        if not isinstance(asset_value, str):
            return False

        if "://" not in asset_value:
            return False

        try:
            parsed_asset = urlsplit(asset_value)

            if (
                parsed_asset.scheme.lower() not in ("http", "https")
                or not parsed_asset.hostname
                or parsed_asset.username
                or parsed_asset.password
            ):
                return False

            asset_hostname = normalize_hostname(
                parsed_asset.hostname
            )

            if not asset_hostname:
                return False

            asset_port = parsed_asset.port
            asset_scheme = parsed_asset.scheme.lower()

            asset_path = normalize_path(
                parsed_asset.path or "/"
            )

            if asset_path is None:
                return False

            # URL asset must match scheme and port.
            if target_info["scheme"] != asset_scheme:
                return False

            if target_info["port"] != asset_port:
                return False

            if not hostname_matches(
                target_info["hostname"],
                asset_hostname,
                match_type,
            ):
                return False

            return path_matches(
                target_info["path"],
                asset_path,
            )

        except (ValueError, UnicodeError):
            return False

    return False


# =========================================================
# SCOPE CLASSIFICATION
# =========================================================

def classify_target(target: str, config: dict) -> dict:
    """
    Classify a target.

    Returns:
        {
            "status": "in_scope" | "out_of_scope" | "unverified",
            "reason": "..."
        }

    Exclusions always take priority.
    """

    if not isinstance(config, dict):
        return {
            "status": "unverified",
            "reason": "Invalid configuration",
        }

    target_info = parse_target(target)

    if not target_info:
        return {
            "status": "unverified",
            "reason": "Invalid or unsupported target",
        }

    scope = config.get("scope", {})

    if not isinstance(scope, dict):
        return {
            "status": "unverified",
            "reason": "Invalid scope configuration",
        }

    # -----------------------------------------------------
    # NEW PROFILE FORMAT
    # -----------------------------------------------------

    if "assets" in scope:

        assets = scope.get("assets", [])
        excluded_assets = scope.get("excluded_assets", [])

        if (
            not isinstance(assets, list)
            or not isinstance(excluded_assets, list)
        ):
            return {
                "status": "unverified",
                "reason": "Invalid assets or exclusions list",
            }

        # Exclusions always take priority.
        for asset in excluded_assets:

            if asset_matches(target, asset):

                return {
                    "status": "out_of_scope",
                    "reason": "Matches an explicitly excluded asset",
                }

        # Only explicitly eligible assets are authorized.
        for asset in assets:

            if not isinstance(asset, dict):
                continue

            if asset.get("eligible") is not True:
                continue

            if asset_matches(target, asset):

                return {
                    "status": "in_scope",
                    "reason": "Matches an explicitly eligible asset",
                }

        return {
            "status": "unverified",
            "reason": "No eligible scope asset matched",
        }

    # -----------------------------------------------------
    # LEGACY PROFILE FORMAT
    # -----------------------------------------------------

    allowed = scope.get("allowed_domains", [])
    excluded = scope.get("excluded_domains", [])

    if not isinstance(allowed, list) or not isinstance(excluded, list):
        return {
            "status": "unverified",
            "reason": "Invalid legacy scope configuration",
        }

    # Legacy exclusions first.
    for item in excluded:

        normalized = normalize_hostname(item)

        if not normalized:
            continue

        match_type = (
            "wildcard"
            if normalized.startswith("*.")
            else "exact"
        )

        if hostname_matches(
            target_info["hostname"],
            normalized,
            match_type,
        ):

            return {
                "status": "out_of_scope",
                "reason": "Matches a legacy excluded domain",
            }

    # Legacy allowed domains.
    for item in allowed:

        normalized = normalize_hostname(item)

        if not normalized:
            continue

        match_type = (
            "wildcard"
            if normalized.startswith("*.")
            else "exact"
        )

        if hostname_matches(
            target_info["hostname"],
            normalized,
            match_type,
        ):

            return {
                "status": "in_scope",
                "reason": "Matches a legacy allowed domain",
            }

    return {
        "status": "unverified",
        "reason": "No allowed asset matched",
    }


# =========================================================
# BACKWARD-COMPATIBLE SCOPE CHECK
# =========================================================

def is_in_scope(domain: str, config: dict) -> bool:
    """
    Existing modules can continue using this function.
    Only in_scope returns True.
    """

    result = classify_target(domain, config)

    return result["status"] == "in_scope"


# =========================================================
# AUTHORIZATION + SCOPE GATE
# =========================================================

def can_test_target(target: str, config: dict) -> dict:
    """
    Final gate before any active testing.

    Both authorization and scope must pass.
    """

    if not is_authorized(config):

        return {
            "allowed": False,
            "status": "unauthorized",
            "reason": "Program authorization is not confirmed",
        }

    classification = classify_target(target, config)

    if classification["status"] != "in_scope":

        return {
            "allowed": False,
            "status": classification["status"],
            "reason": classification["reason"],
        }

    return {
        "allowed": True,
        "status": "in_scope",
        "reason": classification["reason"],
    }
