
import re
import shutil
import subprocess

from bugx.core.scope import (
    load_scope,
    is_authorized,
    classify_target,
    normalize_hostname,
)


# =========================================================
# DOMAIN VALIDATION
# =========================================================

def valid_domain(domain: str) -> bool:
    """Validate a normalized hostname."""

    hostname = normalize_hostname(domain)

    if not hostname or hostname.startswith("*."):
        return False

    if len(hostname) > 253:
        return False

    pattern = (
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
    )

    return re.fullmatch(pattern, hostname) is not None


# =========================================================
# SCOPE CLASSIFICATION
# =========================================================

def classify_subdomains(
    discovered: list,
    config: dict,
) -> dict:
    """
    Classify discovered hosts using Scope Engine v2.0.

    Only explicitly eligible assets are accepted.
    """

    in_scope = set()
    out_of_scope = set()
    unverified = set()

    for hostname in discovered:

        result = classify_target(hostname, config)
        status = result.get("status")

        if status == "in_scope":
            in_scope.add(hostname)

        elif status == "out_of_scope":
            out_of_scope.add(hostname)

        else:
            # Unknown or unverified results are never accepted.
            unverified.add(hostname)

    return {
        "in_scope": sorted(in_scope),
        "out_of_scope": sorted(out_of_scope),
        "unverified": sorted(unverified),
    }


# =========================================================
# SAVE RECON RESULTS
# =========================================================

def save_results(
    domain: str,
    discovered: list,
    classified: dict,
) -> dict:

    safe_name = domain.replace(".", "_")

    from bugx.core.config import output_root

    output_dir = (
        output_root()
        / "recon"
        / safe_name
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    files = {
        "all_discoveries": output_dir / "all_subdomains.txt",
        "in_scope": output_dir / "in_scope.txt",
        "out_of_scope": output_dir / "out_of_scope.txt",
        "unverified": output_dir / "unverified.txt",
    }

    results = {
        "all_discoveries": sorted(set(discovered)),
        "in_scope": classified["in_scope"],
        "out_of_scope": classified["out_of_scope"],
        "unverified": classified["unverified"],
    }

    for key, file_path in files.items():

        entries = results[key]

        content = (
            "\n".join(entries) + "\n"
            if entries
            else ""
        )

        file_path.write_text(
            content,
            encoding="utf-8",
        )

    return {
        "output_directory": str(output_dir),
        "output_file": str(files["in_scope"]),
        "all_file": str(files["all_discoveries"]),
        "out_of_scope_file": str(files["out_of_scope"]),
        "unverified_file": str(files["unverified"]),
    }


# =========================================================
# MAIN SUBDOMAIN RECONNAISSANCE
# =========================================================

def run_subdomain_recon(
    domain: str,
    config_path: str,
) -> dict:
    """
    Perform passive Subfinder discovery.

    Every valid discovery is saved.
    Only explicitly authorized hosts are accepted.
    """

    # STEP 1: Normalize and validate target

    domain = normalize_hostname(domain)

    if not domain or not valid_domain(domain):
        raise ValueError("Invalid domain format.")

    # STEP 2: Load program configuration

    config = load_scope(config_path)

    # STEP 3: Verify authorization

    if not is_authorized(config):
        raise PermissionError(
            "BUGX: Program authorization is not confirmed."
        )

    # STEP 4: Verify starting domain using Scope Engine v2.0

    target_result = classify_target(domain, config)

    if target_result.get("status") != "in_scope":
        raise PermissionError(
            f"BUGX: Target {domain} is not explicitly in scope. "
            f"Reason: {target_result.get('reason', 'Scope not confirmed.')}"
        )

    # STEP 5: Check Subfinder installation

    subfinder_path = shutil.which("subfinder")

    if not subfinder_path:
        raise FileNotFoundError(
            "Subfinder not found. Check your system PATH."
        )

    # STEP 6: Run passive discovery

    try:
        result = subprocess.run(
            [
                subfinder_path,
                "-d",
                domain,
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Subfinder timed out after 180 seconds."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Subfinder execution failed."
        )

    # STEP 7: Normalize and deduplicate discoveries

    discovered = set()

    for line in result.stdout.splitlines():

        hostname = normalize_hostname(line.strip())

        if not hostname:
            continue

        if not valid_domain(hostname):
            continue

        discovered.add(hostname)

    all_subdomains = sorted(discovered)

    # STEP 8: Classify with Scope Engine v2.0

    classified = classify_subdomains(
        all_subdomains,
        config,
    )

    in_scope = classified["in_scope"]
    out_of_scope = classified["out_of_scope"]
    unverified = classified["unverified"]

    # STEP 9: Save all result categories

    saved = save_results(
        domain,
        all_subdomains,
        classified,
    )

    # STEP 10: Return results to CLI

    return {
        "domain": domain,

        "total_discovered": len(all_subdomains),
        "all_subdomains": all_subdomains,

        "accepted_total": len(in_scope),
        "accepted_hosts": in_scope,

        "out_of_scope_total": len(out_of_scope),
        "out_of_scope_hosts": out_of_scope,

        "unverified_total": len(unverified),
        "unverified_hosts": unverified,

        # Backward compatibility
        "total": len(in_scope),
        "subdomains": in_scope,
        "rejected_total": len(out_of_scope),
        "rejected_hosts": out_of_scope,

        **saved,
    }
