import json

import pytest

from bugx.core.findings import Finding, categorize, normalize_severity
from bugx.core.results_manager import ScanRecord, update_finding_fields


def _finding(**kw):
    data = dict(title="Reflected XSS in q", severity="high", url="https://example.com/s?q=1", source_tool="dalfox", parameter="q")
    data.update(kw)
    return Finding(**data)


def test_severity_and_category_normalisation():
    assert normalize_severity("CRITICAL") == "Critical"
    assert normalize_severity("info") == "Informational"
    assert normalize_severity("bogus") == "Informational"
    assert categorize("Missing HSTS header") in ("tls", "misconfiguration")
    assert categorize("SQL injection in id") == "sql_injection"


def test_finding_mapping_and_defaults():
    finding = _finding()
    assert finding.severity == "High"
    assert finding.category == "xss"
    assert finding.owasp.startswith("A03:2021")
    assert finding.validation_status == "Needs Review"
    assert finding.finding_id.startswith("BUGX-")


def test_cvss_requires_vector():
    assert _finding(cvss_score=9.8).cvss_score is None
    assert _finding(cvss_score=6.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").cvss_score == 6.1


def test_scan_files_never_overwrite(results):
    record = ScanRecord(program_id="p1", platform="hackerone", target="example.com", module="recon", tool="subfinder")
    first = results.save_scan(record)
    second = results.save_scan(record)
    assert first != second and first.exists() and second.exists()
    assert results.load_scan(first)["scan_id"] == record.scan_id


def test_list_scans_and_in_scope_assets(results):
    for tool, assets in (("subfinder", ["a.example.com"]), ("httpx", ["https://a.example.com"])):
        record = ScanRecord(program_id="p1", platform="h1", target="example.com", module="recon", tool=tool, status="success")
        record.scope = {"in_scope": assets, "out_of_scope": [], "unverified": ["evil.com"]}
        results.save_scan(record)
    (results.root / "recon" / "p1" / "garbage.json").write_text("{not json")
    scans = results.list_scans("p1")
    assert {s["tool"] for s in scans} == {"subfinder", "httpx"}
    assert results.in_scope_assets("p1") == ["a.example.com", "https://a.example.com"]


def test_unknown_module_rejected(results):
    with pytest.raises(ValueError):
        results.module_dir("../etc", "p1")


def test_findings_dedup_and_status_history(results):
    ids = results.upsert_findings("p1", [_finding(), _finding(evidence=["e2"])])
    assert ids[0] == ids[1]
    assert len(results.load_findings("p1")) == 1
    updated = results.update_finding_status("p1", ids[0], "Validated", note="reproduced", evidence=["shot.png"])
    assert updated.validation_status == "Validated"
    assert updated.validation_history[-1]["from"] == "Needs Review"
    # re-running the scanner must not reset a validated finding
    results.upsert_findings("p1", [_finding()])
    assert results.get_finding("p1", ids[0]).validation_status == "Validated"
    records = list((results.root / "validation" / "p1").glob("*.json"))
    assert len(records) == 1 and json.loads(records[0].read_text())["to"] == "Validated"


def test_invalid_status_and_missing_finding(results):
    results.upsert_findings("p1", [_finding()])
    with pytest.raises(ValueError):
        results.update_finding_status("p1", _finding().finding_id, "Confirmed!!")
    with pytest.raises(KeyError):
        results.update_finding_status("p1", "BUGX-NOPE", "Potential")


def test_update_fields_validation(results):
    fid = results.upsert_findings("p1", [_finding()])[0]
    with pytest.raises(ValueError):
        update_finding_fields(results, "p1", fid, cvss_score=7.0)
    with pytest.raises(ValueError):
        update_finding_fields(results, "p1", fid, validation_status="Validated")
    f = update_finding_fields(results, "p1", fid, cvss_score=6.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                              reproduction_steps=["open url"])
    assert f.cvss_score == 6.1 and f.reproduction_steps == ["open url"]
