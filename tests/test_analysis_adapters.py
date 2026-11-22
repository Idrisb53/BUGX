"""Command construction, safety settings and parsing for the 10 analysis adapters."""

import json

import pytest

from bugx.modules.analysis.adapters.sqlmap import check_safe
from bugx.modules.analysis.adapters.wapiti import SAFE_MODULES
from bugx.modules.analysis.registry import ANALYSIS_ADAPTERS

A = {a.key: a for a in ANALYSIS_ADAPTERS}
H1 = {"required_headers": {"X-HackerOne-Research": "idris4hack"}, "rate_limit": 2, "concurrency": 2}


def test_registry_has_ten_unique_tools():
    assert [a.key for a in ANALYSIS_ADAPTERS] == [
        "nuclei", "zap", "nikto", "testssl", "dalfox", "sqlmap", "wapiti", "retire", "trivy", "semgrep"]


def test_network_scanners_are_intrusive():
    for key in ("nuclei", "zap", "nikto", "dalfox", "sqlmap", "wapiti"):
        assert A[key].intrusive is True
    for key in ("retire", "trivy", "semgrep"):
        assert A[key].sends_traffic is False and A[key].input_kind == "path"


def test_nuclei_safe_template_selection(ctx, settings):
    c = ctx(policy=H1)
    args = A["nuclei"].build_args(c, "https://example.com")
    assert "-ni" in args and "-duc" in args
    etags = args[args.index("-etags") + 1].split(",")
    assert {"dos", "fuzz", "intrusive", "bruteforce"} <= set(etags)
    assert args[args.index("-tags") + 1] == "exposure,misconfig,tech,ssl"
    settings["nuclei"]["tags"] = []
    settings["nuclei"]["templates"] = []
    assert A["nuclei"].config_status(settings)[0] is False
    row = {"template-id": "git-config", "matched-at": "https://example.com/.git/config",
           "info": {"name": "Git Config Exposure", "severity": "medium", "reference": ["https://x"]}}
    finding = A["nuclei"].parse(c, json.dumps(row), "", "https://example.com")[0]["finding"]
    assert finding["severity"] == "medium" and finding["url"].endswith(".git/config")


def test_zap_baseline_headers_and_report(ctx):
    c = ctx(policy=H1)
    args = A["zap"].build_args(c, "https://example.com")
    assert args[:2] == ["-t", "https://example.com"] and "-z" in args
    assert args[args.index("-J") + 1] == "zap_report.json"
    assert "replacer.full_list(0).matchstr=X-HackerOne-Research" in args[args.index("-z") + 1]
    A["zap"]._report(c).write_text(json.dumps({"site": [{"alerts": [{
        "name": "CSP Header Not Set", "riskdesc": "Medium (High)", "desc": "<p>No CSP</p>",
        "solution": "<p>Set CSP</p>", "instances": [{"uri": "https://example.com/", "method": "GET"}]}]}]}))
    finding = A["zap"].parse(c, "", "", "https://example.com")[0]["finding"]
    assert finding["severity"] == "Medium" and finding["description"] == "No CSP"


def test_nikto_excludes_dos_and_cannot_send_headers(ctx):
    c = ctx()
    args = A["nikto"].build_args(c, "https://example.com")
    assert args[args.index("-Tuning") + 1] == "x6"
    assert A["nikto"].supports_headers is False
    A["nikto"]._report(c).write_text(json.dumps([{"vulnerabilities": [{"id": "999", "method": "GET", "url": "/admin/", "msg": "Admin dir"}]}]))
    assert A["nikto"].parse(c, "", "", "https://example.com")[0]["asset"] == "https://example.com/admin/"


def test_testssl(ctx):
    c = ctx(policy=H1)
    args = A["testssl"].build_args(c, "https://example.com")
    assert args[-1] == "example.com:443" and "--reqheader" in args
    assert A["testssl"].build_args(c, "https://example.com:8443/")[-1] == "example.com:8443"
    A["testssl"]._report(c, "example.com").write_text(json.dumps([
        {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
        {"id": "TLS1_3", "severity": "OK", "finding": "offered"}]))
    items = A["testssl"].parse(c, "", "", "example.com")
    assert len(items) == 1 and items[0]["finding"]["category"] == "tls"


def test_dalfox_requires_params(ctx):
    c = ctx(policy=H1)
    with pytest.raises(ValueError):
        A["dalfox"].build_args(c, "https://example.com/")
    args = A["dalfox"].build_args(c, "https://example.com/s?q=1")
    assert "--skip-bav" in args and args[args.index("--delay") + 1] == "500"
    A["dalfox"]._report(c, "https://example.com/s?q=1").write_text(json.dumps(
        [{"type": "V", "data": "https://example.com/s?q=PAYLOAD", "param": "q", "payload": "<svg>", "method": "GET"}]))
    finding = A["dalfox"].parse(c, "", "", "https://example.com/s?q=1")[0]["finding"]
    assert finding["parameter"] == "q" and finding["confidence"] == "Medium"


def test_sqlmap_detection_only(ctx):
    c = ctx(policy={**H1, "user_agent": "UA"})
    with pytest.raises(ValueError):
        A["sqlmap"].build_args(c, "https://example.com/")
    args = A["sqlmap"].build_args(c, "https://example.com/item?id=1")
    assert {"--batch", "--level=1", "--risk=1", "--technique=BEU"} <= set(args)
    assert not any(a.split("=")[0] in ("--dump", "--dbs", "--os-shell", "--forms", "--crawl") for a in args)
    for bad in (["--dump"], ["--risk=3"], ["--level=5"], ["--os-shell"], ["--technique=BEUSTQ"], ["--file-read=/etc/passwd"]):
        with pytest.raises(ValueError):
            check_safe(bad)
    out = """
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
"""
    finding = A["sqlmap"].parse(c, out, "", "https://example.com/item?id=1")[0]["finding"]
    assert finding["parameter"] == "id" and finding["category"] == "sql_injection"


def test_wapiti_safe_module_set(ctx):
    modules = set(SAFE_MODULES.split(","))
    assert not modules & {"brute_login_form", "buster", "upload", "exec", "file", "permanentxss", "ssrf", "timesql", "shellshock", "log4shell"}
    c = ctx(policy=H1)
    args = A["wapiti"].build_args(c, "https://example.com/")
    assert args[args.index("-m") + 1] == SAFE_MODULES and args[args.index("--scope") + 1] == "folder"
    A["wapiti"]._report(c).write_text(json.dumps({"vulnerabilities": {"Reflected Cross Site Scripting": [
        {"method": "GET", "path": "/s?q=x", "info": "XSS in q", "level": 3, "parameter": "q"}]}}))
    finding = A["wapiti"].parse(c, "", "", "https://example.com/")[0]["finding"]
    assert finding["severity"] == "High" and finding["url"] == "https://example.com/s?q=x"


def test_retire_trivy_semgrep_local(ctx, tmp_path):
    c = ctx()
    with pytest.raises(ValueError):
        A["trivy"].build_args(c, str(tmp_path / "missing"))
    assert "--metrics=off" in A["semgrep"].build_args(c, str(tmp_path))
    A["retire"]._report(c).write_text(json.dumps({"data": [{"file": "/js/a.js", "results": [
        {"component": "jquery", "version": "1.8.0", "vulnerabilities": [{"severity": "medium", "identifiers": {"summary": "XSS"}, "info": ["https://x"]}]}]}]}))
    assert "jquery 1.8.0" in A["retire"].parse(c, "", "", str(tmp_path))[0]["finding"]["title"]
    A["trivy"]._report(c).write_text(json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-1", "PkgName": "flask", "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH"}]}]}))
    assert A["trivy"].parse(c, "", "", str(tmp_path))[0]["finding"]["severity"] == "HIGH"
    A["semgrep"]._report(c).write_text(json.dumps({"results": [{"check_id": "python.lang.sqli-format", "path": "app.py",
        "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "SQLi", "metadata": {"owasp": ["A03:2021"]}}}]}))
    finding = A["semgrep"].parse(c, "", "", str(tmp_path))[0]["finding"]
    assert finding["severity"] == "High" and finding["url"] == "app.py:3"
