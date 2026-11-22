"""End-to-end CLI workflow tests (Typer CliRunner, isolated config/output)."""

import pytest
import yaml
from typer.testing import CliRunner

from bugx import cli
from bugx.core import config, profile_creator, program_manager
from bugx.core.adapters import STATUS_MISSING, ToolAdapter, ToolStatus

runner = CliRunner()
ENV = {"COLUMNS": "200"}


@pytest.fixture
def workspace(tmp_path, monkeypatch, base_profile):
    programs = tmp_path / "config" / "programs"
    (programs / "hackerone").mkdir(parents=True)
    (programs / "hackerone" / "example.yaml").write_text(yaml.safe_dump(base_profile, sort_keys=False))
    for module in (program_manager, profile_creator, config):
        monkeypatch.setattr(module, "PROGRAMS_DIR", programs)
    monkeypatch.setenv("BUGX_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(ToolAdapter, "status", lambda self, settings=None, check_version=True: ToolStatus(
        key=self.key, name=self.name, module=self.module, status=STATUS_MISSING, message="Not found in PATH.",
        install_hint=self.install_hint()))
    monkeypatch.setattr(cli, "ACTIVE_SESSION", None)
    from bugx.integrations.playwright import browser

    monkeypatch.setattr(browser, "availability", lambda settings: {
        "available": False, "missing": ["npx (test stub)"], "browser": None, "launcher_command": "npx", "mcp_sdk": False, "launcher": False})
    return tmp_path


def run(inputs, args=()):
    return runner.invoke(cli.app, list(args), input="\n".join(inputs) + "\n", env=ENV)


def test_existing_profile_full_startup(workspace):
    result = run(["1", "1", "1", "YES", "", "7", "", "0"])
    assert result.exit_code == 0, result.output
    out = result.output
    for text in ("SELECT YOUR BUG BOUNTY PLATFORM", "PROGRAM CONFIGURATION", "PROGRAM SCOPE",
                 "AUTHORIZATION CONFIRMATION", "BUGX SESSION READY", "BUGX CONTROL CENTER", "ABOUT BUGX",
                 "Thank you for using BUGX"):
        assert text in out, text
    assert "admin.example.com" in out and "EXCLUDED" in out


def test_all_five_platforms_offered(workspace):
    result = run(["9", "4", "1", "2"])  # invalid, then YesWeHack; no saved profile -> creator
    out = result.output
    for name in ("HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "Custom"):
        assert name in out
    assert "Invalid choice. Select 1 to 5." in out
    assert "No saved profiles for this platform" in out


def test_create_new_profile(workspace):
    inputs = [
        "1", "2",
        "Deriv", "https://deriv.com", "https://hackerone.com/deriv", "deriv.com",
        "YES", "YES",
        "YES", "", "0",
    ]
    result = run(inputs)
    assert result.exit_code == 0, result.output
    created = workspace / "config" / "programs" / "hackerone" / "deriv.yaml"
    profile = yaml.safe_load(created.read_text())
    assert [a["value"] for a in profile["scope"]["assets"]] == ["deriv.com"]
    assert profile["scope"]["excluded_assets"] == []
    assert "Additional in-scope assets" not in result.output
    assert "Excluded / out-of-scope assets" not in result.output
    assert "policy" not in profile
    assert "PROGRAM REQUEST RULES" not in result.output
    assert "POLICY REVIEW" in result.output


def test_policy_not_reviewed_cancels(workspace):
    inputs = ["1", "2", "X", "https://x.com", "https://h1.com/x", "x.com", "no"]
    result = run(inputs)
    assert result.exit_code == 1 and "Policy review not confirmed" in result.output


def test_session_authorization_required(workspace):
    result = run(["1", "1", "1", "no"])
    assert result.exit_code == 1 and "Authorization not confirmed. BUGX stopped." in result.output


def test_out_of_scope_target_blocked(workspace):
    result = run(["1", "1", "1", "YES", "evil.com", "admin.example.com", "https://evil.com/x"])
    assert result.exit_code == 1
    assert result.output.count("Target blocked") == 3
    assert "No authorized target selected" in result.output


def test_all_modules_reachable_and_report(workspace):
    inputs = ["1", "1", "1", "YES", "www.example.com",
              "1", "1", "", "0",          # recon: subfinder missing -> guidance, back
              "2", "13", "", "0",         # enumeration: browser option (mcp may be missing), back
              "3", "0",                   # analysis menu
              "4",                        # validation: no findings -> returns
              "5", "1", "", "3", "", "0", # report: generate, history, back
              "0"]
    result = run(inputs)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "BUGX RECONNAISSANCE MODULE" in out and "Subfinder" in out and "Cloudlist" in out
    assert "MISSING" in out and "Install:" in out
    assert "BUGX ENUMERATION MODULE" in out and "GoWitness" in out
    assert "PLAYWRIGHT MCP NOT AVAILABLE" in out
    assert "BUGX VULNERABILITY ANALYSIS MODULE" in out and "SQLmap" in out
    assert "No findings recorded yet" in out
    assert "REPORT FILES" in out and "SCAN HISTORY" in out
    reports = list((workspace / "output" / "reports" / "example-hackerone").glob("bugx_report_*.md"))
    assert reports and "No vulnerabilities were identified" in reports[0].read_text()


def test_noninteractive_commands(workspace, base_profile):
    profile = str(workspace / "config" / "programs" / "hackerone" / "example.yaml")
    assert runner.invoke(cli.app, ["version"], env=ENV).output.strip().startswith("BUGX v")
    listed = runner.invoke(cli.app, ["programs"], env=ENV)
    assert "example-hackerone" in listed.output
    ok = runner.invoke(cli.app, ["scope-check", "www.example.com", profile], env=ENV)
    assert ok.exit_code == 0 and "SCOPE CHECK PASSED" in ok.output
    blocked = runner.invoke(cli.app, ["scope-check", "admin.example.com", profile], env=ENV)
    assert blocked.exit_code == 1 and "out_of_scope" in blocked.output
    hist = runner.invoke(cli.app, ["history", profile], env=ENV)
    assert hist.exit_code == 0 and "No saved scans" in hist.output
    rep = runner.invoke(cli.app, ["report", profile, "--formats", "json,markdown"], env=ENV)
    assert rep.exit_code == 0 and "JSON" in rep.output
    bad = runner.invoke(cli.app, ["report", profile, "--formats", "docx"], env=ENV)
    assert bad.exit_code == 1


def test_recon_command_fails_with_nonzero_exit(workspace, monkeypatch):
    from bugx.modules.recon import subdomains

    monkeypatch.setattr(subdomains.shutil, "which", lambda name: None)
    profile = str(workspace / "config" / "programs" / "hackerone" / "example.yaml")
    result = runner.invoke(cli.app, ["recon", "example.com", profile], env=ENV)
    assert result.exit_code == 1 and "Subfinder not found" in result.output


def test_doctor_runs(workspace):
    result = runner.invoke(cli.app, ["doctor"], env=ENV)
    assert result.exit_code == 0
    for text in ("SYSTEM", "CONFIGURATION", "BROWSER / PLAYWRIGHT MCP", "TOOL INVENTORY", "SYSTEM SUMMARY", "Nuclei"):
        assert text in result.output


def test_execute_recon_without_session_is_fail_closed(workspace, capsys):
    cli.execute_recon_technique("4", "example.com", "x.yaml", session=None)
    assert "No authorized session" in capsys.readouterr().out
