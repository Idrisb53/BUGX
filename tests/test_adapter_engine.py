"""Safety rules of the shared tool-adapter engine (all commands mocked)."""

import json

import pytest

from bugx.core import adapters as engine
from bugx.core.adapters import ToolAdapter, run_adapter
from bugx.core.runner import ToolResult, ToolRunner


class FakeAdapter(ToolAdapter):
    key = "fake"
    name = "Fake"
    module = "recon"
    purpose = "test"
    binaries = ("fake-tool",)
    input_kind = "host"
    install = {"any": "pip install fake"}

    def build_args(self, ctx, target):
        return ["-t", target, *ctx.header_args("-H")]

    def parse(self, ctx, stdout, stderr, target):
        return [json.loads(line) for line in stdout.splitlines() if line.strip()]


class FakeIntrusive(FakeAdapter):
    key = "fakescan"
    module = "vulnerability_analysis"
    intrusive = True


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(ToolAdapter, "resolve_executable", lambda self, settings=None: "/usr/bin/fake-tool")
    monkeypatch.setattr(ToolAdapter, "detect_version", lambda self, exe, timeout=20: ("1.2.3", "fake 1.2.3", None))


@pytest.fixture
def runner(monkeypatch):
    calls = []
    state = {"stdout": "", "returncode": 0, "error": None}

    def fake_run(tool, args, timeout=180, input_text=None, cwd=None):
        calls.append({"tool": tool, "args": list(args), "input": input_text, "timeout": timeout})
        return ToolResult(tool=tool, success=state["returncode"] == 0, returncode=state["returncode"],
                          stdout=state["stdout"], stderr="", error=state["error"], duration=0.5)

    monkeypatch.setattr(ToolRunner, "run", staticmethod(fake_run))
    return calls, state


def test_blocked_without_session_authorization(session, results, installed, runner):
    session.session_authorized = False
    record, path = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert record["status"] == "blocked" and not runner[0]
    assert path.exists()


def test_missing_tool_is_skipped_with_guidance(session, results, runner, monkeypatch):
    monkeypatch.setattr(ToolAdapter, "resolve_executable", lambda self, settings=None: None)
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert record["status"] == "skipped"
    assert "Missing" in record["errors"][0] and "pip install fake" in record["errors"][0]
    assert not runner[0]


def test_unsupported_os(session, results, runner, monkeypatch):
    monkeypatch.setattr(engine, "current_os", lambda: "windows")

    class LinuxOnly(FakeAdapter):
        supported_os = frozenset({"linux"})

    record, _ = run_adapter(LinuxOnly(), session, ["example.com"], results=results)
    assert record["status"] == "skipped" and "Unsupported OS" in record["errors"][0]


def test_tool_error_status(session, results, runner, monkeypatch):
    monkeypatch.setattr(ToolAdapter, "resolve_executable", lambda self, settings=None: "/usr/bin/amass")
    monkeypatch.setattr(ToolAdapter, "detect_version",
                        lambda self, exe, timeout=20: ("", "sudo: a password is required", "Tool wrapper requested sudo/interactive input."))
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert record["status"] == "skipped" and "Error" in record["errors"][0]


def test_out_of_scope_targets_never_executed(session, results, installed, runner):
    calls, _ = runner
    record, _ = run_adapter(FakeAdapter(), session, ["evil.com", "admin.example.com"], results=results)
    assert record["status"] == "blocked"
    assert not calls
    assert {b["target"] for b in record["blocked_targets"]} == {"evil.com", "admin.example.com"}


def test_mixed_targets_only_in_scope_run(session, results, installed, runner):
    calls, state = runner
    state["stdout"] = json.dumps({"type": "host", "asset": "new.example.com"}) + "\n" + json.dumps({"type": "host", "asset": "evil.org"})
    record, _ = run_adapter(FakeAdapter(), session, ["www.example.com", "evil.com"], results=results)
    assert [c["args"][1] for c in calls] == ["www.example.com"]
    assert record["status"] == "success"
    assert record["scope"]["in_scope"] == ["new.example.com"]
    assert record["scope"]["unverified"] == ["evil.org"]
    assert record["tool_version"] == "1.2.3"
    assert record["evidence"] and record["duration"] == 0.5


def test_results_are_deduplicated(session, results, installed, runner):
    _, state = runner
    line = json.dumps({"type": "host", "asset": "a.example.com"})
    state["stdout"] = "\n".join([line, line, line])
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert len(record["results"]) == 1


def test_headers_sent_and_redacted(session, results, installed, runner):
    calls, _ = runner
    session.profile["policy"] = {"required_headers": {"X-HackerOne-Research": "idris4hack"}}
    from bugx.core.policy import load_policy

    session.policy = load_policy(session.profile)
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert "X-HackerOne-Research: idris4hack" in calls[0]["args"]
    assert "X-HackerOne-Research: idris4hack" not in record["command"]
    assert "<header redacted>" in record["command"]


def test_tool_without_header_support_blocked_when_required(session, results, installed, runner):
    class NoHeaders(FakeAdapter):
        supports_headers = False

    session.profile["policy"] = {"user_agent": "Infomaniak-YWH-Bugbounty/x"}
    from bugx.core.policy import load_policy

    session.policy = load_policy(session.profile)
    record, _ = run_adapter(NoHeaders(), session, ["example.com"], results=results)
    assert record["status"] == "blocked" and not runner[0]


def test_intrusive_requires_confirmation(session, results, installed, runner):
    record, _ = run_adapter(FakeIntrusive(), session, ["example.com"], results=results)
    assert record["status"] == "blocked" and "not explicitly confirmed" in record["errors"][0]
    session.active_scanning_confirmed = True
    record, _ = run_adapter(FakeIntrusive(), session, ["example.com"], results=results)
    assert record["status"] == "success"


def test_intrusive_blocked_by_program_policy(session, results, installed, runner):
    session.profile["policy"] = {"automated_scanning": False}
    from bugx.core.policy import load_policy

    session.policy = load_policy(session.profile)
    session.active_scanning_confirmed = True
    record, _ = run_adapter(FakeIntrusive(), session, ["example.com"], results=results)
    assert record["status"] == "blocked" and "forbids" in record["errors"][0]
    assert not runner[0]


def test_timeout_and_failure_statuses(session, results, installed, runner):
    _, state = runner
    state["error"] = "fake timed out after 5 seconds."
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert record["status"] == "timeout"
    state["error"] = None
    state["returncode"] = 2
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert record["status"] == "failed" and "exited with code 2" in record["errors"][0]


def test_parser_crash_is_recorded(session, results, installed, runner):
    _, state = runner
    state["stdout"] = "{broken json"
    record, _ = run_adapter(FakeAdapter(), session, ["example.com"], results=results)
    assert any("parsing failed" in e for e in record["errors"])


def test_findings_stored_as_needs_review(session, results, installed, runner):
    _, state = runner
    state["stdout"] = json.dumps({"type": "finding", "asset": "https://example.com/x",
                                  "finding": {"title": "Exposed .git", "severity": "high", "validation_status": "Validated"}})
    session.active_scanning_confirmed = True
    record, _ = run_adapter(FakeIntrusive(), session, ["example.com"], results=results)
    findings = results.load_findings(session.program_id)
    assert len(findings) == 1 and record["findings"] == [findings[0].finding_id]
    assert findings[0].validation_status == "Needs Review"  # scanner can never self-validate
    assert findings[0].scope_status == "in_scope"


def test_stdin_closed_by_default(monkeypatch):
    import subprocess

    from bugx.core import runner as runner_module

    seen = {}
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: "/bin/x")

    def fake(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner_module.subprocess, "run", fake)
    ToolRunner.run("x", [])
    assert seen["stdin"] is subprocess.DEVNULL and "input" not in seen
    ToolRunner.run("x", [], input_text="a\n")
    assert seen["input"] == "a\n"
