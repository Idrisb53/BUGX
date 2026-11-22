import subprocess

from bugx.core import runner
from bugx.core.runner import ToolRunner
from bugx.core.tool_manager import ToolManager


def test_missing_tool_reports_error(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    result = ToolRunner.run("definitely-not-installed", ["-h"])
    assert result.success is False
    assert "not installed" in result.error


def test_timeout_is_handled(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/bin/fake")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="fake", timeout=1)

    monkeypatch.setattr(runner.subprocess, "run", boom)
    result = ToolRunner.run("fake", [], timeout=1)
    assert result.success is False
    assert "timed out" in result.error


def test_runner_never_uses_shell(monkeypatch):
    seen = {}
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/bin/fake")

    def fake_run(cmd, **kwargs):
        seen.update(kwargs, cmd=cmd)
        return subprocess.CompletedProcess(cmd, 0, "ok", "")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert ToolRunner.run("fake", ["a; rm -rf /"]).success
    assert seen["shell"] is False
    assert seen["cmd"] == ["/bin/fake", "a; rm -rf /"]


def test_tool_manager_detection(monkeypatch):
    from bugx.core import tool_manager

    monkeypatch.setattr(
        tool_manager.ToolRunner, "get_path",
        staticmethod(lambda c: "/usr/bin/nmap" if c == "nmap" else None),
    )
    manager = ToolManager()
    nmap = manager.get_tool("Nmap")
    assert nmap.installed and nmap.executable == "/usr/bin/nmap"
    summary = manager.summary()
    assert summary["installed"] == 1
    assert summary["external"] == len(manager.get_external())
