"""Tests for the existing passive Subfinder module (mocked subprocess)."""

import subprocess

import pytest

from bugx.modules.recon import subdomains


@pytest.fixture
def fake_subfinder(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subdomains.shutil, "which", lambda name: "/usr/bin/subfinder")

    def fake_run(cmd, **kwargs):
        assert kwargs.get("shell") in (None, False)
        out = "example.com\nwww.example.com\nadmin.example.com\nevil.com\nnot_valid\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(subdomains.subprocess, "run", fake_run)
    return tmp_path


def test_recon_classifies_and_saves(fake_subfinder, profile_file, monkeypatch):
    monkeypatch.setenv("BUGX_OUTPUT_DIR", str(fake_subfinder / "output"))
    result = subdomains.run_subdomain_recon("example.com", str(profile_file))
    assert result["accepted_hosts"] == ["example.com", "www.example.com"]
    assert result["out_of_scope_hosts"] == ["admin.example.com"]
    assert result["unverified_hosts"] == ["evil.com"]
    saved = (fake_subfinder / "output/recon/example_com/in_scope.txt").read_text()
    assert saved.splitlines() == ["example.com", "www.example.com"]


def test_recon_blocks_out_of_scope_start(fake_subfinder, profile_file):
    with pytest.raises(PermissionError):
        subdomains.run_subdomain_recon("evil.com", str(profile_file))


def test_recon_missing_tool(monkeypatch, profile_file):
    monkeypatch.setattr(subdomains.shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError):
        subdomains.run_subdomain_recon("example.com", str(profile_file))
