"""Shared pytest fixtures for BUGX."""

from pathlib import Path

import pytest


@pytest.fixture
def base_profile() -> dict:
    """A valid new-format program profile used across tests."""
    return {
        "program": {
            "id": "example-hackerone",
            "name": "Example",
            "platform": "hackerone",
            "program_url": "https://example.com",
            "policy_url": "https://hackerone.com/example",
        },
        "authorization": {
            "user_confirmed": True,
            "policy_reviewed": True,
            "confirmation_date": "2026-11-21",
            "evidence_url": "https://hackerone.com/example",
        },
        "scope": {
            "assets": [
                {"type": "domain", "value": "example.com", "match": "exact", "eligible": True},
                {"type": "domain", "value": "*.example.com", "match": "wildcard", "eligible": True},
            ],
            "excluded_assets": [
                {"type": "domain", "value": "admin.example.com", "match": "exact"},
            ],
        },
    }


@pytest.fixture
def profile_file(tmp_path: Path, base_profile: dict) -> Path:
    import yaml

    path = tmp_path / "example.yaml"
    path.write_text(yaml.safe_dump(base_profile, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def settings() -> dict:
    from bugx.core.config import DEFAULT_SETTINGS
    import copy

    return copy.deepcopy(DEFAULT_SETTINGS)


@pytest.fixture
def session(base_profile, settings):
    from bugx.core.authorization import Session

    s = Session(profile=base_profile, profile_path="example.yaml", target="example.com",
                platform="hackerone", settings=settings)
    s.confirm_authorization()
    return s


@pytest.fixture
def results(tmp_path, monkeypatch):
    from bugx.core.results_manager import ResultsManager

    out = tmp_path / "output"
    monkeypatch.setenv("BUGX_OUTPUT_DIR", str(out))
    return ResultsManager(out)


@pytest.fixture
def ctx(session, settings, tmp_path):
    from bugx.core.adapters import RunContext

    def make(targets=None, policy=None, options=None):
        if policy is not None:
            from bugx.core.policy import load_policy

            session.profile["policy"] = policy
            session.policy = load_policy(session.profile, settings)
        work = tmp_path / "work"
        work.mkdir(exist_ok=True)
        return RunContext(session=session, targets=targets or ["example.com"], settings=settings,
                          work_dir=work, options=options or {})

    return make
