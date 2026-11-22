import pytest

from bugx.core import profile_creator as pc
from bugx.core.program_manager import load_program_profile_from_path


@pytest.fixture
def programs_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(pc, "PROGRAMS_DIR", tmp_path)
    return tmp_path


def _create(**overrides):
    args = dict(
        program_name="Deriv",
        target_url="https://deriv.com",
        policy_url="https://hackerone.com/deriv",
        asset_value="deriv.com",
        platform_key="hackerone",
        policy_reviewed=True,
        user_confirmed=True,
    )
    args.update(overrides)
    return pc.create_program_profile(**args)


def test_creates_valid_profile(programs_dir):
    path = _create()
    assert path == programs_dir / "hackerone" / "deriv.yaml"
    cfg = load_program_profile_from_path(str(path))
    assert cfg["scope"]["assets"][0] == {
        "type": "domain", "value": "deriv.com", "match": "exact", "eligible": True,
    }


def test_never_overwrites(programs_dir):
    first = _create()
    second = _create()
    assert first.name == "deriv.yaml"
    assert second.name == "deriv-2.yaml"
    assert load_program_profile_from_path(str(second))["program"]["id"] == "deriv-hackerone-2"


def test_wildcard_asset(programs_dir):
    cfg = load_program_profile_from_path(str(_create(asset_value="*.deriv.com")))
    assert cfg["scope"]["assets"][0]["match"] == "wildcard"


@pytest.mark.parametrize(
    "overrides",
    [
        {"platform_key": "myspace"},
        {"program_name": "   "},
        {"target_url": "deriv.com"},
        {"policy_url": "ftp://x"},
        {"asset_value": "not a host"},
        {"asset_value": "deriv.com:8080"},
    ],
)
def test_rejects_invalid_input(programs_dir, overrides):
    with pytest.raises(ValueError):
        _create(**overrides)


def test_requires_confirmation(programs_dir):
    with pytest.raises(PermissionError):
        _create(user_confirmed=False)
