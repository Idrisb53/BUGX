import pytest
import yaml

from bugx.core import program_manager as pm


def test_load_valid_profile(profile_file):
    cfg = pm.load_program_profile_from_path(str(profile_file))
    assert cfg["program"]["id"] == "example-hackerone"


def test_missing_profile_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        pm.load_program_profile_from_path(str(tmp_path / "nope.yaml"))


def test_invalid_yaml_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("program: [unclosed", encoding="utf-8")
    with pytest.raises(ValueError):
        pm.load_program_profile_from_path(str(path))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda c: c.pop("program"), "program section"),
        (lambda c: c["program"].update(platform="myspace"), "Unsupported"),
        (lambda c: c["authorization"].update(user_confirmed=False), "authorization"),
        (lambda c: c["authorization"].update(policy_reviewed=False), "policy review"),
        (lambda c: c["scope"].update(assets=[]), "No scope assets"),
        (lambda c: c["scope"]["assets"][0].update(match="regex"), "exact or wildcard"),
    ],
)
def test_validation_rejects(base_profile, mutate, message):
    mutate(base_profile)
    with pytest.raises(ValueError, match=message):
        pm.validate_program_profile(base_profile)


def test_list_and_find_programs(tmp_path, base_profile, monkeypatch):
    platform_dir = tmp_path / "hackerone"
    platform_dir.mkdir()
    (platform_dir / "example.yaml").write_text(yaml.safe_dump(base_profile), encoding="utf-8")
    monkeypatch.setattr(pm, "PROGRAMS_DIR", tmp_path)

    listed = pm.list_programs()
    assert [p["id"] for p in listed] == ["example-hackerone"]
    assert pm.load_program_profile("example-hackerone")["program"]["name"] == "Example"
    with pytest.raises(FileNotFoundError):
        pm.load_program_profile("missing")
