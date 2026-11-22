import pytest

from bugx.core.authorization import ScopeGate, Session
from bugx.core.exceptions import ConfigurationError, PolicyViolation, ScopeViolation
from bugx.core.policy import load_policy


def test_policy_defaults_when_missing(base_profile):
    policy = load_policy(base_profile, {"defaults": {"rate_limit": 3, "concurrency": 2}})
    assert (policy.rate_limit, policy.concurrency, policy.automated_scanning) == (3, 2, None)
    assert policy.header_list() == [] and not policy.requires_headers


def test_policy_headers_and_user_agent(base_profile):
    base_profile["policy"] = {
        "required_headers": {"X-HackerOne-Research": "idris4hack"},
        "user_agent": "Infomaniak-YWH-Bugbounty/tester",
        "rate_limit": 2,
        "automated_scanning": False,
    }
    policy = load_policy(base_profile)
    assert policy.header_list() == [
        "X-HackerOne-Research: idris4hack",
        "User-Agent: Infomaniak-YWH-Bugbounty/tester",
    ]
    assert policy.automated_scanning is False


@pytest.mark.parametrize(
    "bad",
    [
        {"required_headers": ["x"]},
        {"required_headers": {"A": "b\nInjected: 1"}},
        {"rate_limit": 0},
        {"rate_limit": "fast"},
        {"automated_scanning": "maybe"},
        {"user_agent": 5},
        "not-a-mapping",
    ],
)
def test_invalid_policy_rejected(base_profile, bad):
    base_profile["policy"] = bad
    with pytest.raises(ConfigurationError):
        load_policy(base_profile)


def test_session_requires_explicit_confirmation(base_profile):
    session = Session(profile=base_profile, profile_path="p", target="example.com")
    with pytest.raises(PolicyViolation):
        session.require_session_authorization()
    session.confirm_authorization()
    session.require_session_authorization()
    assert session.authorized_at


def test_gate_require_and_filter(base_profile):
    gate = ScopeGate(base_profile)
    assert gate.require("www.example.com")["allowed"]
    with pytest.raises(ScopeViolation) as info:
        gate.require("admin.example.com")
    assert info.value.status == "out_of_scope"
    allowed, blocked = gate.filter_allowed(["example.com", "evil.com", "example.com", "admin.example.com"])
    assert allowed == ["example.com"]
    assert {b["target"] for b in blocked} == {"evil.com", "admin.example.com"}


def test_gate_fails_closed_on_engine_error(base_profile, monkeypatch):
    from bugx.core import authorization

    def boom(*a, **k):
        raise RuntimeError("engine broke")

    monkeypatch.setattr(authorization, "can_test_target", boom)
    result = ScopeGate(base_profile).check("example.com")
    assert result["allowed"] is False and result["status"] == "error"


def test_gate_unauthorized_profile_blocks_everything(base_profile):
    base_profile["authorization"]["policy_reviewed"] = False
    assert ScopeGate(base_profile).is_allowed("example.com") is False


def test_redirect_revalidation(base_profile):
    gate = ScopeGate(base_profile)
    assert gate.validate_redirect("https://example.com/a", "/login")["allowed"] is True
    out = gate.validate_redirect("https://example.com/a", "https://evil.com/phish")
    assert out["allowed"] is False and out["url"] == "https://evil.com/phish"
    assert gate.validate_redirect("https://example.com/", "//admin.example.com/")["status"] == "out_of_scope"


def test_classify_many_dedups(base_profile):
    buckets = ScopeGate(base_profile).classify_many(["a.example.com", "a.example.com", "evil.com", "admin.example.com", ""])
    assert buckets == {"in_scope": ["a.example.com"], "out_of_scope": ["admin.example.com"], "unverified": ["evil.com"]}
