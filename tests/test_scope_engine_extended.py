"""Additional scope-engine behaviour checks (existing behaviour, not new rules)."""

import pytest

from bugx.core.scope import (
    can_test_target,
    classify_target,
    is_authorized,
    is_in_scope,
    normalize_hostname,
    normalize_path,
)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("EXAMPLE.COM", "in_scope"),
        ("example.com.", "in_scope"),
        ("https://example.com@evil.com", "unverified"),
        ("https://evil.com/?x=example.com", "unverified"),
        ("example.com.evil.com", "unverified"),
        ("10.0.0.1", "unverified"),
        ("https://example.com:99999/", "unverified"),
        ("api.example.com", "in_scope"),
        ("admin.example.com", "out_of_scope"),
        ("", "unverified"),
        ("ftp://example.com", "unverified"),
        ("https://example.com/%2e%2e/admin", "unverified"),
    ],
)
def test_classification_edge_cases(base_profile, target, expected):
    assert classify_target(target, base_profile)["status"] == expected


def test_exclusion_beats_wildcard(base_profile):
    assert not is_in_scope("admin.example.com", base_profile)


def test_unauthorized_profile_is_blocked(base_profile):
    base_profile["authorization"]["user_confirmed"] = False
    result = can_test_target("example.com", base_profile)
    assert result == {
        "allowed": False,
        "status": "unauthorized",
        "reason": "Program authorization is not confirmed",
    }


def test_policy_not_reviewed_is_blocked(base_profile):
    base_profile["authorization"]["policy_reviewed"] = False
    assert can_test_target("example.com", base_profile)["allowed"] is False


def test_in_scope_target_allowed(base_profile):
    assert can_test_target("https://www.example.com/login", base_profile)["allowed"] is True


def test_legacy_authorization_format():
    assert is_authorized({"authorization": {"authorized": True}}) is True
    assert is_authorized({"authorization": {"authorized": "yes"}}) is False
    assert is_authorized(None) is False


def test_legacy_scope_format():
    cfg = {
        "authorization": {"authorized": True},
        "scope": {"allowed_domains": ["flipkart.com"], "excluded_domains": ["flipkart.net"]},
    }
    assert classify_target("flipkart.com", cfg)["status"] == "in_scope"
    assert classify_target("www.flipkart.com", cfg)["status"] == "unverified"
    assert classify_target("flipkart.net", cfg)["status"] == "out_of_scope"


def test_invalid_config_fails_closed():
    assert classify_target("example.com", "not-a-dict")["status"] == "unverified"
    assert classify_target("example.com", {"scope": []})["status"] == "unverified"
    assert classify_target("example.com", {"scope": {"assets": "x"}})["status"] == "unverified"


def test_normalizers():
    assert normalize_hostname("*.Example.COM") == "*.example.com"
    assert normalize_hostname("example.com:443") == "example.com"
    assert normalize_hostname("a..b") is None
    assert normalize_path("/a/%2e%2e/b") is None
    assert normalize_path("/a/%2f") == "/a/%2F"
