"""Regression baseline: the 11 original cases from test_scope_engine.py.

These expectations are copied verbatim from the original script and must
never be changed to make new code pass.
"""

import pytest

from bugx.core.scope import classify_target

CONFIG = {
    "authorization": {"user_confirmed": True, "policy_reviewed": True},
    "scope": {
        "assets": [
            {"type": "domain", "value": "example.com", "match": "exact", "eligible": True},
            {"type": "domain", "value": "*.wild.example.com", "match": "wildcard", "eligible": True},
            {"type": "url", "value": "https://api.example.com/v1/*", "match": "exact", "eligible": True},
        ],
        "excluded_assets": [
            {"type": "domain", "value": "admin.example.com", "match": "exact"},
            {"type": "url", "value": "https://api.example.com/v1/private/*", "match": "exact"},
        ],
    },
}

CASES = [
    ("example.com", "in_scope"),
    ("www.example.com", "unverified"),
    ("admin.example.com", "out_of_scope"),
    ("api.wild.example.com", "in_scope"),
    ("wild.example.com", "unverified"),
    ("api.example.com", "unverified"),
    ("https://api.example.com/v1/users", "in_scope"),
    ("https://api.example.com/v1/private/data", "out_of_scope"),
    ("https://api.example.com/v2/users", "unverified"),
    ("http://api.example.com/v1/users", "unverified"),
    ("https://evil-example.com/v1/users", "unverified"),
]


@pytest.mark.parametrize(("target", "expected"), CASES)
def test_original_scope_cases(target, expected):
    assert classify_target(target, CONFIG)["status"] == expected
