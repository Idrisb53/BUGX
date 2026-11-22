"""Structured BUGX exceptions."""


class BugxError(Exception):
    """Base class for BUGX errors."""


class ConfigurationError(BugxError, ValueError):
    """Invalid profile, policy or settings."""


class ScopeViolation(BugxError, PermissionError):
    """A target failed the authorization/scope gate."""

    def __init__(self, target: str, status: str, reason: str):
        self.target = target
        self.status = status
        self.reason = reason
        super().__init__(f"{target}: {status} ({reason})")


class ToolUnavailable(BugxError):
    """An external tool is missing, misconfigured or unsupported on this OS."""


class PolicyViolation(BugxError, PermissionError):
    """An operation is not permitted by the program policy or session confirmations."""
