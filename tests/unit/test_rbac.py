"""Unit tests for RBAC PolicyEngine."""

import pytest

from secretshield.policy.authenticator import CallerIdentity
from secretshield.policy.rbac import PermissionDeniedError, PolicyEngine, PolicyRule


@pytest.fixture
def rbac() -> PolicyEngine:
    engine = PolicyEngine(default_deny=True)
    engine.set_rule(
        PolicyRule(
            service_id="payment-service",
            allowed_profiles=["stripe*", "paypal"],
            denied_profiles=["stripe-admin"],
            allowed_methods=["GET", "POST"],
            allowed_paths=["/v1/charges*", "/v1/refunds"],
            denied_paths=["/v1/charges/dangerous-op"],
        )
    )
    return engine


def test_allowed_request_passes(rbac: PolicyEngine):
    """Verify allowed profile, method, and path succeeds."""
    allowed, reason = rbac.is_allowed(
        service_id="payment-service",
        profile_name="stripe-prod",
        method="POST",
        path="/v1/charges",
    )
    assert allowed is True
    assert reason == "Authorized"


def test_denied_profile_fails(rbac: PolicyEngine):
    """Verify calling an unlisted profile fails."""
    allowed, reason = rbac.is_allowed(
        service_id="payment-service",
        profile_name="openai",
        method="POST",
        path="/v1/chat/completions",
    )
    assert allowed is False
    assert "not in allowed list" in reason


def test_explicitly_denied_profile_fails(rbac: PolicyEngine):
    """Verify explicit deny overrides wildcard allow."""
    allowed, reason = rbac.is_allowed(
        service_id="payment-service",
        profile_name="stripe-admin",
        method="POST",
        path="/v1/charges",
    )
    assert allowed is False
    assert "explicitly denied" in reason


def test_denied_method_fails(rbac: PolicyEngine):
    """Verify unallowed HTTP method (DELETE) fails."""
    allowed, reason = rbac.is_allowed(
        service_id="payment-service",
        profile_name="stripe-prod",
        method="DELETE",
        path="/v1/charges/123",
    )
    assert allowed is False
    assert "Method 'DELETE' is not in allowed list" in reason


def test_denied_path_fails(rbac: PolicyEngine):
    """Verify explicitly denied subpath fails."""
    allowed, reason = rbac.is_allowed(
        service_id="payment-service",
        profile_name="stripe-prod",
        method="POST",
        path="/v1/charges/dangerous-op",
    )
    assert allowed is False
    assert "explicitly denied" in reason


def test_enforce_raises_permission_denied(rbac: PolicyEngine):
    """Verify enforce method raises PermissionDeniedError."""
    caller = CallerIdentity(service_id="payment-service")
    with pytest.raises(PermissionDeniedError, match="Access denied"):
        rbac.enforce(
            caller=caller,
            profile_name="openai",
            method="POST",
            path="/v1/chat",
        )


def test_unknown_service_default_deny(rbac: PolicyEngine):
    """Verify unknown service without rules is blocked by default."""
    allowed, reason = rbac.is_allowed(
        service_id="unknown-hacker",
        profile_name="stripe-prod",
        method="GET",
        path="/v1/charges",
    )
    assert allowed is False
    assert "No policy rule defined" in reason
