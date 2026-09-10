"""Unit tests for TokenAuthenticator."""

import pytest

from secretshield.policy.authenticator import AuthenticationError, TokenAuthenticator


@pytest.fixture
def auth() -> TokenAuthenticator:
    return TokenAuthenticator(
        jwt_secret="super-secret-test-jwt-key-for-unit-tests-12345",
        static_service_keys={"billing-cron": "static_cron_secret_token_123"},
        default_token_ttl_seconds=60,
    )


def test_issue_and_verify_jwt_token(auth: TokenAuthenticator):
    """Verify issued token can be authenticated and extracts caller identity."""
    token = auth.issue_service_token(service_id="order-engine", scopes=["read", "write"])
    identity = auth.authenticate(service_id="order-engine", token=token)

    assert identity.service_id == "order-engine"
    assert identity.scopes == ["read", "write"]


def test_authenticate_bearer_prefix_stripped(auth: TokenAuthenticator):
    """Verify Bearer prefix in token header is correctly handled."""
    token = auth.issue_service_token(service_id="checkout-app")
    identity = auth.authenticate(service_id=None, token=f"Bearer {token}")
    assert identity.service_id == "checkout-app"


def test_authenticate_static_service_key(auth: TokenAuthenticator):
    """Verify pre-shared static key authentication succeeds."""
    identity = auth.authenticate(
        service_id="billing-cron",
        token="static_cron_secret_token_123",
    )
    assert identity.service_id == "billing-cron"
    assert identity.scopes == ["*"]


def test_service_id_mismatch_fails(auth: TokenAuthenticator):
    """Verify token issued to service A cannot be claimed by service B."""
    token = auth.issue_service_token(service_id="order-service")

    with pytest.raises(AuthenticationError, match="Service ID mismatch"):
        auth.authenticate(service_id="attacker-service", token=token)


def test_missing_token_fails(auth: TokenAuthenticator):
    """Verify missing token raises AuthenticationError."""
    with pytest.raises(AuthenticationError, match="Missing service authentication token"):
        auth.authenticate(service_id="order-service", token=None)


def test_expired_token_fails(auth: TokenAuthenticator):
    """Verify expired token is rejected."""
    token = auth.issue_service_token(service_id="test-exp", ttl_seconds=-10)

    with pytest.raises(AuthenticationError, match="expired"):
        auth.authenticate(service_id="test-exp", token=token)
