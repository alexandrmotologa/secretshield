"""Integration tests for FastAPI proxy application endpoints."""

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from secretshield.config import settings
from secretshield.server import app, state
from secretshield.vault.store import InjectionType


@pytest.fixture
def client(tmp_path: Path):
    """Test client fixture with clean test databases."""
    settings.data_dir = tmp_path
    with TestClient(app) as tc:
        yield tc


def test_health_check(client: TestClient):
    """Verify health endpoint responds with 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_admin_metrics(client: TestClient):
    """Verify metrics endpoint returns event list."""
    response = client.get("/admin/metrics")
    assert response.status_code == 200
    assert "recent_events" in response.json()


@pytest.mark.asyncio
async def test_end_to_end_proxy_with_redaction_and_audit(client: TestClient):
    """Verify complete proxy request cycle with credential injection and card redaction."""

    # 1. Setup mock upstream handler
    def mock_upstream(request: httpx.Request) -> httpx.Response:
        # Verify injected authorization
        assert request.headers.get("authorization") == "Bearer mock_prod_stripe_token_555"
        # Upstream returns a payload containing a valid credit card
        return httpx.Response(
            status_code=200,
            json={
                "status": "succeeded",
                "customer_card": "4532015112830366",
                "secret_key": "sk_test_1234567890abcdefghijklmnop",
            },
            headers={"Content-Type": "application/json"},
        )

    # 2. Add profile to vault store
    await state.vault_store.set_profile(
        name="stripe-test",
        base_url="https://mock.stripe.api",
        secret="mock_prod_stripe_token_555",
        injection_type=InjectionType.BEARER,
    )

    # 3. Issue service token for client
    service_token = state.authenticator.issue_service_token(service_id="payment-worker")

    # Patch forwarder client
    state.forwarder._client = httpx.AsyncClient(transport=httpx.MockTransport(mock_upstream))

    # 4. Make request to proxy
    resp = client.post(
        "/proxy/stripe-test/v1/charges",
        headers={
            "X-Service-Id": "payment-worker",
            "X-Service-Token": service_token,
        },
        json={"amount": 1000},
    )

    assert resp.status_code == 200
    data = resp.json()

    # 5. Verify response payload was REDACTED by SecretRedactor!
    assert data["status"] == "succeeded"
    assert data["customer_card"] == "[REDACTED_CARD_****0366]"
    assert data["secret_key"] == "[REDACTED_STRIPE_KEY]"
    assert "4532015112830366" not in resp.text
    assert "sk_test_" not in resp.text

    # 6. Verify audit entry was written
    recent_records = await state.audit_logger.get_recent_entries(limit=1)
    assert len(recent_records) == 1
    assert recent_records[0].service_id == "payment-worker"
    assert recent_records[0].profile_name == "stripe-test"
    assert recent_records[0].status_code == 200


def test_proxy_authentication_failure(client: TestClient):
    """Verify missing or invalid service token returns 401."""
    resp = client.get(
        "/proxy/stripe-test/v1/customers",
        headers={
            "X-Service-Id": "hacker-service",
            "X-Service-Token": "invalid.jwt.token",
        },
    )
    assert resp.status_code == 401
