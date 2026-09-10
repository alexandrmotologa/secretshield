"""Integration tests for Transparent Forward Proxy (HTTP_PROXY mode)."""

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from secretshield.config import settings
from secretshield.server import app, state
from secretshield.vault.store import InjectionType


@pytest.fixture
def client(tmp_path: Path):
    settings.data_dir = tmp_path
    with TestClient(app) as tc:
        yield tc


@pytest.mark.asyncio
async def test_transparent_proxy_by_host_header(client: TestClient):
    """Verify standard HTTP client with Host: api.stripe.com is resolved transparently."""
    captured = {}

    def mock_stripe(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"status": "paid"})

    # Setup profile with domain api.stripe.com
    await state.vault_store.set_profile(
        name="stripe-prod",
        base_url="https://api.stripe.com",
        secret="sec_test_stripe_transparent_999",
        domains=["api.stripe.com"],
        injection_type=InjectionType.BEARER,
    )

    state.forwarder._client = httpx.AsyncClient(transport=httpx.MockTransport(mock_stripe))

    # Send request mimicking a transparent forward proxy call
    resp = client.post(
        "/v1/charges",
        headers={
            "Host": "api.stripe.com",
            "Content-Type": "application/json",
            "X-Service-Id": "billing-app",
        },
        json={"amount": 4200},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "paid"
    assert captured["auth"] == "Bearer sec_test_stripe_transparent_999"
    assert captured["url"] == "https://api.stripe.com/v1/charges"


@pytest.mark.asyncio
async def test_transparent_proxy_unknown_host_returns_404(client: TestClient):
    """Verify unknown host returns 404 with helpful message."""
    resp = client.get(
        "/v1/unknown",
        headers={"Host": "unconfigured.api.com"},
    )
    assert resp.status_code == 404
    assert "no profile matching Host" in resp.json()["detail"]
