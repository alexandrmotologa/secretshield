"""Integration tests for SecretShieldClient helper shim."""

import httpx
import pytest

from secretshield.client.shim import SecretShieldClient


@pytest.mark.asyncio
async def test_client_shim_sends_service_headers():
    """Verify SecretShieldClient attaches service credentials and formats target url."""
    captured = {}

    def mock_transport(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["headers"] = dict(request.headers)
        return httpx.Response(status_code=200, json={"ok": True})

    client = SecretShieldClient(
        proxy_url="http://mock-shield:8000",
        service_id="checkout-worker",
        service_token="test-jwt-token-999",
    )
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))

    try:
        resp = await client.post(
            profile="stripe",
            path="v1/charges",
            json={"amount": 500},
        )
        assert resp.status_code == 200
        assert captured["url"] == "http://mock-shield:8000/proxy/stripe/v1/charges"
        assert captured["method"] == "POST"
        assert captured["headers"]["x-service-id"] == "checkout-worker"
        assert captured["headers"]["x-service-token"] == "test-jwt-token-999"

        # Context manager test
        async with client as c:
            r2 = await c.get(profile="stripe", path="v1/charges/ch_1")
            assert r2.status_code == 200
            assert captured["url"] == "http://mock-shield:8000/proxy/stripe/v1/charges/ch_1"
            assert captured["method"] == "GET"

    finally:
        await client.aclose()
