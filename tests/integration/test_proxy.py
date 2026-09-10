"""Integration tests for ProxyForwarder with mock upstream API."""

import os
from pathlib import Path

import httpx
import pytest

from secretshield.proxy.forwarder import ProxyForwarder
from secretshield.vault.cipher import VaultCipher
from secretshield.vault.store import InjectionType, VaultStore


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def cipher(master_key: bytes) -> VaultCipher:
    return VaultCipher(master_key)


@pytest.fixture
def store(tmp_path: Path, cipher: VaultCipher) -> VaultStore:
    return VaultStore(db_path=tmp_path / "vault.db", cipher=cipher)


@pytest.mark.asyncio
async def test_proxy_injects_credentials_to_mock_upstream(store: VaultStore):
    """Verify forwarder retrieves secret from vault and injects into upstream call."""
    captured_request = {}

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_request["headers"] = dict(request.headers)
        captured_request["url"] = str(request.url)
        captured_request["method"] = request.method
        return httpx.Response(
            status_code=200,
            json={"status": "charge_created", "id": "ch_123"},
            headers={"Content-Type": "application/json"},
        )

    # Configure profile in vault
    await store.set_profile(
        name="stripe-test",
        base_url="https://mock.stripe.internal",
        secret="mock_secret_key_prod_998877",
        injection_type=InjectionType.BEARER,
    )

    forwarder = ProxyForwarder(vault_store=store)
    # Patch forwarder._client transport with MockTransport
    forwarder._client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))

    try:
        # Downstream client call (Notice: no Authorization header sent by client!)
        inbound_headers = {
            "X-Service-Id": "checkout-service",
            "X-Service-Token": "client-temp-jwt",
            "Content-Type": "application/json",
        }

        status, _headers, stream, latency = await forwarder.forward(
            profile_name="stripe-test",
            path="v1/charges",
            method="POST",
            headers=inbound_headers,
            content=b'{"amount": 5000}',
        )

        assert status == 200
        assert latency >= 0

        # Read response stream
        body = b"".join([chunk async for chunk in stream])
        import json

        resp_data = json.loads(body)
        assert resp_data["status"] == "charge_created"
        assert resp_data["id"] == "ch_123"

        # Verify what the mock upstream received
        assert captured_request["method"] == "POST"
        assert captured_request["url"] == "https://mock.stripe.internal/v1/charges"
        assert captured_request["headers"]["authorization"] == "Bearer mock_secret_key_prod_998877"
        assert "x-service-id" not in captured_request["headers"]
        assert "x-service-token" not in captured_request["headers"]

    finally:
        await forwarder.aclose()


@pytest.mark.asyncio
async def test_proxy_returns_404_for_unknown_profile(store: VaultStore):
    """Verify forwarder raises 404 HTTPException when profile is missing."""
    from fastapi import HTTPException

    forwarder = ProxyForwarder(vault_store=store)
    try:
        with pytest.raises(HTTPException) as exc_info:
            await forwarder.forward(
                profile_name="non-existent",
                path="test",
                method="GET",
                headers={},
            )
        assert exc_info.value.status_code == 404
    finally:
        await forwarder.aclose()
