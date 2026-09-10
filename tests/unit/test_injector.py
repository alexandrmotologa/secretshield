"""Unit tests for CredentialInjector."""

from secretshield.proxy.injector import CredentialInjector
from secretshield.vault.store import CredentialProfile, InjectionType


def make_test_profile(
    injection_type: InjectionType, header_name="Authorization", prefix="Bearer "
) -> CredentialProfile:
    return CredentialProfile(
        name="test-profile",
        base_url="https://api.upstream.com",
        injection_type=injection_type,
        header_name=header_name,
        header_prefix=prefix,
        encrypted_secret=b"fake_bytes",
        created_at="2026-09-10T00:00:00Z",
        updated_at="2026-09-10T00:00:00Z",
    )


def test_bearer_injection_and_header_sanitization():
    """Verify Bearer token is injected and internal service headers are stripped."""
    profile = make_test_profile(InjectionType.BEARER)
    inbound_headers = {
        "X-Service-Id": "order-service",
        "X-Service-Token": "jwt-token-xyz",
        "Host": "secretshield:8000",
        "Content-Type": "application/json",
        "User-Agent": "CustomApp/1.0",
    }

    outbound = CredentialInjector.prepare_headers(
        inbound_headers=inbound_headers,
        profile=profile,
        decrypted_secret="mock_prod_secret_token_999",
    )

    assert "x-service-id" not in outbound
    assert "x-service-token" not in outbound
    assert "host" not in outbound
    assert outbound["Content-Type"] == "application/json"
    assert outbound["User-Agent"] == "CustomApp/1.0"
    assert outbound["Authorization"] == "Bearer mock_prod_secret_token_999"


def test_custom_header_injection():
    """Verify custom API key header injection without prefix."""
    profile = make_test_profile(InjectionType.HEADER, header_name="X-API-Key", prefix="")
    outbound = CredentialInjector.prepare_headers(
        inbound_headers={"Accept": "application/json"},
        profile=profile,
        decrypted_secret="my-custom-api-key-val",
    )

    assert outbound["X-API-Key"] == "my-custom-api-key-val"
    assert "Authorization" not in outbound


def test_basic_auth_injection():
    """Verify username/password secret is Base64 encoded for Basic auth."""
    profile = make_test_profile(InjectionType.BASIC)
    outbound = CredentialInjector.prepare_headers(
        inbound_headers={},
        profile=profile,
        decrypted_secret="api_user:secret_pass_123",
    )

    # base64 of 'api_user:secret_pass_123'
    import base64

    expected_b64 = base64.b64encode(b"api_user:secret_pass_123").decode("ascii")
    assert outbound["Authorization"] == f"Basic {expected_b64}"


def test_prepare_url_and_query_injection():
    """Verify URL path construction and query parameter injection."""
    profile = CredentialProfile(
        name="weather-api",
        base_url="https://api.weather.example/v2/",
        injection_type=InjectionType.QUERY,
        query_param="api_key",
        encrypted_secret=b"fake",
        created_at="2026-09-10T00:00:00Z",
        updated_at="2026-09-10T00:00:00Z",
    )

    url, params = CredentialInjector.prepare_url(
        profile=profile,
        path="/current/city",
        query_params={"city": "Bucharest"},
        decrypted_secret="secret_key_123",
    )

    assert url == "https://api.weather.example/v2/current/city"
    assert params["city"] == "Bucharest"
    assert params["api_key"] == "secret_key_123"
