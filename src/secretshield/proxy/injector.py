"""Outbound credential injector supporting Bearer, custom headers, Basic auth, and query params."""

import base64

from secretshield.vault.store import CredentialProfile, InjectionType

# Headers that must be stripped from downstream client requests before forwarding
STRIP_INBOUND_HEADERS = {
    "host",
    "x-service-id",
    "x-service-token",
    "x-secretshield-cost",
    "content-length",  # HTTPX will recalculate appropriately
}


class CredentialInjector:
    """Injects decrypted secrets into outgoing HTTP requests and strips internal headers."""

    @staticmethod
    def prepare_headers(
        inbound_headers: dict[str, str],
        profile: CredentialProfile,
        decrypted_secret: str,
    ) -> dict[str, str]:
        """Sanitize inbound headers and inject upstream credentials.

        Args:
            inbound_headers: Headers sent by the downstream client microservice.
            profile: Credential profile for the upstream API.
            decrypted_secret: Decrypted plaintext secret from the vault.

        Returns:
            Cleaned and credential-injected dictionary of headers.
        """
        # Normalize header keys to lowercase for stripping
        outbound_headers: dict[str, str] = {
            k: v for k, v in inbound_headers.items() if k.lower() not in STRIP_INBOUND_HEADERS
        }

        # Apply credential injection based on profile type
        if profile.injection_type == InjectionType.BEARER:
            prefix = profile.header_prefix or "Bearer "
            outbound_headers[profile.header_name] = f"{prefix}{decrypted_secret}"

        elif profile.injection_type == InjectionType.HEADER:
            prefix = profile.header_prefix or ""
            outbound_headers[profile.header_name] = f"{prefix}{decrypted_secret}"

        elif profile.injection_type == InjectionType.BASIC:
            encoded = base64.b64encode(decrypted_secret.encode("utf-8")).decode("ascii")
            outbound_headers[profile.header_name] = f"Basic {encoded}"

        return outbound_headers

    @staticmethod
    def prepare_url(
        profile: CredentialProfile,
        path: str,
        query_params: dict[str, str] | None = None,
        decrypted_secret: str | None = None,
    ) -> tuple[str, dict[str, str]]:
        """Construct full target URL and query parameters.

        Args:
            profile: Credential profile containing base_url.
            path: Relative target path.
            query_params: Downstream client query parameters.
            decrypted_secret: Decrypted secret (used if injection_type is QUERY).

        Returns:
            Tuple of (full_target_url, final_query_params).
        """
        base = profile.base_url.rstrip("/")
        clean_path = path.lstrip("/")
        full_url = f"{base}/{clean_path}" if clean_path else base

        params = dict(query_params or {})
        if (
            profile.injection_type == InjectionType.QUERY
            and profile.query_param
            and decrypted_secret
        ):
            params[profile.query_param] = decrypted_secret

        return full_url, params
