"""Streaming outbound HTTP proxy forwarder."""

from collections.abc import AsyncIterator

import httpx
from fastapi import HTTPException

from secretshield.proxy.injector import CredentialInjector
from secretshield.proxy.resilience import CircuitBreakerOpenError, CircuitBreakerRegistry
from secretshield.vault.store import VaultStore

# Response headers that should not be directly forwarded from upstream
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class ProxyForwarder:
    """Async streaming proxy forwarder."""

    def __init__(
        self,
        vault_store: VaultStore,
        circuit_registry: CircuitBreakerRegistry | None = None,
        timeout: float = 30.0,
        max_connections: int = 100,
    ):
        self.vault_store = vault_store
        self.circuit_registry = circuit_registry or CircuitBreakerRegistry()
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_keepalive_connections=max_connections),
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client session."""
        await self._client.aclose()

    async def forward(
        self,
        profile_name: str,
        path: str,
        method: str,
        headers: dict[str, str],
        query_params: dict[str, str] | None = None,
        content: bytes | None = None,
        stream_content: AsyncIterator[bytes] | None = None,
    ) -> tuple[int, dict[str, str], AsyncIterator[bytes], float]:
        """Forward downstream request to upstream target.

        Args:
            profile_name: Upstream profile name to look up in vault.
            path: Relative target API path.
            method: HTTP verb (GET, POST, etc.).
            headers: Inbound client request headers.
            query_params: Query parameters.
            content: Raw request bytes.
            stream_content: Optional async generator of request chunks.

        Returns:
            Tuple of (status_code, response_headers, response_stream, latency_ms).

        Raises:
            HTTPException: If profile does not exist or circuit breaker is open.
        """
        profile = await self.vault_store.get_profile(profile_name)
        if not profile:
            raise HTTPException(
                status_code=404,
                detail=f"Credential profile '{profile_name}' not found in vault",
            )

        decrypted_secret = await self.vault_store.get_decrypted_secret(profile_name)
        if not decrypted_secret:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to decrypt credentials for profile '{profile_name}'",
            )

        circuit_breaker = self.circuit_registry.get(profile_name)
        try:
            circuit_breaker.check_can_execute()
        except CircuitBreakerOpenError as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
            ) from exc

        target_url, final_params = CredentialInjector.prepare_url(
            profile=profile,
            path=path,
            query_params=query_params,
            decrypted_secret=decrypted_secret,
        )
        outbound_headers = CredentialInjector.prepare_headers(
            inbound_headers=headers,
            profile=profile,
            decrypted_secret=decrypted_secret,
        )

        import time

        start_time = time.monotonic()

        try:
            # Build streaming request
            request = self._client.build_request(
                method=method,
                url=target_url,
                headers=outbound_headers,
                params=final_params,
                content=content if content is not None else stream_content,
            )

            upstream_response = await self._client.send(request, stream=True)
            latency_ms = (time.monotonic() - start_time) * 1000.0

            if upstream_response.status_code >= 500:
                circuit_breaker.record_failure()
            else:
                circuit_breaker.record_success()

            # Filter response headers
            clean_headers: dict[str, str] = {
                k: v
                for k, v in upstream_response.headers.items()
                if k.lower() not in HOP_BY_HOP_HEADERS
            }

            async def stream_wrapper() -> AsyncIterator[bytes]:
                try:
                    async for chunk in upstream_response.aiter_bytes():
                        yield chunk
                finally:
                    await upstream_response.aclose()

            return (
                upstream_response.status_code,
                clean_headers,
                stream_wrapper(),
                latency_ms,
            )

        except httpx.RequestError as exc:
            circuit_breaker.record_failure()
            latency_ms = (time.monotonic() - start_time) * 1000.0
            raise HTTPException(
                status_code=502,
                detail=f"Bad Gateway: upstream request failed ({type(exc).__name__}: {exc!s})",
            ) from exc
