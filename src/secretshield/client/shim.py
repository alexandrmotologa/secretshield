"""Drop-in Python client helper for microservices calling SecretShield."""

from typing import Any

import httpx


class SecretShieldClient:
    """Client helper allowing microservices to route API calls through SecretShield."""

    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:8000",
        service_id: str | None = None,
        service_token: str | None = None,
        timeout: float = 30.0,
    ):
        self.proxy_url = proxy_url.rstrip("/")
        self.service_id = service_id
        self.service_token = service_token
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        """Close HTTP client session."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    def _build_headers(self, custom_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Attach service authentication headers."""
        headers = dict(custom_headers or {})
        if self.service_id:
            headers["X-Service-Id"] = self.service_id
        if self.service_token:
            headers["X-Service-Token"] = self.service_token
        return headers

    async def request(
        self,
        method: str,
        profile: str,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json: Any | None = None,
        data: Any | None = None,
    ) -> httpx.Response:
        """Send a proxied request through SecretShield."""
        clean_path = path.lstrip("/")
        url = f"{self.proxy_url}/proxy/{profile}/{clean_path}"
        req_headers = self._build_headers(headers)

        return await self._client.request(
            method=method,
            url=url,
            headers=req_headers,
            params=params,
            json=json,
            data=data,
        )

    async def get(self, profile: str, path: str, **kwargs) -> httpx.Response:
        return await self.request("GET", profile, path, **kwargs)

    async def post(self, profile: str, path: str, **kwargs) -> httpx.Response:
        return await self.request("POST", profile, path, **kwargs)

    async def put(self, profile: str, path: str, **kwargs) -> httpx.Response:
        return await self.request("PUT", profile, path, **kwargs)

    async def delete(self, profile: str, path: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", profile, path, **kwargs)
