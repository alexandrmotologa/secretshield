"""Zero-Trust microservice caller authentication with HMAC JWT and pre-shared keys."""

from datetime import UTC, datetime, timedelta

import jwt
from pydantic import BaseModel


class AuthenticationError(Exception):
    """Raised when caller identity cannot be verified."""


class CallerIdentity(BaseModel):
    """Verified identity of the calling microservice."""

    service_id: str
    scopes: list[str] = []
    metadata: dict[str, str] = {}


class TokenAuthenticator:
    """Issues and validates internal service tokens."""

    def __init__(
        self,
        jwt_secret: str,
        static_service_keys: dict[str, str] | None = None,
        default_token_ttl_seconds: int = 3600,
    ):
        self.jwt_secret = jwt_secret
        self.static_service_keys = static_service_keys or {}
        self.default_token_ttl = default_token_ttl_seconds

    def issue_service_token(
        self,
        service_id: str,
        scopes: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        """Issue a short-lived internal HMAC-SHA256 JWT for a microservice."""
        now = datetime.now(UTC)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_token_ttl
        payload = {
            "sub": service_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "scopes": scopes or [],
            "iss": "secretshield",
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def authenticate(
        self,
        service_id: str | None,
        token: str | None,
    ) -> CallerIdentity:
        """Authenticate a microservice caller via JWT token or pre-shared key.

        Args:
            service_id: Claimed service identifier from X-Service-Id.
            token: Service token from X-Service-Token or Authorization.

        Returns:
            CallerIdentity if authenticated.

        Raises:
            AuthenticationError: If token is missing, expired, invalid, or ID mismatches.
        """
        if not token:
            raise AuthenticationError("Missing service authentication token")

        # Strip Bearer prefix if caller passed Authorization: Bearer <internal-token>
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        # 1. Check if token matches static pre-shared key
        if service_id and service_id in self.static_service_keys:
            if self.static_service_keys[service_id] == token:
                return CallerIdentity(service_id=service_id, scopes=["*"])

        # 2. Otherwise validate as HMAC JWT
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                issuer="secretshield",
                options={"require": ["exp", "sub", "iat"]},
            )
            sub = payload.get("sub")
            if not sub:
                raise AuthenticationError("JWT token missing 'sub' subject claim")

            # If service_id was explicitly provided, it must match sub
            if service_id and service_id != sub:
                raise AuthenticationError(
                    f"Service ID mismatch: header specifies '{service_id}' but token issued to '{sub}'"
                )

            return CallerIdentity(
                service_id=sub,
                scopes=payload.get("scopes", []),
            )

        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("Service token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(f"Invalid service token: {exc!s}") from exc
