"""Global configuration and settings for SecretShield."""

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings and environment configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SECRETSHIELD_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Base paths
    data_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("SECRETSHIELD_DATA_DIR", "./data"))
    )

    # Master encryption key (32 bytes hex-encoded, 64 chars)
    master_key: str = Field(
        default="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        description="Master encryption key as 32-byte hex string (64 characters)",
    )

    # Server configuration
    host: str = Field(default="127.0.0.1", description="Server host interface")
    port: int = Field(default=8000, description="Server port")
    log_level: str = Field(default="INFO", description="Logging level")

    # Zero-Trust auth secret for internal service JWT verification
    jwt_secret: str = Field(
        default="secretshield-internal-service-hmac-secret-key-32b",
        description="HMAC secret used for internal service JWT signing and verification",
    )

    # Proxy behavior
    timeout_seconds: float = Field(default=30.0, description="Upstream HTTP timeout in seconds")
    max_keepalive_connections: int = Field(default=50, description="Connection pool size")

    @property
    def vault_db_path(self) -> Path:
        """Return the path to the vault SQLite database."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "vault.db"

    @property
    def audit_db_path(self) -> Path:
        """Return the path to the audit ledger SQLite database."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "audit.db"

    @property
    def master_key_bytes(self) -> bytes:
        """Return the master key as raw bytes."""
        try:
            raw = bytes.fromhex(self.master_key.strip())
            if len(raw) != 32:
                raise ValueError("Master key must be exactly 32 bytes (64 hex characters)")
            return raw
        except ValueError as exc:
            raise ValueError(
                f"Invalid SECRETSHIELD_MASTER_KEY: must be 64-character hex string. ({exc})"
            ) from exc


# Singleton instance
settings = Settings()
