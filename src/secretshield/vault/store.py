"""SQLite-backed encrypted credential profile repository."""

import json
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import aiosqlite
from pydantic import BaseModel, Field

from secretshield.vault.cipher import VaultCipher


class InjectionType(str, Enum):
    """How the secret is injected into the outbound request."""

    BEARER = "bearer"
    HEADER = "header"
    BASIC = "basic"
    QUERY = "query"


class CredentialProfile(BaseModel):
    """Internal model for an encrypted credential profile."""

    name: str
    base_url: str
    injection_type: InjectionType = InjectionType.BEARER
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "
    query_param: str | None = None
    encrypted_secret: bytes
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ProfileView(BaseModel):
    """Sanitized profile view safe for listing and CLI output."""

    name: str
    base_url: str
    injection_type: InjectionType
    header_name: str
    header_prefix: str
    query_param: str | None = None
    secret_preview: str
    created_at: str
    updated_at: str


def mask_secret(secret: str) -> str:
    """Mask a secret for display, showing only the beginning and end."""
    if len(secret) <= 8:
        return "********"
    prefix = secret[:4]
    suffix = secret[-4:]
    return f"{prefix}...{suffix}"


class VaultStore:
    """Async SQLite repository for encrypted profiles."""

    def __init__(self, db_path: Path, cipher: VaultCipher):
        self.db_path = db_path
        self.cipher = cipher

    async def init_db(self) -> None:
        """Create vault tables if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_profiles (
                    name TEXT PRIMARY KEY,
                    base_url TEXT NOT NULL,
                    injection_type TEXT NOT NULL,
                    header_name TEXT NOT NULL,
                    header_prefix TEXT NOT NULL,
                    query_param TEXT,
                    encrypted_secret BLOB NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            await db.commit()

    async def set_profile(
        self,
        name: str,
        base_url: str,
        secret: str,
        injection_type: InjectionType = InjectionType.BEARER,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer ",
        query_param: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CredentialProfile:
        """Store or update an encrypted profile.

        Args:
            name: Unique profile name (e.g. 'stripe-prod', 'openai').
            base_url: The target API base URL (e.g. 'https://api.stripe.com').
            secret: The plaintext secret to encrypt and store.
            injection_type: Type of credential injection.
            header_name: HTTP header to inject into.
            header_prefix: Prefix preceding the secret in the header.
            query_param: Optional query parameter name if injection_type is QUERY.
            metadata: Additional metadata dictionary.

        Returns:
            The stored CredentialProfile object.
        """
        await self.init_db()
        now = datetime.now(UTC).isoformat()
        encrypted_secret = self.cipher.encrypt(secret, context=name)
        meta_json = json.dumps(metadata or {})

        async with aiosqlite.connect(self.db_path) as db:
            # Check if profile already exists to preserve created_at
            async with db.execute(
                "SELECT created_at FROM vault_profiles WHERE name = ?", (name,)
            ) as cursor:
                row = await cursor.fetchone()
                created_at = row[0] if row else now

            await db.execute(
                """
                INSERT INTO vault_profiles (
                    name, base_url, injection_type, header_name, header_prefix,
                    query_param, encrypted_secret, metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    base_url = excluded.base_url,
                    injection_type = excluded.injection_type,
                    header_name = excluded.header_name,
                    header_prefix = excluded.header_prefix,
                    query_param = excluded.query_param,
                    encrypted_secret = excluded.encrypted_secret,
                    metadata = excluded.metadata,
                    updated_at = excluded.updated_at
                """,
                (
                    name,
                    base_url.rstrip("/"),
                    injection_type.value,
                    header_name,
                    header_prefix,
                    query_param,
                    encrypted_secret,
                    meta_json,
                    created_at,
                    now,
                ),
            )
            await db.commit()

        return CredentialProfile(
            name=name,
            base_url=base_url.rstrip("/"),
            injection_type=injection_type,
            header_name=header_name,
            header_prefix=header_prefix,
            query_param=query_param,
            encrypted_secret=encrypted_secret,
            metadata=metadata or {},
            created_at=created_at,
            updated_at=now,
        )

    async def get_profile(self, name: str) -> CredentialProfile | None:
        """Fetch a credential profile by name."""
        await self.init_db()
        async with (
            aiosqlite.connect(self.db_path) as db,
            db.execute(
                """
                SELECT name, base_url, injection_type, header_name, header_prefix,
                       query_param, encrypted_secret, metadata, created_at, updated_at
                FROM vault_profiles WHERE name = ?
                """,
                (name,),
            ) as cursor,
        ):
            row = await cursor.fetchone()
            if not row:
                return None

            return CredentialProfile(
                name=row[0],
                base_url=row[1],
                injection_type=InjectionType(row[2]),
                header_name=row[3],
                header_prefix=row[4],
                query_param=row[5],
                encrypted_secret=row[6],
                metadata=json.loads(row[7]),
                created_at=row[8],
                updated_at=row[9],
            )

    async def get_decrypted_secret(self, name: str) -> str | None:
        """Fetch and decrypt the secret for a profile."""
        profile = await self.get_profile(name)
        if not profile:
            return None
        return self.cipher.decrypt(profile.encrypted_secret, context=name)

    async def list_profiles(self) -> list[ProfileView]:
        """List all profiles with masked secret previews."""
        await self.init_db()
        results: list[ProfileView] = []
        async with (
            aiosqlite.connect(self.db_path) as db,
            db.execute(
                """
                SELECT name, base_url, injection_type, header_name, header_prefix,
                       query_param, encrypted_secret, created_at, updated_at
                FROM vault_profiles ORDER BY name ASC
                """
            ) as cursor,
        ):
            rows = await cursor.fetchall()
            for row in rows:
                name = row[0]
                encrypted = row[6]
                try:
                    secret = self.cipher.decrypt(encrypted, context=name)
                    preview = mask_secret(secret)
                except Exception:
                    preview = "[decryption_error]"

                results.append(
                    ProfileView(
                        name=name,
                        base_url=row[1],
                        injection_type=InjectionType(row[2]),
                        header_name=row[3],
                        header_prefix=row[4],
                        query_param=row[5],
                        secret_preview=preview,
                        created_at=row[7],
                        updated_at=row[8],
                    )
                )
        return results

    async def delete_profile(self, name: str) -> bool:
        """Delete a profile by name. Returns True if found and deleted."""
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("DELETE FROM vault_profiles WHERE name = ?", (name,))
            await db.commit()
            return cursor.rowcount > 0
