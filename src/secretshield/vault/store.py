"""SQLite-backed encrypted credential profile repository with rotation and host resolution."""

import json
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
    domains: list[str] = Field(default_factory=list)
    version: int = 1
    injection_type: InjectionType = InjectionType.BEARER
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "
    query_param: str | None = None
    encrypted_secret: bytes
    previous_encrypted_secret: bytes | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ProfileView(BaseModel):
    """Sanitized profile view safe for listing and CLI output."""

    name: str
    base_url: str
    domains: list[str] = Field(default_factory=list)
    version: int = 1
    injection_type: InjectionType
    header_name: str
    header_prefix: str
    query_param: str | None = None
    secret_preview: str
    has_backup_key: bool = False
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
        """Create vault tables if they do not exist and ensure schema migrations."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_profiles (
                    name TEXT PRIMARY KEY,
                    base_url TEXT NOT NULL,
                    domains TEXT NOT NULL DEFAULT '[]',
                    version INTEGER NOT NULL DEFAULT 1,
                    injection_type TEXT NOT NULL,
                    header_name TEXT NOT NULL,
                    header_prefix TEXT NOT NULL,
                    query_param TEXT,
                    encrypted_secret BLOB NOT NULL,
                    previous_encrypted_secret BLOB,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            # Check for existing table schema to migrate columns if needed
            async with db.execute("PRAGMA table_info(vault_profiles)") as cursor:
                columns = [row[1] for row in await cursor.fetchall()]

            if "domains" not in columns:
                await db.execute(
                    "ALTER TABLE vault_profiles ADD COLUMN domains TEXT NOT NULL DEFAULT '[]'"
                )
            if "version" not in columns:
                await db.execute(
                    "ALTER TABLE vault_profiles ADD COLUMN version INTEGER NOT NULL DEFAULT 1"
                )
            if "previous_encrypted_secret" not in columns:
                await db.execute(
                    "ALTER TABLE vault_profiles ADD COLUMN previous_encrypted_secret BLOB"
                )

            await db.commit()

    async def set_profile(
        self,
        name: str,
        base_url: str,
        secret: str,
        domains: list[str] | None = None,
        injection_type: InjectionType = InjectionType.BEARER,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer ",
        query_param: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CredentialProfile:
        """Store or update an encrypted profile."""
        await self.init_db()
        now = datetime.now(UTC).isoformat()
        encrypted_secret = self.cipher.encrypt(secret, context=name)
        meta_json = json.dumps(metadata or {})

        # Default domain from base_url if not provided
        parsed_host = urlparse(base_url).hostname
        final_domains = domains if domains is not None else ([parsed_host] if parsed_host else [])
        domains_json = json.dumps(final_domains)

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT created_at, version, encrypted_secret FROM vault_profiles WHERE name = ?",
                (name,),
            ) as cursor:
                row = await cursor.fetchone()
                created_at = row[0] if row else now
                version = row[1] if row else 1

            await db.execute(
                """
                INSERT INTO vault_profiles (
                    name, base_url, domains, version, injection_type, header_name, header_prefix,
                    query_param, encrypted_secret, previous_encrypted_secret, metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    base_url = excluded.base_url,
                    domains = excluded.domains,
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
                    domains_json,
                    version,
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
            domains=final_domains,
            version=version,
            injection_type=injection_type,
            header_name=header_name,
            header_prefix=header_prefix,
            query_param=query_param,
            encrypted_secret=encrypted_secret,
            metadata=metadata or {},
            created_at=created_at,
            updated_at=now,
        )

    async def rotate_secret(self, name: str, new_secret: str) -> CredentialProfile:
        """Perform Blue-Green rotation of secret, keeping previous secret as fallback."""
        profile = await self.get_profile(name)
        if not profile:
            raise ValueError(f"Cannot rotate secret: profile '{name}' not found")

        await self.init_db()
        now = datetime.now(UTC).isoformat()
        new_encrypted = self.cipher.encrypt(new_secret, context=name)
        old_encrypted = profile.encrypted_secret
        new_version = profile.version + 1

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE vault_profiles SET
                    encrypted_secret = ?,
                    previous_encrypted_secret = ?,
                    version = ?,
                    updated_at = ?
                WHERE name = ?
                """,
                (new_encrypted, old_encrypted, new_version, now, name),
            )
            await db.commit()

        profile.encrypted_secret = new_encrypted
        profile.previous_encrypted_secret = old_encrypted
        profile.version = new_version
        profile.updated_at = now
        return profile

    async def get_profile(self, name: str) -> CredentialProfile | None:
        """Fetch a credential profile by name."""
        await self.init_db()
        async with (
            aiosqlite.connect(self.db_path) as db,
            db.execute(
                """
                SELECT name, base_url, domains, version, injection_type, header_name, header_prefix,
                       query_param, encrypted_secret, previous_encrypted_secret, metadata, created_at, updated_at
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
                domains=json.loads(row[2]) if row[2] else [],
                version=row[3],
                injection_type=InjectionType(row[4]),
                header_name=row[5],
                header_prefix=row[6],
                query_param=row[7],
                encrypted_secret=row[8],
                previous_encrypted_secret=row[9],
                metadata=json.loads(row[10]),
                created_at=row[11],
                updated_at=row[12],
            )

    async def get_profile_by_host(self, host: str) -> CredentialProfile | None:
        """Resolve a credential profile by target hostname for transparent forward proxying."""
        await self.init_db()
        clean_host = host.split(":")[0].lower()

        profiles = await self.get_all_profiles()
        for p in profiles:
            # Check domains list
            for d in p.domains:
                if d.lower() == clean_host:
                    return p
            # Check hostname of base_url
            base_host = urlparse(p.base_url).hostname
            if base_host and base_host.lower() == clean_host:
                return p
        return None

    async def get_all_profiles(self) -> list[CredentialProfile]:
        """Fetch all raw profile models."""
        await self.init_db()
        results: list[CredentialProfile] = []
        async with (
            aiosqlite.connect(self.db_path) as db,
            db.execute(
                """
                SELECT name, base_url, domains, version, injection_type, header_name, header_prefix,
                       query_param, encrypted_secret, previous_encrypted_secret, metadata, created_at, updated_at
                FROM vault_profiles
                """
            ) as cursor,
        ):
            rows = await cursor.fetchall()
            for row in rows:
                results.append(
                    CredentialProfile(
                        name=row[0],
                        base_url=row[1],
                        domains=json.loads(row[2]) if row[2] else [],
                        version=row[3],
                        injection_type=InjectionType(row[4]),
                        header_name=row[5],
                        header_prefix=row[6],
                        query_param=row[7],
                        encrypted_secret=row[8],
                        previous_encrypted_secret=row[9],
                        metadata=json.loads(row[10]),
                        created_at=row[11],
                        updated_at=row[12],
                    )
                )
        return results

    async def get_decrypted_secret(self, name: str) -> str | None:
        """Fetch and decrypt the secret for a profile."""
        profile = await self.get_profile(name)
        if not profile:
            return None
        return self.cipher.decrypt(profile.encrypted_secret, context=name)

    async def list_profiles(self) -> list[ProfileView]:
        """List all profiles with masked secret previews and version info."""
        await self.init_db()
        results: list[ProfileView] = []
        profiles = await self.get_all_profiles()
        for p in sorted(profiles, key=lambda x: x.name):
            try:
                secret = self.cipher.decrypt(p.encrypted_secret, context=p.name)
                preview = mask_secret(secret)
            except Exception:
                preview = "[decryption_error]"

            results.append(
                ProfileView(
                    name=p.name,
                    base_url=p.base_url,
                    domains=p.domains,
                    version=p.version,
                    injection_type=p.injection_type,
                    header_name=p.header_name,
                    header_prefix=p.header_prefix,
                    query_param=p.query_param,
                    secret_preview=preview,
                    has_backup_key=p.previous_encrypted_secret is not None,
                    created_at=p.created_at,
                    updated_at=p.updated_at,
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
