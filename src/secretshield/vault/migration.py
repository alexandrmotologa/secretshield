"""Encrypted backup export and restore utility for SecretShield vault."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from secretshield.vault.store import InjectionType, VaultStore


class MigrationError(Exception):
    """Raised when vault export or import fails."""


class VaultMigration:
    """Handles encrypted export and restore of credential profiles."""

    SALT_SIZE = 16
    NONCE_SIZE = 12
    ITERATIONS = 100_000

    @classmethod
    def _derive_key(cls, passphrase: str, salt: bytes) -> bytes:
        """Derive 256-bit encryption key from user passphrase."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=cls.ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @classmethod
    async def export_vault(
        cls,
        store: VaultStore,
        passphrase: str,
        output_path: Path,
    ) -> int:
        """Export all vault profiles to an encrypted backup file.

        Args:
            store: Source VaultStore instance.
            passphrase: User password protecting the backup file.
            output_path: Destination file path (e.g. 'vault-backup.enc').

        Returns:
            Count of exported profiles.
        """
        if not passphrase or len(passphrase) < 8:
            raise MigrationError("Export passphrase must be at least 8 characters")

        profiles = await store.get_all_profiles()
        export_items: List[Dict[str, Any]] = []

        for p in profiles:
            secret = await store.get_decrypted_secret(p.name)
            if not secret:
                continue
            export_items.append(
                {
                    "name": p.name,
                    "base_url": p.base_url,
                    "domains": p.domains,
                    "injection_type": p.injection_type.value,
                    "header_name": p.header_name,
                    "header_prefix": p.header_prefix,
                    "query_param": p.query_param,
                    "secret": secret,
                    "metadata": p.metadata,
                }
            )

        payload_bytes = json.dumps(export_items).encode("utf-8")

        salt = os.urandom(cls.SALT_SIZE)
        nonce = os.urandom(cls.NONCE_SIZE)
        key = cls._derive_key(passphrase, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, payload_bytes, b"secretshield-export-v1")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

        return len(export_items)

    @classmethod
    async def import_vault(
        cls,
        store: VaultStore,
        passphrase: str,
        input_path: Path,
    ) -> int:
        """Decrypt backup file and import profiles into the vault.

        Args:
            store: Destination VaultStore instance.
            passphrase: User password protecting the backup file.
            input_path: Source backup file path.

        Returns:
            Count of imported profiles.
        """
        if not input_path.exists():
            raise MigrationError(f"Backup file '{input_path}' not found")

        with open(input_path, "rb") as f:
            data = f.read()

        min_size = cls.SALT_SIZE + cls.NONCE_SIZE + 16
        if len(data) < min_size:
            raise MigrationError("Corrupted or invalid backup file format")

        salt = data[: cls.SALT_SIZE]
        nonce = data[cls.SALT_SIZE : cls.SALT_SIZE + cls.NONCE_SIZE]
        ciphertext = data[cls.SALT_SIZE + cls.NONCE_SIZE :]

        key = cls._derive_key(passphrase, salt)
        aesgcm = AESGCM(key)

        try:
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, b"secretshield-export-v1")
            items = json.loads(decrypted_bytes.decode("utf-8"))
        except Exception as exc:
            raise MigrationError(
                "Decryption failed: incorrect passphrase or corrupted file"
            ) from exc

        count = 0
        for item in items:
            await store.set_profile(
                name=item["name"],
                base_url=item["base_url"],
                secret=item["secret"],
                domains=item.get("domains", []),
                injection_type=InjectionType(item.get("injection_type", "bearer")),
                header_name=item.get("header_name", "Authorization"),
                header_prefix=item.get("header_prefix", "Bearer "),
                query_param=item.get("query_param"),
                metadata=item.get("metadata", {}),
            )
            count += 1

        return count
