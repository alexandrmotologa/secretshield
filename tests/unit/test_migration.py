"""Unit tests for VaultMigration export/import and Blue-Green rotation."""

import os
from pathlib import Path

import pytest

from secretshield.vault.cipher import VaultCipher
from secretshield.vault.migration import MigrationError, VaultMigration
from secretshield.vault.store import VaultStore


@pytest.fixture
def cipher() -> VaultCipher:
    return VaultCipher(os.urandom(32))


@pytest.fixture
def store(tmp_path: Path, cipher: VaultCipher) -> VaultStore:
    return VaultStore(tmp_path / "vault1.db", cipher)


@pytest.fixture
def store2(tmp_path: Path, cipher: VaultCipher) -> VaultStore:
    return VaultStore(tmp_path / "vault2.db", cipher)


@pytest.mark.asyncio
async def test_vault_blue_green_rotation(store: VaultStore):
    """Verify secret rotation increments version and preserves previous secret."""
    p1 = await store.set_profile(
        name="stripe-rot",
        base_url="https://api.stripe.com",
        secret="sec_test_stripe_key_v1_12345",
    )
    assert p1.version == 1

    # Rotate to v2
    p2 = await store.rotate_secret("stripe-rot", "sec_test_stripe_key_v2_67890")
    assert p2.version == 2
    assert p2.previous_encrypted_secret is not None

    # Current decrypted secret should be v2
    current_sec = await store.get_decrypted_secret("stripe-rot")
    assert current_sec == "sec_test_stripe_key_v2_67890"


@pytest.mark.asyncio
async def test_vault_get_profile_by_host(store: VaultStore):
    """Verify host resolution matches base_url or custom domains."""
    await store.set_profile(
        name="openai-prod",
        base_url="https://api.openai.com",
        secret="sec_test_openai_123",
        domains=["api.openai.com", "openai.internal.mesh"],
    )

    p1 = await store.get_profile_by_host("api.openai.com")
    assert p1 is not None
    assert p1.name == "openai-prod"

    p2 = await store.get_profile_by_host("openai.internal.mesh:443")
    assert p2 is not None
    assert p2.name == "openai-prod"

    p3 = await store.get_profile_by_host("unknown.domain.com")
    assert p3 is None


@pytest.mark.asyncio
async def test_vault_export_and_import(store: VaultStore, store2: VaultStore, tmp_path: Path):
    """Verify exporting encrypted vault and importing into another store."""
    await store.set_profile(
        name="github",
        base_url="https://api.github.com",
        secret="sec_test_gh_token_12345",
    )
    await store.set_profile(
        name="stripe",
        base_url="https://api.stripe.com",
        secret="sec_test_stripe_token_999",
    )

    backup_path = tmp_path / "backup.enc"
    passphrase = "super-secret-backup-passphrase"

    # Export
    count = await VaultMigration.export_vault(store, passphrase, backup_path)
    assert count == 2
    assert backup_path.exists()

    # Import into clean store2
    imported_count = await VaultMigration.import_vault(store2, passphrase, backup_path)
    assert imported_count == 2

    # Verify decrypted contents in destination
    assert await store2.get_decrypted_secret("github") == "sec_test_gh_token_12345"
    assert await store2.get_decrypted_secret("stripe") == "sec_test_stripe_token_999"


@pytest.mark.asyncio
async def test_vault_import_wrong_passphrase_fails(store: VaultStore, tmp_path: Path):
    """Verify importing with incorrect password raises MigrationError."""
    await store.set_profile(name="p1", base_url="https://api.com", secret="sec1")
    backup_path = tmp_path / "backup_wrong.enc"
    await VaultMigration.export_vault(store, "correct-password-123", backup_path)

    with pytest.raises(MigrationError, match="incorrect passphrase"):
        await VaultMigration.import_vault(store, "wrong-password-999", backup_path)
