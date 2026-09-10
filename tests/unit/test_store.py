"""Unit tests for SQLite VaultStore repository."""

import os
from pathlib import Path
import pytest
from secretshield.vault.cipher import VaultCipher
from secretshield.vault.store import VaultStore, InjectionType, mask_secret


@pytest.fixture
def cipher() -> VaultCipher:
    return VaultCipher(os.urandom(32))


@pytest.fixture
def store(tmp_path: Path, cipher: VaultCipher) -> VaultStore:
    db_path = tmp_path / "test_vault.db"
    return VaultStore(db_path=db_path, cipher=cipher)


def test_mask_secret_helper():
    """Verify secret masking correctly hides middle characters."""
    assert mask_secret("short") == "********"
    assert mask_secret("sec_tok_1234567890abcdef") == "sec_...cdef"


@pytest.mark.asyncio
async def test_set_and_get_profile(store: VaultStore):
    """Verify profile can be saved and retrieved with decrypted secret."""
    profile = await store.set_profile(
        name="stripe-prod",
        base_url="https://api.stripe.com",
        secret="sec_sample_secret_token_stripe_1234",
        injection_type=InjectionType.BEARER,
        header_name="Authorization",
        header_prefix="Bearer ",
    )

    assert profile.name == "stripe-prod"
    assert profile.base_url == "https://api.stripe.com"

    # Retrieve profile
    fetched = await store.get_profile("stripe-prod")
    assert fetched is not None
    assert fetched.name == "stripe-prod"
    assert fetched.base_url == "https://api.stripe.com"
    assert fetched.injection_type == InjectionType.BEARER

    # Decrypt secret
    decrypted = await store.get_decrypted_secret("stripe-prod")
    assert decrypted == "sec_sample_secret_token_stripe_1234"


@pytest.mark.asyncio
async def test_get_nonexistent_profile(store: VaultStore):
    """Verify querying an unknown profile returns None."""
    assert await store.get_profile("unknown") is None
    assert await store.get_decrypted_secret("unknown") is None


@pytest.mark.asyncio
async def test_update_profile(store: VaultStore):
    """Verify updating a profile preserves creation date and updates fields."""
    p1 = await store.set_profile(
        name="openai",
        base_url="https://api.openai.com",
        secret="key-v1",
    )
    initial_created = p1.created_at

    p2 = await store.set_profile(
        name="openai",
        base_url="https://api.openai.com/v1",
        secret="key-v2",
    )

    assert p2.created_at == initial_created
    decrypted = await store.get_decrypted_secret("openai")
    assert decrypted == "key-v2"


@pytest.mark.asyncio
async def test_list_profiles(store: VaultStore):
    """Verify listing profiles masks raw secrets."""
    await store.set_profile(
        name="github",
        base_url="https://api.github.com",
        secret="tok_gh_1234567890abcdefghijklmnopqr",
    )
    await store.set_profile(
        name="aws",
        base_url="https://aws.amazon.com",
        secret="tok_aws_1234567890ABCDEF",
    )

    profiles = await store.list_profiles()
    assert len(profiles) == 2
    assert profiles[0].name == "aws"
    assert profiles[1].name == "github"
    assert "..." in profiles[0].secret_preview
    assert "..." in profiles[1].secret_preview


@pytest.mark.asyncio
async def test_delete_profile(store: VaultStore):
    """Verify deleting a profile removes it from store."""
    await store.set_profile(
        name="to-delete",
        base_url="https://example.com",
        secret="secret123",
    )

    assert await store.delete_profile("to-delete") is True
    assert await store.get_profile("to-delete") is None
    assert await store.delete_profile("to-delete") is False
