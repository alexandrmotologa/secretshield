"""Unit tests for AES-256-GCM cipher with HKDF key derivation."""

import os
import pytest
from secretshield.vault.cipher import (
    VaultCipher,
    DecryptionFailedError,
    InvalidPayloadError,
)


@pytest.fixture
def master_key() -> bytes:
    """Provide a secure 32-byte test master key."""
    return os.urandom(32)


@pytest.fixture
def cipher(master_key: bytes) -> VaultCipher:
    """Initialize cipher with test master key."""
    return VaultCipher(master_key)


def test_init_invalid_key_length():
    """Verify initialization rejects keys that are not 32 bytes."""
    with pytest.raises(ValueError, match="Master key must be exactly 32 bytes"):
        VaultCipher(b"too-short")


def test_encryption_decryption_roundtrip(cipher: VaultCipher):
    """Verify plaintext can be encrypted and cleanly decrypted."""
    plaintext = "mock_sec_key_sample_abcdefghijklmnopqrstuvwxyz123456"
    encrypted = cipher.encrypt(plaintext)

    assert encrypted != plaintext.encode()
    assert len(encrypted) >= VaultCipher.MIN_PAYLOAD_SIZE

    decrypted = cipher.decrypt(encrypted)
    assert decrypted == plaintext


def test_encryption_with_context_aad(cipher: VaultCipher):
    """Verify Additional Authenticated Data binds ciphertext to context."""
    secret = "anthropic-api-key-xyz"
    context = "profile-production"

    encrypted = cipher.encrypt(secret, context=context)
    decrypted = cipher.decrypt(encrypted, context=context)
    assert decrypted == secret

    # Decrypting with wrong context must fail
    with pytest.raises(DecryptionFailedError):
        cipher.decrypt(encrypted, context="profile-staging")

    # Decrypting with no context must fail
    with pytest.raises(DecryptionFailedError):
        cipher.decrypt(encrypted)


def test_ciphertext_tampering_detected(cipher: VaultCipher):
    """Verify bit tampering in ciphertext triggers DecryptionFailedError."""
    secret = "my_super_secret"
    encrypted = bytearray(cipher.encrypt(secret))

    # Flip a bit in the ciphertext payload
    encrypted[-1] ^= 0xFF

    with pytest.raises(DecryptionFailedError):
        cipher.decrypt(bytes(encrypted))


def test_salt_randomness(cipher: VaultCipher):
    """Verify each encryption of identical plaintext produces different ciphertext."""
    secret = "identical_secret"
    enc1 = cipher.encrypt(secret)
    enc2 = cipher.encrypt(secret)

    assert enc1 != enc2
    assert enc1[:16] != enc2[:16]  # Random salts differ


def test_invalid_payload_length(cipher: VaultCipher):
    """Verify payloads smaller than minimum size are rejected."""
    with pytest.raises(InvalidPayloadError):
        cipher.decrypt(b"short_bytes")


def test_unicode_and_binary_payload(cipher: VaultCipher):
    """Verify unicode characters are preserved through encryption."""
    unicode_secret = "secret-🔒-clé-sécurisée-こんにちは"
    encrypted = cipher.encrypt(unicode_secret)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == unicode_secret
