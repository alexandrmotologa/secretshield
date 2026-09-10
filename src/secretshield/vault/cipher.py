"""AES-256-GCM authenticated envelope encryption with HKDF key derivation."""

import os
from typing import Optional
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CipherError(Exception):
    """Base exception for cryptographic operations."""


class DecryptionFailedError(CipherError):
    """Raised when ciphertext cannot be decrypted or authentication tag mismatches."""


class InvalidPayloadError(CipherError):
    """Raised when payload length is insufficient for salt, nonce, and tag."""


class VaultCipher:
    """Envelope encryption cipher using AES-256-GCM and HKDF SHA-256 key derivation."""

    SALT_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16
    MIN_PAYLOAD_SIZE = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    HKDF_INFO = b"secretshield-vault-v1"

    def __init__(self, master_key: bytes):
        """Initialize with a 32-byte master key."""
        if len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes (256 bits)")
        self._master_key = master_key

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive an ephemeral AES key using HKDF SHA-256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=self.HKDF_INFO,
        )
        return hkdf.derive(self._master_key)

    def encrypt(self, plaintext: str | bytes, context: Optional[str] = None) -> bytes:
        """Encrypt plaintext with AES-256-GCM.

        The payload format is:
            [salt (16 bytes)] + [nonce (12 bytes)] + [ciphertext + tag]

        Args:
            plaintext: The secret to encrypt.
            context: Optional context string bound as Additional Authenticated Data (AAD).

        Returns:
            Binary encrypted payload.
        """
        if isinstance(plaintext, str):
            data = plaintext.encode("utf-8")
        else:
            data = plaintext

        salt = os.urandom(self.SALT_SIZE)
        derived_key = self._derive_key(salt)
        nonce = os.urandom(self.NONCE_SIZE)
        aad = context.encode("utf-8") if context else None

        aesgcm = AESGCM(derived_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, data, aad)

        return salt + nonce + ciphertext_with_tag

    def decrypt(self, payload: bytes, context: Optional[str] = None) -> str:
        """Decrypt payload and verify authentication tag.

        Args:
            payload: Binary payload containing salt, nonce, and ciphertext with tag.
            context: Context string passed as AAD during encryption.

        Returns:
            Decrypted plaintext string.

        Raises:
            InvalidPayloadError: If the payload is too short.
            DecryptionFailedError: If key is wrong, tag mismatches, or context differs.
        """
        if len(payload) < self.MIN_PAYLOAD_SIZE:
            raise InvalidPayloadError(
                f"Payload size {len(payload)} bytes is less than minimum {self.MIN_PAYLOAD_SIZE} bytes"
            )

        salt = payload[: self.SALT_SIZE]
        nonce = payload[self.SALT_SIZE : self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext_with_tag = payload[self.SALT_SIZE + self.NONCE_SIZE :]

        derived_key = self._derive_key(salt)
        aad = context.encode("utf-8") if context else None

        aesgcm = AESGCM(derived_key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag as exc:
            raise DecryptionFailedError(
                "Decryption failed: invalid tag, wrong key, corrupted data, or mismatched context"
            ) from exc
        except UnicodeDecodeError as exc:
            raise DecryptionFailedError("Decrypted bytes could not be decoded as UTF-8") from exc
