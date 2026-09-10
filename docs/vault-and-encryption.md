# Vault and envelope encryption

SecretShield protects stored API keys and credentials using authenticated envelope encryption with AES-256-GCM.

## Key derivation

The system requires a 256-bit (32-byte) master key supplied via the `SECRETSHIELD_MASTER_KEY` environment variable.

For each encrypted secret, the cipher generates a cryptographically secure random 16-byte salt and derives a dedicated encryption key using HKDF (HMAC-based Key Derivation Function) with SHA-256:

- Hash algorithm: SHA-256
- Salt length: 16 bytes (randomly generated per secret)
- Info field: `secretshield-vault-v1`
- Derived key length: 32 bytes (256 bits)

## Encryption algorithm

The vault uses AES-256 in Galois/Counter Mode (GCM):

- Initialization Vector (IV/Nonce): 12 bytes generated with `os.urandom(12)`.
- Authentication Tag: 16 bytes produced by GCM.
- Additional Authenticated Data (AAD): The profile identifier is bound to the ciphertext as AAD. This prevents an attacker from swapping ciphertext blocks between different profiles.

The resulting binary payload stores the concatenation of:
`[salt (16 bytes) | nonce (12 bytes) | tag (16 bytes) | ciphertext (variable)]`
encoded as base64 or stored as a BLOB in SQLite.

## Storage schema

Credential profiles are stored in SQLite table `vault_profiles`:

```sql
CREATE TABLE IF NOT EXISTS vault_profiles (
    name TEXT PRIMARY KEY,
    base_url TEXT NOT NULL,
    injection_type TEXT NOT NULL,       -- "bearer", "header", "basic"
    header_name TEXT NOT NULL,          -- e.g. "Authorization" or "X-Api-Key"
    header_prefix TEXT DEFAULT '',      -- e.g. "Bearer "
    encrypted_secret BLOB NOT NULL,
    metadata JSON DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Security guarantees

- Confidentiality: Secrets cannot be decrypted without the master key.
- Integrity: GCM verifies that ciphertext has not been altered. Any bit flip causes decryption to fail.
- Context binding: Binding profile name via AAD ensures ciphertext cannot be copied to overwrite another profile.
