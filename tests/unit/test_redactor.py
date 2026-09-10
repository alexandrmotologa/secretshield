"""Unit tests for SecretRedactor, Luhn algorithm, and Shannon entropy masking."""

from secretshield.proxy.redactor import (
    SecretRedactor,
    calculate_shannon_entropy,
    is_luhn_valid,
)


def test_luhn_algorithm():
    """Verify Luhn checksum accurately identifies valid cards and rejects invalid numbers."""
    # Standard test card numbers (valid Luhn)
    assert is_luhn_valid("4532015112830366") is True
    assert is_luhn_valid("4532015112830367") is False

    # Random order numbers / phone numbers should fail
    assert is_luhn_valid("12345678901234") is False
    assert is_luhn_valid("10000000000000") is False


def test_redact_card_pan():
    """Verify valid credit cards are masked while non-card numbers remain unchanged."""
    text_with_card = "Customer charged with card 4532015112830366 in transaction"
    redacted = SecretRedactor.redact_text(text_with_card, check_entropy=False)
    assert "[REDACTED_CARD_****0366]" in redacted
    assert "4532015112830366" not in redacted

    # Invalid card number should NOT be redacted
    text_with_id = "Order ID 4532015112830367 processed successfully"
    assert "4532015112830367" in SecretRedactor.redact_text(text_with_id, check_entropy=False)


def test_redact_known_token_patterns():
    """Verify masking of provider tokens."""
    sample = (
        "Logs: stripe key is sk_test_abcdefghijklmnopqrstuvwxyz123456, "
        "openai key is sk-proj-1234567890abcdefghijklmnopqrstuvwxyz12, "
        "github token is ghp_1234567890abcdefghijklmnopqrstuvwxyz, "
        "aws key is AKIAIOSFODNN7EXAMPLE, "
        "bearer is Bearer abcdef1234567890abcdef1234567890"
    )
    redacted = SecretRedactor.redact_text(sample, check_entropy=False)

    assert "[REDACTED_STRIPE_KEY]" in redacted
    assert "[REDACTED_OPENAI_KEY]" in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "Bearer [REDACTED_BEARER_TOKEN]" in redacted
    assert "sk_test_" not in redacted
    assert "AKIA" not in redacted


def test_shannon_entropy_calculation():
    """Verify entropy for predictable vs random strings."""
    low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert calculate_shannon_entropy(low_entropy) == 0.0

    high_entropy = "f8b9d03a4c8e1f2b6e7a9c0d3e5f7a1b"
    assert calculate_shannon_entropy(high_entropy) > 3.5


def test_redact_high_entropy_secret():
    """Verify unexpected high entropy random tokens are masked."""
    random_secret = "dK9mQ2zL8vP1jX7bN4cT5wY6aB0eF3gH"
    text = f"Internal token: {random_secret} in payload"
    redacted = SecretRedactor.redact_text(text, check_entropy=True)
    assert "[REDACTED_HIGH_ENTROPY]" in redacted
    assert random_secret not in redacted


def test_redact_headers():
    """Verify sensitive headers are masked."""
    headers = {
        "Authorization": "Bearer some-token",
        "X-API-Key": "my-key-123",
        "Content-Type": "application/json",
    }
    clean = SecretRedactor.redact_headers(headers)
    assert clean["Authorization"] == "[REDACTED_HEADER_VALUE]"
    assert clean["X-API-Key"] == "[REDACTED_HEADER_VALUE]"
    assert clean["Content-Type"] == "application/json"


def test_redact_json_recursive():
    """Verify recursive redaction on nested JSON structures."""
    payload = {
        "user": {
            "name": "Alex",
            "card": "4532015112830366",
            "keys": ["sk_test_abcdefghijklmnopqrstuvwxyz123456"],
        },
        "count": 42,
    }
    redacted = SecretRedactor.redact_json(payload)
    assert "[REDACTED_CARD_****0366]" in redacted["user"]["card"]
    assert "[REDACTED_STRIPE_KEY]" in redacted["user"]["keys"][0]
    assert redacted["user"]["name"] == "Alex"
    assert redacted["count"] == 42
