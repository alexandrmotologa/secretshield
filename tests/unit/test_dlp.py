"""Unit tests for InboundDLPGuard."""

import pytest

from secretshield.proxy.dlp import DLPMode, DLPViolationError, InboundDLPGuard


@pytest.fixture
def dlp() -> InboundDLPGuard:
    return InboundDLPGuard(default_mode=DLPMode.MASK, scan_ssn=True, scan_emails=True)


def test_dlp_clean_payload_passes(dlp: InboundDLPGuard):
    """Verify clean payload produces no violations."""
    clean_body = b'{"prompt": "Summarize the quarterly financial earnings report"}'
    result = dlp.inspect_payload(clean_body)
    assert result.has_violations is False
    assert result.sanitized_content == clean_body


def test_dlp_mask_mode_redacts_card_and_ssn(dlp: InboundDLPGuard):
    """Verify mask mode redacts card numbers and SSNs before forwarding."""
    body_with_pii = (
        b'{"prompt": "Customer account details: Card 4532015112830366 and SSN 123-45-6789"}'
    )
    result = dlp.inspect_payload(body_with_pii, mode=DLPMode.MASK)
    assert result.has_violations is True
    assert len(result.violations) == 2

    text = result.sanitized_content.decode("utf-8")
    assert "[REDACTED_CARD_****0366]" in text
    assert "[REDACTED_SSN]" in text
    assert "4532015112830366" not in text
    assert "123-45-6789" not in text


def test_dlp_block_mode_raises_violation_error(dlp: InboundDLPGuard):
    """Verify block mode stops request with DLPViolationError."""
    body_with_key = b'{"query": "Here is my stripe key: sk_test_1234567890abcdefghijklmnop"}'

    with pytest.raises(DLPViolationError) as exc_info:
        dlp.inspect_payload(body_with_key, mode=DLPMode.BLOCK)

    violations = exc_info.value.violations
    assert len(violations) >= 1
    assert any("STRIPE_KEY" in v.pattern_type for v in violations)


def test_dlp_audit_mode_logs_without_modifying(dlp: InboundDLPGuard):
    """Verify audit mode detects violations while preserving raw payload."""
    body = b'{"prompt": "Contact user at test.user@example.com"}'
    result = dlp.inspect_payload(body, mode=DLPMode.AUDIT)

    assert result.has_violations is True
    assert result.sanitized_content == body
    assert any(v.pattern_type == "EMAIL_ADDRESS" for v in result.violations)
