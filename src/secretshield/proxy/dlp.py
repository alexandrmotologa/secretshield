"""Inbound Data Loss Prevention (DLP) guard protecting against PII and credential leakage."""

import re
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

from secretshield.proxy.redactor import SecretRedactor, is_luhn_valid


class DLPMode(str, Enum):
    """How the DLP guard responds to detected sensitive data."""

    AUDIT = "audit"  # Log violation but allow request unchanged
    MASK = "mask"  # Automatically sanitize payload before forwarding
    BLOCK = "block"  # Reject request immediately with HTTP 422


class DLPViolation(BaseModel):
    """Details of a single sensitive data pattern detected in inbound payload."""

    pattern_type: str
    sample_preview: str
    location: Optional[str] = None


class DLPInspectionResult(BaseModel):
    """Summary of inbound DLP scan."""

    has_violations: bool
    violations: List[DLPViolation] = Field(default_factory=list)
    sanitized_content: bytes
    blocked: bool = False
    message: Optional[str] = None


class DLPViolationError(Exception):
    """Raised when an inbound request violates DLP policy in BLOCK mode."""

    def __init__(self, violations: List[DLPViolation]):
        self.violations = violations
        super().__init__(
            f"DLP blocked request due to {len(violations)} sensitive data violation(s): "
            + ", ".join(v.pattern_type for v in violations)
        )


class InboundDLPGuard:
    """Scans microservice request bodies to prevent accidental PII/secret exfiltration to external APIs."""

    # Additional PII patterns for inbound scans (SSN, emails)
    SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    def __init__(
        self,
        default_mode: DLPMode = DLPMode.MASK,
        scan_card_pan: bool = True,
        scan_api_keys: bool = True,
        scan_ssn: bool = True,
        scan_emails: bool = False,
    ):
        self.default_mode = default_mode
        self.scan_card_pan = scan_card_pan
        self.scan_api_keys = scan_api_keys
        self.scan_ssn = scan_ssn
        self.scan_emails = scan_emails

    def inspect_payload(
        self,
        content: bytes,
        mode: Optional[DLPMode] = None,
        context: Optional[str] = None,
    ) -> DLPInspectionResult:
        """Scan inbound request bytes for sensitive data.

        Args:
            content: Raw inbound HTTP request body.
            mode: Desired enforcement mode (defaults to self.default_mode).
            context: Target profile name (e.g. 'openai-gpt4', 'stripe').

        Returns:
            DLPInspectionResult with sanitization status and violations.

        Raises:
            DLPViolationError: If mode is BLOCK and violations were discovered.
        """
        if not content:
            return DLPInspectionResult(
                has_violations=False,
                sanitized_content=content,
            )

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            # Skip non-UTF8 binary files (images, audio)
            return DLPInspectionResult(
                has_violations=False,
                sanitized_content=content,
            )

        violations: List[DLPViolation] = []
        effective_mode = mode or self.default_mode

        # 1. Scan for Payment Cards (Luhn check)
        if self.scan_card_pan:
            for match in SecretRedactor.CARD_CANDIDATE_REGEX.finditer(text):
                candidate = match.group(0)
                clean_digits = "".join(filter(str.isdigit, candidate))
                if is_luhn_valid(clean_digits):
                    violations.append(
                        DLPViolation(
                            pattern_type="CREDIT_CARD_PAN",
                            sample_preview=f"****{clean_digits[-4:]}",
                        )
                    )

        # 2. Scan for API Keys
        if self.scan_api_keys:
            for pattern, name in SecretRedactor.KNOWN_PATTERNS:
                for match in pattern.finditer(text):
                    violations.append(
                        DLPViolation(
                            pattern_type=name.strip("[]"),
                            sample_preview=match.group(0)[:8] + "...",
                        )
                    )

        # 3. Scan for US SSN numbers
        if self.scan_ssn:
            for match in self.SSN_REGEX.finditer(text):
                violations.append(
                    DLPViolation(
                        pattern_type="US_SSN",
                        sample_preview="***-**-" + match.group(0)[-4:],
                    )
                )

        # 4. Scan for email addresses if enabled
        if self.scan_emails:
            for match in self.EMAIL_REGEX.finditer(text):
                violations.append(
                    DLPViolation(
                        pattern_type="EMAIL_ADDRESS",
                        sample_preview=match.group(0)[:3] + "...@" + match.group(0).split("@")[-1],
                    )
                )

        has_violations = len(violations) > 0

        # Action handling based on mode
        if has_violations and effective_mode == DLPMode.BLOCK:
            raise DLPViolationError(violations)

        if has_violations and effective_mode == DLPMode.MASK:
            sanitized_text = SecretRedactor.redact_text(text)
            if self.scan_ssn:
                sanitized_text = self.SSN_REGEX.sub("[REDACTED_SSN]", sanitized_text)
            if self.scan_emails:
                sanitized_text = self.EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized_text)
            sanitized_bytes = sanitized_text.encode("utf-8")
        else:
            sanitized_bytes = content

        return DLPInspectionResult(
            has_violations=has_violations,
            violations=violations,
            sanitized_content=sanitized_bytes,
            blocked=False,
            message=f"Detected {len(violations)} violations" if has_violations else "Clean",
        )
