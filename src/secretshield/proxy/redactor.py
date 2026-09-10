"""High-speed secret redactor with Luhn algorithm and Shannon entropy checks."""

import math
import re
from typing import Any, Dict, List, Pattern, Tuple


def is_luhn_valid(card_number_str: str) -> bool:
    """Validate a card number string using the Luhn checksum algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else (doubled - 9)
        else:
            checksum += digit

    return checksum % 10 == 0


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return entropy


class SecretRedactor:
    """Detects and masks API keys, payment card numbers, and high-entropy strings."""

    # Pre-compiled regex patterns for known providers
    KNOWN_PATTERNS: List[Tuple[Pattern[str], str]] = [
        # Stripe
        (re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"), "[REDACTED_STRIPE_KEY]"),
        # OpenAI
        (re.compile(r"\bsk-(?:proj-)?[0-9a-zA-Z-_]{32,}\b"), "[REDACTED_OPENAI_KEY]"),
        # GitHub
        (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
        # AWS Access Key
        (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
        # Google API Key
        (re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
        # Slack token
        (re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{24,}\b"), "[REDACTED_SLACK_TOKEN]"),
        # Bearer token
        (re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9._-]{20,}\b"), "Bearer [REDACTED_BEARER_TOKEN]"),
        # Generic JWT
        (
            re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
            "[REDACTED_JWT_TOKEN]",
        ),
    ]

    # Regex for potential credit card numbers (13 to 19 digits, possibly hyphen/space separated)
    CARD_CANDIDATE_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    # High entropy candidate pattern (words of 24+ chars including common password/token symbols)
    HIGH_ENTROPY_CANDIDATE_REGEX = re.compile(r"(?:\b|(?<=[\s\"':=]))[A-Za-z0-9+/=_\-\$#@!]{24,}(?:\b|(?=[\s\"',;]))")

    # Entropy threshold (standard english text is ~3.0 - 3.8, random secrets are > 4.5)
    ENTROPY_THRESHOLD = 4.6

    # Sensitive header names to mask entirely
    SENSITIVE_HEADERS = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "set-cookie",
        "cookie",
        "x-auth-token",
    }

    @classmethod
    def redact_text(cls, text: str, check_entropy: bool = True) -> str:
        """Sanitize text by replacing card PANs, known keys, and high-entropy secrets."""
        if not text:
            return ""

        # 1. Mask known token patterns
        for pattern, replacement in cls.KNOWN_PATTERNS:
            text = pattern.sub(replacement, text)

        # 2. Mask credit card numbers with Luhn check
        def luhn_replacement(match: re.Match[str]) -> str:
            candidate = match.group(0)
            clean_digits = "".join(filter(str.isdigit, candidate))
            if is_luhn_valid(clean_digits):
                last4 = clean_digits[-4:]
                return f"[REDACTED_CARD_****{last4}]"
            return candidate

        text = cls.CARD_CANDIDATE_REGEX.sub(luhn_replacement, text)

        # 3. Shannon entropy check for unknown high-entropy secrets
        if check_entropy:
            def entropy_replacement(match: re.Match[str]) -> str:
                candidate = match.group(0)
                # Don't re-redact already replaced tags
                if candidate.startswith("[REDACTED"):
                    return candidate
                if calculate_shannon_entropy(candidate) >= cls.ENTROPY_THRESHOLD:
                    return "[REDACTED_HIGH_ENTROPY]"
                return candidate

            text = cls.HIGH_ENTROPY_CANDIDATE_REGEX.sub(entropy_replacement, text)

        return text

    @classmethod
    def redact_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive HTTP headers."""
        clean: Dict[str, str] = {}
        for key, value in headers.items():
            if key.lower() in cls.SENSITIVE_HEADERS:
                clean[key] = "[REDACTED_HEADER_VALUE]"
            else:
                clean[key] = cls.redact_text(value, check_entropy=False)
        return clean

    @classmethod
    def redact_json(cls, data: Any) -> Any:
        """Recursively redact strings inside JSON-serializable structures."""
        if isinstance(data, str):
            return cls.redact_text(data)
        elif isinstance(data, dict):
            return {k: cls.redact_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls.redact_json(item) for item in data]
        return data
