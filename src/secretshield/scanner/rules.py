"""Secret detection rules and finding data models for SecretShield scanner."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern


class Severity(str, Enum):
    """Finding severity level."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class RuleDefinition:
    """Definition of a secret detection rule."""

    rule_id: str
    name: str
    severity: Severity
    pattern: Pattern[str]
    remediation_hint: str
    vault_profile_hint: str


@dataclass(frozen=True)
class Finding:
    """A detected hardcoded secret candidate."""

    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    line_content: str
    masked_secret: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        """Serialize finding to dictionary for JSON output."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "line_content": self.line_content.strip(),
            "masked_secret": self.masked_secret,
            "remediation": self.remediation,
        }


def mask_token(raw_token: str, visible_chars: int = 4) -> str:
    """Mask a sensitive token showing only prefix/suffix for identification."""
    if len(raw_token) <= visible_chars * 2:
        return "*" * len(raw_token)
    return raw_token[:visible_chars] + "*" * (len(raw_token) - visible_chars * 2) + raw_token[-visible_chars:]


DEFAULT_RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="SEC001",
        name="Stripe Secret Key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        remediation_hint="Use SecretShield Vault: `secretshield vault set stripe --base-url https://api.stripe.com`",
        vault_profile_hint="stripe",
    ),
    RuleDefinition(
        rule_id="SEC002",
        name="OpenAI API Key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bsk-(?:proj-)?[0-9a-zA-Z-_]{32,}\b"),
        remediation_hint="Use SecretShield Vault: `secretshield vault set openai --base-url https://api.openai.com`",
        vault_profile_hint="openai",
    ),
    RuleDefinition(
        rule_id="SEC003",
        name="Anthropic API Key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\bsk-ant-[a-zA-Z0-9-_]{32,}\b"),
        remediation_hint="Use SecretShield Vault: `secretshield vault set anthropic --base-url https://api.anthropic.com`",
        vault_profile_hint="anthropic",
    ),
    RuleDefinition(
        rule_id="SEC004",
        name="GitHub Personal Access Token",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b"),
        remediation_hint="Use SecretShield Vault: `secretshield vault set github --base-url https://api.github.com`",
        vault_profile_hint="github",
    ),
    RuleDefinition(
        rule_id="SEC005",
        name="AWS Access Key ID",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        remediation_hint="Store AWS credentials in environment or SecretShield Vault.",
        vault_profile_hint="aws",
    ),
    RuleDefinition(
        rule_id="SEC006",
        name="Google API Key",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),
        remediation_hint="Use SecretShield Vault: `secretshield vault set google --base-url https://www.googleapis.com`",
        vault_profile_hint="google",
    ),
    RuleDefinition(
        rule_id="SEC007",
        name="Slack Token",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{24,}\b"),
        remediation_hint="Use SecretShield Vault: `secretshield vault set slack --base-url https://slack.com/api`",
        vault_profile_hint="slack",
    ),
    RuleDefinition(
        rule_id="SEC008",
        name="Slack Incoming Webhook",
        severity=Severity.HIGH,
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        remediation_hint="Use SecretShield dynamic webhook broker instead of static URLs.",
        vault_profile_hint="slack_webhook",
    ),
    RuleDefinition(
        rule_id="SEC009",
        name="Private Key Block",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        remediation_hint="Never commit private keys to git. Store in SecretShield or a key management service.",
        vault_profile_hint="private_key",
    ),
    RuleDefinition(
        rule_id="SEC010",
        name="Database Connection String with Credentials",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:]+:([^@\s\"'\\]+)@[^\s\"']+"),
        remediation_hint="Avoid hardcoding database passwords. Use environment variables or SecretShield credential injection.",
        vault_profile_hint="database",
    ),
    RuleDefinition(
        rule_id="SEC011",
        name="Generic JSON Web Token (JWT)",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        remediation_hint="Avoid committing active JWTs. Use short-lived SecretShield tokens.",
        vault_profile_hint="jwt",
    ),
]
