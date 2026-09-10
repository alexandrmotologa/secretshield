# Secret redactor and data masking

The secret redactor inspects outgoing response logs and error payloads to prevent accidental leaks of authentication keys and cardholder data.

## Redaction pipeline

The redactor runs in streaming pipelines with three validation stages:

1. Pattern matching: Fast regex targeting known provider token prefixes:
   - Stripe keys: `sk_live_[0-9a-zA-Z]{24,}`
   - OpenAI keys: `sk-(?:proj-)?[0-9a-zA-Z-_]{32,}`
   - GitHub tokens: `ghp_[0-9a-zA-Z]{36}`, `gho_[0-9a-zA-Z]{36}`
   - AWS access keys: `AKIA[0-9A-Z]{16}`
   - Bearer tokens: `Bearer [a-zA-Z0-9._-]{20,}`

2. Payment Card (PAN) verification with Luhn algorithm:
   Plain 16-digit regexes produce false positives against database IDs and order numbers. When a 13 to 19 digit number matches card prefix patterns (Visa, Mastercard, Amex), the redactor executes a Luhn checksum calculation:
   - If the checksum passes, the number is replaced with `[REDACTED_CARD_ending_in_XXXX]`.
   - If the checksum fails, the string is left untouched.

3. Shannon entropy detection:
   Random tokens without explicit prefixes (such as database passwords or session secrets) exhibit high Shannon entropy (typically > 4.5 bits per character for base64 or hex strings of 24+ characters). High-entropy tokens in query strings and header values are flagged and masked with `[REDACTED_HIGH_ENTROPY]`.

## Performance characteristics

The redactor uses pre-compiled regular expressions and skips binary payloads (such as images, PDFs, or gzip-encoded content without Content-Type text/json). It processes standard JSON response bodies in under 0.5 milliseconds.

## Shared Core with Shift-Left Scanner

The pattern recognition algorithms and Shannon entropy calculations defined in the redactor are also utilized by the `secretshield scan` engine. This ensures consistent detection logic between pre-commit static analysis and runtime traffic inspection. See [Shift-Left Scanner Documentation](scanner-and-ci.md) for full details.

