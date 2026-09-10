# SecretShield architecture and threat model

SecretShield acts as a reverse proxy for outbound traffic, sitting between internal microservices and external third-party APIs.

## Problem definition

In standard cloud architectures, services that talk to external APIs store API keys directly. This creates three security problems:

1. Credential distribution: If twenty services use Stripe, twenty containers hold high-privilege Stripe keys. Compromise of any one service exposes the key.
2. Log leakage: Application errors and debug traces frequently dump request headers or payload bodies into observability platforms like Datadog or CloudWatch.
3. Uncontrolled cost: A runaway worker or logic bug can loop requests, incurring large API bills before anyone notices.

## Architecture

SecretShield centralizes credential management and outbound traffic routing.

```
+---------------------+
| Microservice        |
| (No external keys)  |
+---------------------+
          |
          | 1. HTTP request with X-Service-Id and X-Service-Token
          v
+-------------------------------------------------------------+
| SecretShield Proxy                                          |
|                                                             |
|  +---------------------+    +----------------------------+  |
|  | Policy Engine       | -> | Budget Limiter             |  |
|  | Verifies caller JWT |    | Checks hourly/daily limits |  |
|  +---------------------+    +----------------------------+  |
|             |                                               |
|             v                                               |
|  +---------------------+    +----------------------------+  |
|  | Vault Engine        | -> | Injector & Forwarder       |  |
|  | Decrypts key (AES)  |    | Calls upstream external API|  |
|  +---------------------+    +----------------------------+  |
|                                         |                   |
|                                         v                   |
|  +---------------------+    +----------------------------+  |
|  | Hash-Chained Audit  | <- | Secret Redactor            |  |
|  | SHA-256 ledger      |    | Strips card PANs & tokens  |  |
|  +---------------------+    +----------------------------+  |
+-------------------------------------------------------------+
          |
          | 2. Outbound request with real API key
          v
+---------------------+
| Upstream Provider   |
| (Stripe, OpenAI...) |
+---------------------+
```

## Request lifecycle

1. A microservice sends a request to `/proxy/{profile_name}/{path}` with headers identifying the caller (`X-Service-Id`, `X-Service-Token`).
2. Authentication layer validates the caller token using HMAC SHA-256.
3. RBAC engine verifies that the caller has permission to query the requested profile and HTTP method.
4. Budget limiter checks whether the caller has remaining quota for the current sliding hour and day windows. If exhausted, it rejects the request with HTTP 429.
5. Vault engine loads the target profile and decrypts the upstream secret using AES-256-GCM.
6. Injector places the secret in the configured header (such as `Authorization: Bearer <key>`) and removes caller identity headers.
7. Forwarder streams the request to the upstream target and captures the response stream.
8. Redactor scans response metadata and body to mask credit card numbers (Luhn checked) and known API key formats.
9. Audit logger appends an immutable entry containing timestamp, caller ID, upstream endpoint, latency, status code, and the cryptographic hash of the prior entry.
10. The clean response streams back to the microservice.

## Threat model and boundaries

- Downstream trust: The connection between the microservice and SecretShield should run on an internal network or service mesh with mutual TLS when deployed in production.
- Master key isolation: The vault master key (`SECRETSHIELD_MASTER_KEY`) must be supplied through environment variable or KMS (such as AWS KMS, GCP KMS, or HashiCorp Vault). It is never stored on disk.
- Plaintext memory lifetime: Secrets are decrypted only in memory during request construction and discarded immediately afterward.
- Audit log tampering: Because each audit record includes the SHA-256 hash of the preceding record, unauthorized modifications or deletions break the hash chain and trigger validation errors during verification.

## Two-Stage Defense Architecture

SecretShield implements defense-in-depth across two distinct development stages:

1. **Pre-Production (Shift-Left CI Gating)**:
   - Command: `secretshield scan [PATH]` & GitHub Action (`alexandrmotologa/secretshield@v1`).
   - Analyzes source code and git pull request diffs for exposed credentials (API keys, private keys, database connection strings, and high-entropy secrets).
   - Blocks non-compliant pull requests before they reach the main repository branch.
   - Outputs actionable remediation guidance directing engineers to register keys in SecretShield Vault.

2. **Production (Zero-Trust Runtime Proxy)**:
   - Centralized outbound proxy handling dynamic credential injection, RBAC enforcement, budget quotas, and DLP response masking.
   - Prevents credential sprawl by eliminating long-lived credentials from microservice runtime environments entirely.

