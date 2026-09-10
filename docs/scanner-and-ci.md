# Shift-Left Repository Scanner & CI Gating

SecretShield includes a dedicated static code and repository scanner designed to intercept hardcoded credentials before they are committed or merged into production branches.

---

## Overview

While the runtime SecretShield proxy prevents credential sprawl in production environments, the **Shift-Left Scanner** enforces hygiene earlier in the development lifecycle (pre-commit and CI/CD).

```
[ Developer Branch ]
         │
         ▼  git push / Pull Request
+─────────────────────────────────────────────────────────+
| SecretShield CI Gatekeeper (GitHub Action / CLI)        |
|                                                         |
|  1. Parse modified lines via git diff                   |
|  2. Match against known secret provider signatures      |
|  3. Run Shannon entropy analysis on candidate tokens     |
|  4. Filter out binaries, test mock fixtures & lockfiles |
+─────────────────────────────────────────────────────────+
         │
         ├── Secrets Detected ──> ❌ Block PR & Output Remediation
         │                           `secretshield vault set <profile>`
         │
         └── Clean Diff ────────> ✅ Pass Gate to Production Proxy
```

---

## Detection Rules & Provider Signatures

The scanner evaluates source code against a comprehensive rule catalog:

| Rule ID | Provider / Pattern | Severity | Signature Description | Suggested Action |
| :--- | :--- | :--- | :--- | :--- |
| `SEC001` | **Stripe Secret Key** | `CRITICAL` | `sk_live_...`, `rk_live_...`, `sk_test_...` (24+ chars) | `secretshield vault set stripe` |
| `SEC002` | **OpenAI API Key** | `CRITICAL` | `sk-proj-...`, `sk-...` (32+ chars) | `secretshield vault set openai` |
| `SEC003` | **Anthropic API Key** | `CRITICAL` | `sk-ant-...` (32+ chars) | `secretshield vault set anthropic` |
| `SEC004` | **GitHub Personal Access Token** | `CRITICAL` | `ghp_...`, `gho_...`, `ghu_...`, `ghs_...` (36 chars) | `secretshield vault set github` |
| `SEC005` | **AWS Access Key ID** | `HIGH` | `AKIA...`, `ASIA...` (16 chars) | Store in Vault or environment |
| `SEC006` | **Google API Key** | `HIGH` | `AIza...` (35 chars) | `secretshield vault set google` |
| `SEC007` | **Slack Token** | `HIGH` | `xoxb-...`, `xoxp-...`, `xoxr-...` (24+ chars) | `secretshield vault set slack` |
| `SEC008` | **Slack Incoming Webhook** | `HIGH` | `https://hooks.slack.com/services/T.../B.../...` | Use SecretShield webhook proxy |
| `SEC009` | **Private Key Block** | `CRITICAL` | `-----BEGIN (RSA\|OPENSSH\|PGP) PRIVATE KEY-----` | Store in Vault or cloud KMS |
| `SEC010` | **Database Credentials** | `CRITICAL` | Embedded URI passwords (`postgres://user:pass@host`) | Use SecretShield credential injection |
| `SEC011` | **Generic JWT** | `MEDIUM` | Raw base64 JSON Web Tokens | Use short-lived SecretShield tokens |
| `SEC_ENTROPY` | **High-Entropy Token** | `HIGH` | Unclassified strings with Shannon entropy ≥ 4.6 | Verify if random key or password |

---

## Ignore Management & Noise Reduction

To maintain near-zero false positive rates, the scanner automatically ignores:

1. **Virtual Environments & Dependencies**: `.venv/`, `venv/`, `node_modules/`, `site-packages/`.
2. **Version Control & IDEs**: `.git/`, `.idea/`, `.vscode/`.
3. **Build Artifacts & Caches**: `dist/`, `build/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`.
4. **Lockfiles**: `uv.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Cargo.lock`.
5. **Binary Files & Assets**: `.png`, `.jpg`, `.pdf`, `.zip`, `.woff`, `.exe`, `.pyc`, `.db`, `.sqlite`.
6. **Custom Patterns**: Pass `--ignore-path <pattern>` or `-i <pattern>` to exclude test fixture directories.

---

## CLI Command Reference

### Basic Scan
Scan all files in the current working directory:
```bash
secretshield scan .
```

### Git Diff Scanning (Pull Requests)
Scan only lines modified relative to a target branch:
```bash
secretshield scan . --against origin/main
```

### Output Formats
- **`table`** (default): Colored Rich console table with location, masked secret, and remediation hint.
- **`json`**: Structured JSON payload containing counts, file paths, line numbers, and findings.
- **`github`**: Markdown table designed for `$GITHUB_STEP_SUMMARY` and workflow error annotations.

### Exit Codes
- `0`: Scan passed (no hardcoded secrets detected, or `--no-fail` was supplied).
- `1`: Scan failed (one or more secrets detected and `--fail-on-findings` is active).

---

## GitHub Action Reference

SecretShield provides a standalone GitHub Action (`alexandrmotologa/secretshield@v1`) published on GitHub Marketplace.

### Workflow Example

```yaml
name: SecretShield Guard

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  secret-scan:
    name: Repository Secret Scanner
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run SecretShield Scanner
        uses: alexandrmotologa/secretshield@v1
        with:
          against: origin/main
          entropy: 'true'
          fail-on-findings: 'true'
```
