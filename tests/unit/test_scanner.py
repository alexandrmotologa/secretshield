"""Unit tests for the SecretShield static scanner engine."""

import tempfile
from pathlib import Path

from secretshield.scanner.engine import SecretScanner
from secretshield.scanner.rules import Severity, mask_token


def test_mask_token():
    """Verify sensitive token masking."""
    assert mask_token("short") == "*****"
    token = "sk_test_" + "1234567890abcdef12345678"
    assert mask_token(token) == "sk_t************************5678"


def test_scan_text_clean():
    """Ensure clean text returns zero findings."""
    scanner = SecretScanner()
    text = "const port = 8080;\nconst appName = 'MyService';\nconsole.log('Hello World');"
    findings = scanner.scan_text(text)
    assert len(findings) == 0


def test_scan_text_stripe_key():
    """Detect hardcoded Stripe live and test keys."""
    scanner = SecretScanner()
    token = "sk_test_" + "51Mxyz1234567890abcdef1234567890"
    text = f'STRIPE_API_KEY = "{token}"'
    findings = scanner.scan_text(text)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.CRITICAL
    assert "stripe" in findings[0].remediation.lower()
    assert findings[0].line_number == 1
    assert "sk_t" in findings[0].masked_secret


def test_scan_text_openai_key():
    """Detect OpenAI project keys."""
    scanner = SecretScanner()
    text = 'openai_client = OpenAI(api_key="sk-proj-abc1234567890abcdef1234567890123456")'
    findings = scanner.scan_text(text)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC002"
    assert findings[0].severity == Severity.CRITICAL


def test_scan_text_github_token():
    """Detect GitHub Personal Access Tokens."""
    scanner = SecretScanner()
    text = 'git_token = "ghp_1234567890abcdef1234567890abcdef1234"'
    findings = scanner.scan_text(text)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"
    assert findings[0].severity == Severity.CRITICAL


def test_scan_text_private_key():
    """Detect unencrypted private key blocks."""
    scanner = SecretScanner()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    findings = scanner.scan_text(text)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC009"
    assert findings[0].severity == Severity.CRITICAL


def test_scan_text_db_credentials():
    """Detect database URIs with embedded passwords."""
    scanner = SecretScanner()
    text = 'DATABASE_URL = "postgresql://postgres:SuperSecretP@ss123@db.internal:5432/prod"'
    findings = scanner.scan_text(text)
    assert len(findings) >= 1
    assert any(f.rule_id == "SEC010" for f in findings)


def test_entropy_detection_toggle():
    """Verify high-entropy detection can be enabled and disabled."""
    # High entropy random base64 string
    high_entropy_str = 'const token = "vG8f+3/kL91mZp0wXq7nR2tY5cV8bM1aZp0=";'

    scanner_with_entropy = SecretScanner(check_entropy=True, entropy_threshold=4.5)
    findings_enabled = scanner_with_entropy.scan_text(high_entropy_str)
    assert any(f.rule_id == "SEC_ENTROPY" for f in findings_enabled)

    scanner_without_entropy = SecretScanner(check_entropy=False)
    findings_disabled = scanner_without_entropy.scan_text(high_entropy_str)
    assert len(findings_disabled) == 0


def test_ignored_paths():
    """Ensure standard non-code and binary files are skipped."""
    scanner = SecretScanner(custom_ignore_patterns=["custom_skip"])

    assert scanner.is_path_ignored(Path(".git/objects/abc"))
    assert scanner.is_path_ignored(Path(".venv/lib/site-packages/test.py"))
    assert scanner.is_path_ignored(Path("uv.lock"))
    assert scanner.is_path_ignored(Path("package-lock.json"))
    assert scanner.is_path_ignored(Path("assets/logo.png"))
    assert scanner.is_path_ignored(Path("docs/custom_skip/file.py"))
    assert not scanner.is_path_ignored(Path("src/service.py"))


def test_scan_directory_and_summary_formats():
    """Test full directory scan and serialization to JSON, Markdown, and Annotations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("print('Clean file')\n", encoding="utf-8")

        secret_file = tmp_path / "config.py"
        secret_file.write_text('API_KEY = "AIzaSyD-1234567890abcdef1234567890abcde"\n', encoding="utf-8")

        scanner = SecretScanner()
        summary = scanner.scan_directory(tmp_path)

        assert summary.scanned_files_count == 2
        assert summary.has_findings is True
        assert len(summary.findings) == 1
        assert summary.findings[0].rule_id == "SEC006"

        # Test JSON export
        json_str = summary.to_json()
        assert '"total_findings": 1' in json_str

        # Test Markdown export
        md_str = summary.to_github_markdown()
        assert "SecretShield Security Alert" in md_str
        assert "Google API Key" in md_str

        # Test GitHub Actions annotations
        annotations = summary.to_github_annotations()
        assert len(annotations) == 1
        assert "::error file=" in annotations[0]

        # Test Rich table generation
        table = summary.to_rich_table()
        assert table is not None
