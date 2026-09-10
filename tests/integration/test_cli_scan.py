"""Integration tests for SecretShield CLI scan command."""

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from secretshield.cli import app

runner = CliRunner()


def test_cli_scan_clean_directory():
    """Verify clean directory scan exits with 0 and prints success."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "app.py").write_text("def hello(): return 'clean'", encoding="utf-8")

        res = runner.invoke(app, ["scan", str(tmp_path)])
        assert res.exit_code == 0
        assert "No secrets detected" in res.stdout


def test_cli_scan_findings_fails_by_default():
    """Verify hardcoded secret detection causes exit code 1."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        dummy_stripe = "sk_test_" + "1234567890abcdef1234567890"
        (tmp_path / "secrets.py").write_text(
            f'STRIPE_KEY = "{dummy_stripe}"\n',
            encoding="utf-8",
        )

        res = runner.invoke(app, ["scan", str(tmp_path)])
        assert res.exit_code == 1
        assert "Found 1 potential secret" in res.stdout
        assert "Stripe Secret Key" in res.stdout


def test_cli_scan_no_fail_flag():
    """Verify --no-fail flag exits with 0 even when secrets exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "secrets.py").write_text(
            'OPENAI_KEY = "sk-proj-1234567890abcdef1234567890abcdef12"\n',
            encoding="utf-8",
        )

        res = runner.invoke(app, ["scan", str(tmp_path), "--no-fail"])
        assert res.exit_code == 0
        assert "Found 1 potential secret" in res.stdout


def test_cli_scan_json_format():
    """Verify --format json outputs valid JSON payload."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "config.js").write_text(
            'const slack = "xoxb-123456789012-1234567890123-abcdef123456";\n',
            encoding="utf-8",
        )

        res = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--no-fail"])
        assert res.exit_code == 0
        data = json.loads(res.stdout)
        assert data["total_findings"] == 1
        assert data["findings"][0]["rule_name"] == "Slack Token"


def test_cli_scan_github_format_with_output_file():
    """Verify --format github writes markdown summary and annotations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "auth.py").write_text(
            'GH_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n',
            encoding="utf-8",
        )
        out_file = tmp_path / "summary.md"

        res = runner.invoke(
            app,
            ["scan", str(tmp_path), "--format", "github", "--output", str(out_file), "--no-fail"],
        )
        assert res.exit_code == 0
        assert "::error file=" in res.stdout

        summary_content = out_file.read_text(encoding="utf-8")
        assert "### :rotating_light: SecretShield Security Alert" in summary_content
        assert "GitHub Personal Access Token" in summary_content
