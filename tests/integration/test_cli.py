"""Integration tests for SecretShield CLI commands."""

from typer.testing import CliRunner

from secretshield.cli import app

runner = CliRunner()


def test_cli_help():
    """Verify top-level CLI help outputs available subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Zero-Trust outbound credential proxy" in result.stdout
    assert "vault" in result.stdout
    assert "token" in result.stdout
    assert "audit" in result.stdout


def test_cli_vault_crud():
    """Verify CLI vault set, list, and delete commands."""
    # 1. Set profile
    res_set = runner.invoke(
        app,
        [
            "vault",
            "set",
            "cli-test",
            "--base-url",
            "https://api.example.com",
            "--secret",
            "sec_test_cli_secret_key_12345",
            "--type",
            "bearer",
        ],
    )
    assert res_set.exit_code == 0
    assert "stored successfully" in res_set.stdout

    # 2. List profiles
    res_list = runner.invoke(app, ["vault", "list"])
    assert res_list.exit_code == 0
    assert "cli-test" in res_list.stdout

    # 3. Delete profile
    res_del = runner.invoke(app, ["vault", "delete", "cli-test"])
    assert res_del.exit_code == 0
    assert "removed from vault" in res_del.stdout


def test_cli_token_issue():
    """Verify issuing a microservice JWT token."""
    result = runner.invoke(app, ["token", "issue", "checkout-service", "--ttl-hours", "12"])
    assert result.exit_code == 0
    assert "JWT issued for service" in result.stdout
    assert "checkout-service" in result.stdout
    assert "X-Service-Token" in result.stdout


def test_cli_audit_verify():
    """Verify running audit verification on database."""
    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 0
    assert "Audit chain is 100% VALID" in result.stdout
