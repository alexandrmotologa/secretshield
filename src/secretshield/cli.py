"""Command-line interface for SecretShield."""

import asyncio
import sys
from pathlib import Path

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from secretshield.audit.logger import AuditLogger
from secretshield.audit.verifier import AuditChainVerifier
from secretshield.config import settings
from secretshield.policy.authenticator import TokenAuthenticator
from secretshield.vault.cipher import VaultCipher
from secretshield.vault.migration import VaultMigration
from secretshield.vault.store import InjectionType, VaultStore

app = typer.Typer(
    name="secretshield",
    help="Zero-Trust outbound credential proxy and dynamic token broker",
    add_completion=False,
)

vault_app = typer.Typer(name="vault", help="Manage encrypted credential profiles")
token_app = typer.Typer(name="token", help="Issue and manage internal service tokens")
audit_app = typer.Typer(name="audit", help="Inspect and verify the hash-chained audit ledger")
cache_app = typer.Typer(name="cache", help="Inspect and purge deterministic response cache")

app.add_typer(vault_app)
app.add_typer(token_app)
app.add_typer(audit_app)
app.add_typer(cache_app)

console = Console()


def get_vault_store() -> VaultStore:
    """Initialize VaultStore with configured master key."""
    cipher = VaultCipher(settings.master_key_bytes)
    return VaultStore(settings.vault_db_path, cipher)


@app.command()
def run(
    host: str = typer.Option(settings.host, help="Bind host address"),
    port: int = typer.Option(settings.port, help="Bind port number"),
    dashboard: bool = typer.Option(
        False, "--dashboard", "-d", help="Launch interactive Rich TUI dashboard"
    ),
):
    """Start the SecretShield proxy server."""
    if dashboard:
        import multiprocessing

        from secretshield.tui.app import run_dashboard

        server_process = multiprocessing.Process(
            target=uvicorn.run,
            args=("secretshield.server:app",),
            kwargs={"host": host, "port": port, "log_level": "warning"},
            daemon=True,
        )
        server_process.start()

        console.print(f"[green]Proxy server running on http://{host}:{port}[/green]")
        console.print("[cyan]Starting live TUI dashboard...[/cyan]")
        try:
            asyncio.run(run_dashboard(f"http://{host}:{port}"))
        except KeyboardInterrupt:
            server_process.terminate()
            console.print("\n[yellow]SecretShield shut down cleanly.[/yellow]")
    else:
        console.print(
            f"[bold cyan]🛡️ Starting SecretShield proxy on http://{host}:{port}[/bold cyan]"
        )
        console.print(f"[dim]Web Control Plane available at http://{host}:{port}/ui[/dim]")
        uvicorn.run(
            "secretshield.server:app", host=host, port=port, log_level=settings.log_level.lower()
        )


@app.command("ui")
def open_ui(
    host: str = typer.Option(settings.host, help="Host address"),
    port: int = typer.Option(settings.port, help="Port number"),
):
    """Print the Web Dashboard URL and open in browser."""
    url = f"http://{host}:{port}/ui"
    console.print(
        f"[bold green]🌐 SecretShield Web Dashboard:[/bold green] [underline cyan]{url}[/underline cyan]"
    )
    import webbrowser

    webbrowser.open(url)


@vault_app.command("set")
def vault_set(
    name: str = typer.Argument(..., help="Unique profile name (e.g. 'stripe', 'openai')"),
    base_url: str = typer.Option(..., "--base-url", "-u", help="Upstream API base URL"),
    secret: str = typer.Option(..., "--secret", "-s", help="Plaintext secret to encrypt and store"),
    domains: str | None = typer.Option(
        None, "--domains", "-d", help="Comma-separated domains for transparent proxying"
    ),
    injection_type: InjectionType = typer.Option(
        InjectionType.BEARER, "--type", "-t", help="Injection type: bearer, header, basic, query"
    ),
    header_name: str = typer.Option(
        "Authorization", "--header-name", help="HTTP header to inject into"
    ),
    header_prefix: str = typer.Option(
        "Bearer ", "--header-prefix", help="Prefix for header secret"
    ),
    query_param: str | None = typer.Option(
        None, "--query-param", help="Query parameter name if type is query"
    ),
):
    """Encrypt and store an upstream API secret profile."""
    store = get_vault_store()
    domain_list = [d.strip() for d in domains.split(",")] if domains else None

    async def _do_set():
        return await store.set_profile(
            name=name,
            base_url=base_url,
            secret=secret,
            domains=domain_list,
            injection_type=injection_type,
            header_name=header_name,
            header_prefix=header_prefix,
            query_param=query_param,
        )

    profile = asyncio.run(_do_set())
    console.print(
        f"[green]✓ Profile '{profile.name}' stored successfully with AES-256-GCM encryption![/green]"
    )
    console.print(f"  Target: {profile.base_url}")
    if profile.domains:
        console.print(f"  Domains: {', '.join(profile.domains)}")


@vault_app.command("rotate")
def vault_rotate(
    name: str = typer.Argument(..., help="Profile name to rotate"),
    secret: str = typer.Option(..., "--secret", "-s", help="New plaintext secret"),
):
    """Rotate secret with zero downtime, preserving previous secret for fallback."""
    store = get_vault_store()

    async def _do_rotate():
        return await store.rotate_secret(name, secret)

    try:
        profile = asyncio.run(_do_rotate())
        console.print(
            f"[bold green]✓ Secret for '{name}' rotated to v{profile.version}![/bold green]"
        )
        console.print("[dim]Previous key retained in vault as fallback during transition.[/dim]")
    except Exception as exc:
        console.print(f"[bold red]Error rotating secret:[/bold red] {exc}")
        sys.exit(1)


@vault_app.command("export")
def vault_export(
    output: Path = typer.Option(
        Path("./vault-backup.enc"), "--output", "-o", help="Backup file destination"
    ),
    passphrase: str = typer.Option(
        ..., "--passphrase", "-p", prompt=True, hide_input=True, help="Backup password"
    ),
):
    """Export encrypted vault backup archive."""
    store = get_vault_store()
    try:
        count = asyncio.run(VaultMigration.export_vault(store, passphrase, output))
        console.print(
            f"[bold green]✓ Exported {count} profile(s) to encrypted backup file '{output}'![/bold green]"
        )
    except Exception as exc:
        console.print(f"[bold red]Export failed:[/bold red] {exc}")
        sys.exit(1)


@vault_app.command("import")
def vault_import(
    input_file: Path = typer.Option(..., "--input", "-i", help="Backup file to import"),
    passphrase: str = typer.Option(
        ..., "--passphrase", "-p", prompt=True, hide_input=True, help="Backup password"
    ),
):
    """Decrypt and import profiles from encrypted backup archive."""
    store = get_vault_store()
    try:
        count = asyncio.run(VaultMigration.import_vault(store, passphrase, input_file))
        console.print(
            f"[bold green]✓ Successfully imported {count} profile(s) into vault![/bold green]"
        )
    except Exception as exc:
        console.print(f"[bold red]Import failed:[/bold red] {exc}")
        sys.exit(1)


@vault_app.command("list")
def vault_list():
    """List all stored credential profiles with masked secrets."""
    store = get_vault_store()
    profiles = asyncio.run(store.list_profiles())
    if not profiles:
        console.print(
            "[yellow]No credential profiles stored yet. Run 'secretshield vault set' to add one.[/yellow]"
        )
        return

    table = Table(title="Encrypted Credential Profiles", border_style="cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Base URL", style="cyan")
    table.add_column("Version", justify="center")
    table.add_column("Type", style="magenta")
    table.add_column("Secret Preview", style="green")
    table.add_column("Backup Key", justify="center")

    for p in profiles:
        has_bak = "[green]YES[/green]" if p.has_backup_key else "[dim]NO[/dim]"
        table.add_row(
            p.name, p.base_url, f"v{p.version}", p.injection_type.value, p.secret_preview, has_bak
        )

    console.print(table)


@vault_app.command("delete")
def vault_delete(name: str = typer.Argument(..., help="Profile name to remove")):
    """Delete a profile from the encrypted vault."""
    store = get_vault_store()
    deleted = asyncio.run(store.delete_profile(name))
    if deleted:
        console.print(f"[green]✓ Profile '{name}' removed from vault.[/green]")
    else:
        console.print(f"[red]Error: Profile '{name}' not found.[/red]")


@token_app.command("issue")
def token_issue(
    service_id: str = typer.Argument(..., help="Microservice ID to issue token for"),
    ttl_hours: int = typer.Option(24, "--ttl-hours", help="Token lifetime in hours"),
    scopes: str = typer.Option("*", "--scopes", help="Comma-separated permission scopes"),
):
    """Issue a short-lived internal JWT for a microservice."""
    auth = TokenAuthenticator(jwt_secret=settings.jwt_secret)
    scope_list = [s.strip() for s in scopes.split(",")]
    token = auth.issue_service_token(
        service_id=service_id, scopes=scope_list, ttl_seconds=ttl_hours * 3600
    )

    console.print(f"[bold green]✓ JWT issued for service: [white]{service_id}[/white][/bold green]")
    console.print(f"[cyan]TTL:[/cyan] {ttl_hours} hours | [cyan]Scopes:[/cyan] {scope_list}")
    console.print(f"\n[bold]Token (use in X-Service-Token header):[/bold]\n[yellow]{token}[/yellow]\n")


@audit_app.command("verify")
def audit_verify():
    """Verify cryptographic SHA-256 hash chain of the entire audit ledger."""
    console.print("[cyan]Verifying audit ledger integrity...[/cyan]")
    is_valid, err, count = asyncio.run(AuditChainVerifier.verify_chain(settings.audit_db_path))

    if is_valid:
        console.print(
            f"[bold green]✓ Audit chain is 100% VALID ({count} records verified).[/bold green]"
        )
        console.print("[dim]No tampering, missing records, or hash mismatches detected.[/dim]")
    else:
        console.print("[bold red]❌ AUDIT CHAIN COMPROMISED![/bold red]")
        console.print(f"[red]{err}[/red]")
        sys.exit(1)


@audit_app.command("tail")
def audit_tail(limit: int = typer.Option(20, "--limit", "-n", help="Number of records to display")):
    """Display the most recent audit records."""
    logger = AuditLogger(settings.audit_db_path)
    records = asyncio.run(logger.get_recent_entries(limit=limit))

    if not records:
        console.print("[yellow]Audit ledger is empty.[/yellow]")
        return

    table = Table(title=f"Recent Audit Ledger Records (Last {len(records)})", border_style="blue")
    table.add_column("ID", justify="right", width=5)
    table.add_column("Timestamp", width=19)
    table.add_column("Service ID", style="bold white")
    table.add_column("Target", style="cyan")
    table.add_column("Method", width=6)
    table.add_column("Status", width=6, justify="center")
    table.add_column("Cost", width=10, justify="right")
    table.add_column("Hash", width=10, style="dim")

    for r in records:
        status_style = (
            "green" if r.status_code < 400 else ("yellow" if r.status_code < 500 else "bold red")
        )
        table.add_row(
            str(r.id),
            r.timestamp[:19],
            r.service_id,
            f"{r.profile_name}{r.path}",
            r.method,
            f"[{status_style}]{r.status_code}[/{status_style}]",
            f"${r.cost_usd:.4f}",
            r.record_hash[:8] + "...",
        )

    console.print(table)


@cache_app.command("clear")
def cache_clear():
    """Clear in-memory response cache."""
    from secretshield.server import state

    if hasattr(state, "cache"):
        purged = state.cache.clear()
        console.print(f"[green]✓ Purged {purged} entries from response cache.[/green]")
    else:
        console.print("[yellow]Cache not active in CLI process.[/yellow]")


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(
        Path("."),
        help="Path to file or directory to scan for hardcoded secrets",
    ),
    against: str | None = typer.Option(
        None,
        "--against",
        "-a",
        help="Git branch or ref to compare against (e.g. origin/main) for scanning git diff only",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, or github",
    ),
    entropy: bool = typer.Option(
        True,
        "--entropy/--no-entropy",
        help="Enable Shannon entropy checks for high-entropy tokens",
    ),
    ignore_path: list[str] = typer.Option(
        None,
        "--ignore-path",
        "-i",
        help="Additional paths or substrings to ignore",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to write the report output to (e.g. $GITHUB_STEP_SUMMARY)",
    ),
    fail_on_findings: bool = typer.Option(
        True,
        "--fail-on-findings/--no-fail",
        help="Exit with non-zero status code if hardcoded secrets are detected",
    ),
):
    """Scan repositories, files, or git diffs for hardcoded secrets and API keys."""
    from secretshield.scanner.engine import ScanSummary, SecretScanner

    scanner = SecretScanner(
        check_entropy=entropy,
        custom_ignore_patterns=ignore_path or [],
    )

    if against:
        summary = scanner.scan_git_diff(path if path.is_dir() else path.parent, against=against)
    elif path.is_file():
        findings = scanner.scan_file(path)
        summary = ScanSummary(
            scanned_files_count=1,
            scanned_lines_count=len(path.read_text(encoding="utf-8", errors="replace").splitlines()) if path.exists() else 0,
            findings=findings,
        )
    else:
        summary = scanner.scan_directory(path)

    # Format output
    fmt = format.lower().strip()
    if fmt == "json":
        json_output = summary.to_json()
        if output:
            output.write_text(json_output, encoding="utf-8")
        else:
            print(json_output)
    elif fmt == "github":
        md_output = summary.to_github_markdown()
        annotations = summary.to_github_annotations()
        full_content = md_output
        if output:
            output.write_text(full_content, encoding="utf-8")
        else:
            print(full_content)
        # Print annotations for GitHub Actions runner log
        for ann in annotations:
            print(ann)
    else:
        # Default Rich table
        if summary.has_findings:
            console.print(summary.to_rich_table())
            console.print(
                f"[bold red]❌ Found {len(summary.findings)} potential secret(s) "
                f"({summary.critical_count} CRITICAL, {summary.high_count} HIGH)![/bold red]"
            )
            console.print(
                "[dim]Tip: Move credentials to SecretShield Vault using `secretshield vault set <profile>`.[/dim]\n"
            )
        else:
            console.print(
                f"[bold green]✓ No secrets detected in {summary.scanned_files_count} scanned file(s).[/bold green]"
            )

        if output:
            output.write_text(summary.to_github_markdown(), encoding="utf-8")

    if summary.has_findings and fail_on_findings:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()

