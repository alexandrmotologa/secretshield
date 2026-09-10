"""Command-line interface for SecretShield."""

import asyncio
import sys

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from secretshield.audit.logger import AuditLogger
from secretshield.audit.verifier import AuditChainVerifier
from secretshield.config import settings
from secretshield.policy.authenticator import TokenAuthenticator
from secretshield.vault.cipher import VaultCipher
from secretshield.vault.store import InjectionType, VaultStore

app = typer.Typer(
    name="secretshield",
    help="Zero-Trust outbound credential proxy and dynamic token broker",
    add_completion=False,
)

vault_app = typer.Typer(name="vault", help="Manage encrypted credential profiles")
token_app = typer.Typer(name="token", help="Issue and manage internal service tokens")
audit_app = typer.Typer(name="audit", help="Inspect and verify the hash-chained audit ledger")

app.add_typer(vault_app)
app.add_typer(token_app)
app.add_typer(audit_app)

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

        # Start uvicorn server in child process
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
        uvicorn.run(
            "secretshield.server:app", host=host, port=port, log_level=settings.log_level.lower()
        )


@vault_app.command("set")
def vault_set(
    name: str = typer.Argument(..., help="Unique profile name (e.g. 'stripe', 'openai')"),
    base_url: str = typer.Option(..., "--base-url", "-u", help="Upstream API base URL"),
    secret: str = typer.Option(..., "--secret", "-s", help="Plaintext secret to encrypt and store"),
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

    async def _do_set():
        profile = await store.set_profile(
            name=name,
            base_url=base_url,
            secret=secret,
            injection_type=injection_type,
            header_name=header_name,
            header_prefix=header_prefix,
            query_param=query_param,
        )
        return profile

    profile = asyncio.run(_do_set())
    console.print(
        f"[green]✓ Profile '{profile.name}' stored successfully with AES-256-GCM encryption![/green]"
    )
    console.print(f"  Target: {profile.base_url}")
    console.print(f"  Injection: {profile.injection_type.value} -> {profile.header_name}")


@vault_app.command("list")
def vault_list():
    """List all stored credential profiles with masked secrets."""
    store = get_vault_store()

    async def _do_list():
        return await store.list_profiles()

    profiles = asyncio.run(_do_list())
    if not profiles:
        console.print(
            "[yellow]No credential profiles stored yet. Run 'secretshield vault set' to add one.[/yellow]"
        )
        return

    table = Table(title="Encrypted Credential Profiles", border_style="cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Base URL", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Header / Param")
    table.add_column("Secret Preview", style="green")
    table.add_column("Updated At", style="dim")

    for p in profiles:
        hp = (
            f"{p.header_name} ({p.header_prefix})"
            if p.injection_type != InjectionType.QUERY
            else f"?{p.query_param}="
        )
        table.add_row(
            p.name, p.base_url, p.injection_type.value, hp, p.secret_preview, p.updated_at[:19]
        )

    console.print(table)


@vault_app.command("delete")
def vault_delete(name: str = typer.Argument(..., help="Profile name to remove")):
    """Delete a profile from the encrypted vault."""
    store = get_vault_store()

    async def _do_del():
        return await store.delete_profile(name)

    deleted = asyncio.run(_do_del())
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
    console.print("\n[bold]Token:[/bold]")
    console.print(f"[yellow]{token}[/yellow]\n")
    console.print("Pass this token in HTTP requests using header:")
    console.print(f"[dim]X-Service-Id: {service_id}[/dim]")
    console.print(f"[dim]X-Service-Token: {token}[/dim]")


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
    table.add_column("Latency", width=10, justify="right")
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
            f"{r.latency_ms:.1f}ms",
            f"${r.cost_usd:.4f}",
            r.record_hash[:8] + "...",
        )

    console.print(table)


if __name__ == "__main__":
    app()
