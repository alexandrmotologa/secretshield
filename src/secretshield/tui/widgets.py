"""Rich UI widgets for SecretShield live terminal dashboard."""

from typing import Any

from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text


def make_header_panel(host: str, port: int, profile_count: int) -> Panel:
    """Render top status header."""
    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left", ratio=1)
    header_table.add_column(justify="right", ratio=1)

    title = Text("🛡️  SECRETSHIELD — Zero-Trust Credential Broker", style="bold cyan")
    status = Text(
        f"Listening on {host}:{port} | Active Profiles: {profile_count} | AES-256-GCM: Active",
        style="green",
    )

    header_table.add_row(title, status)
    return Panel(header_table, border_style="cyan")


def make_requests_table(events: list[dict[str, Any]]) -> Table:
    """Render table of recent proxied requests."""
    table = Table(
        title="Live Request Stream",
        expand=True,
        border_style="bright_blue",
        header_style="bold bright_white on blue",
    )
    table.add_column("Time", width=10)
    table.add_column("Service ID", width=16)
    table.add_column("Profile", width=14)
    table.add_column("Method", width=8)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Latency", width=10, justify="right")
    table.add_column("Cost", width=10, justify="right")

    if not events:
        table.add_row("--:--:--", "Waiting for calls", "-", "-", "-", "-", "-")
        return table

    for ev in events[-15:]:
        status = ev.get("status", 200)
        status_style = "green" if status < 400 else ("yellow" if status < 500 else "bold red")

        latency = f"{ev.get('latency_ms', 0):.1f} ms"
        cost = f"${ev.get('cost_usd', 0.0):.4f}"

        table.add_row(
            ev.get("timestamp", "--:--:--"),
            ev.get("service_id", "unknown"),
            ev.get("profile", "-"),
            ev.get("method", "GET"),
            Text(str(status), style=status_style),
            latency,
            cost,
        )

    return table


def make_budgets_panel(budgets_dict: dict[str, dict[str, float]]) -> Panel:
    """Render daily and hourly budget usage per service."""
    if not budgets_dict:
        return Panel(
            Text(
                "No active service quotas configured.\nRun 'secretshield policy set' to assign limits.",
                style="dim",
            ),
            title="Service Budgets & Quotas",
            border_style="magenta",
        )

    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(ratio=2)
    table.add_column(ratio=3)

    for service_id, metrics in budgets_dict.items():
        daily_spent = metrics.get("daily_spent", 0.0)
        daily_limit = metrics.get("daily_limit", 100.0)
        daily_pct = metrics.get("daily_percent", 0.0)

        label = Text(f"{service_id}\n${daily_spent:.2f} / ${daily_limit:.2f}", style="bold white")
        bar_color = "green" if daily_pct < 70 else ("yellow" if daily_pct < 90 else "red")
        bar = ProgressBar(total=100.0, completed=daily_pct, style=bar_color)

        table.add_row(label, bar)
        table.add_row("", Text(f"{daily_pct:.1f}% daily limit consumed", style="dim"))

    return Panel(table, title="Service Budgets & Quotas", border_style="magenta")


def make_security_alerts_panel(events: list[dict[str, Any]]) -> Panel:
    """Display unauthorized access attempts and quota limit breaches."""
    alerts = [ev for ev in events if ev.get("status") in (401, 403, 429)][-6:]

    if not alerts:
        content = Text(
            "✅ Zero Security Violations Detected\nNo blocked requests or quota overages.",
            style="green",
        )
    else:
        table = Table.grid(expand=True)
        table.add_column(width=10)
        table.add_column()

        for alert in alerts:
            status = alert.get("status")
            badge = (
                "[AUTH FAIL]"
                if status == 401
                else ("[FORBIDDEN]" if status == 403 else "[QUOTA BLOCK]")
            )
            color = "bold yellow" if status == 429 else "bold red"
            msg = f"{badge} {alert.get('service_id')} -> {alert.get('profile')}: {alert.get('detail', '')}"
            table.add_row(Text(alert.get("timestamp", ""), style="dim"), Text(msg, style=color))
        content = table

    return Panel(content, title="Security & Quota Alerts", border_style="red")
