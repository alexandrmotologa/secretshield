"""Live Rich terminal dashboard application."""

import asyncio

import httpx
from rich.console import Console
from rich.layout import Layout
from rich.live import Live

from secretshield.tui.widgets import (
    make_budgets_panel,
    make_header_panel,
    make_requests_table,
    make_security_alerts_panel,
)


def create_dashboard_layout() -> Layout:
    """Construct split-screen layout."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="body", ratio=1),
    )
    layout["body"].split_row(
        Layout(name="stream", ratio=6),
        Layout(name="sidebar", ratio=4),
    )
    layout["sidebar"].split_column(
        Layout(name="budgets", ratio=5),
        Layout(name="alerts", ratio=5),
    )
    return layout


async def run_dashboard(proxy_url: str = "http://127.0.0.1:8000"):
    """Run interactive live TUI dashboard polling the running proxy."""
    console = Console()
    layout = create_dashboard_layout()

    async with httpx.AsyncClient(timeout=2.0) as client:
        with Live(layout, console=console, refresh_per_second=4, screen=True):
            while True:
                try:
                    resp = await client.get(f"{proxy_url}/admin/metrics")
                    if resp.status_code == 200:
                        data = resp.json()
                        events = data.get("recent_events", [])
                        budgets = data.get("budgets", {})
                    else:
                        events = []
                        budgets = {}
                except Exception:
                    events = []
                    budgets = {}

                layout["header"].update(
                    make_header_panel("127.0.0.1", 8000, profile_count=len(budgets))
                )
                layout["stream"].update(make_requests_table(events))
                layout["budgets"].update(make_budgets_panel(budgets))
                layout["alerts"].update(make_security_alerts_panel(events))

                await asyncio.sleep(0.5)
