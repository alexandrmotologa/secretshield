"""Unit tests for AlertDispatcher."""

import httpx
import pytest

from secretshield.alert.dispatcher import AlertDispatcher, AlertPayload, AlertSeverity


def test_format_slack_payload():
    """Verify Slack webhook message formatting."""
    alert = AlertPayload(
        event_type="budget_warning",
        severity=AlertSeverity.WARNING,
        service_id="checkout",
        profile_name="stripe",
        message="85% budget reached",
    )
    slack_data = AlertDispatcher.format_slack_payload(alert)
    assert "attachments" in slack_data
    assert slack_data["attachments"][0]["color"] == "#F59E0B"
    assert "checkout" in str(slack_data)


def test_format_discord_payload():
    """Verify Discord webhook message formatting."""
    alert = AlertPayload(
        event_type="circuit_open",
        severity=AlertSeverity.CRITICAL,
        service_id="system",
        profile_name="openai",
        message="OpenAI upstream down",
    )
    discord_data = AlertDispatcher.format_discord_payload(alert)
    assert "embeds" in discord_data
    assert discord_data["embeds"][0]["color"] == 0xEF4444


@pytest.mark.asyncio
async def test_alert_dispatch_mock():
    """Verify dispatching calls configured webhook endpoints."""
    received = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url)
        return httpx.Response(200, json={"ok": True})

    dispatcher = AlertDispatcher(
        webhook_urls=[
            "https://hooks.slack.com/services/test/123",
            "https://custom.webhook.local/alert",
        ]
    )
    dispatcher._client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))

    try:
        sent = await dispatcher.notify_budget_warning("order-worker", 45.0, 50.0, 90.0)
        assert sent == 2
        assert len(received) == 2
    finally:
        await dispatcher.aclose()
