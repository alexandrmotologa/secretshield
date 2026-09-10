"""Webhook notification dispatcher for Slack, Discord, and generic incident endpoints."""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertPayload(BaseModel):
    """Structured alert message."""

    event_type: str
    severity: AlertSeverity
    service_id: str
    profile_name: str | None = None
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class AlertDispatcher:
    """Dispatches webhook notifications asynchronously to Slack, Discord, or generic endpoints."""

    def __init__(self, webhook_urls: list[str] | None = None, timeout: float = 5.0):
        self.webhook_urls = webhook_urls or []
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @staticmethod
    def format_slack_payload(alert: AlertPayload) -> dict[str, Any]:
        """Format alert payload into Slack incoming webhook block structure."""
        color = (
            "#10B981"
            if alert.severity == AlertSeverity.INFO
            else ("#F59E0B" if alert.severity == AlertSeverity.WARNING else "#EF4444")
        )
        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"🛡️ SecretShield Alert: {alert.event_type.upper()}",
                    "text": alert.message,
                    "fields": [
                        {"title": "Service", "value": alert.service_id, "short": True},
                        {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                        {"title": "Profile", "value": alert.profile_name or "N/A", "short": True},
                        {"title": "Time", "value": alert.timestamp[:19], "short": True},
                    ],
                }
            ]
        }

    @staticmethod
    def format_discord_payload(alert: AlertPayload) -> dict[str, Any]:
        """Format alert payload into Discord webhook embed structure."""
        color = (
            0x10B981
            if alert.severity == AlertSeverity.INFO
            else (0xF59E0B if alert.severity == AlertSeverity.WARNING else 0xEF4444)
        )
        return {
            "embeds": [
                {
                    "title": f"SecretShield Alert: {alert.event_type}",
                    "description": alert.message,
                    "color": color,
                    "fields": [
                        {"name": "Service", "value": alert.service_id, "inline": True},
                        {"name": "Severity", "value": alert.severity.value.upper(), "inline": True},
                        {"name": "Profile", "value": alert.profile_name or "N/A", "inline": True},
                    ],
                    "timestamp": alert.timestamp,
                }
            ]
        }

    async def dispatch(self, alert: AlertPayload) -> int:
        """Send alert to all configured webhook endpoints. Returns successful dispatch count."""
        if not self.webhook_urls:
            return 0

        client = await self._get_client()
        success_count = 0

        for url in self.webhook_urls:
            try:
                # Detect target format
                if "hooks.slack.com" in url:
                    body = self.format_slack_payload(alert)
                elif "discord.com/api/webhooks" in url:
                    body = self.format_discord_payload(alert)
                else:
                    body = alert.model_dump()

                resp = await client.post(url, json=body)
                if resp.status_code < 400:
                    success_count += 1
            except Exception:
                # Non-blocking: alert dispatch errors should not interrupt proxy operation
                pass

        return success_count

    async def notify_budget_warning(
        self, service_id: str, spent: float, limit: float, percent: float
    ):
        alert = AlertPayload(
            event_type="budget_warning",
            severity=AlertSeverity.WARNING,
            service_id=service_id,
            message=f"Service '{service_id}' reached {percent:.1f}% of limit (${spent:.2f} of ${limit:.2f})",
            details={"spent": spent, "limit": limit, "percent": percent},
        )
        return await self.dispatch(alert)

    async def notify_budget_exhausted(self, service_id: str, spent: float, limit: float):
        alert = AlertPayload(
            event_type="budget_exhausted",
            severity=AlertSeverity.CRITICAL,
            service_id=service_id,
            message=f"Service '{service_id}' has exhausted its quota (${spent:.2f} / ${limit:.2f}). Future calls blocked.",
            details={"spent": spent, "limit": limit},
        )
        return await self.dispatch(alert)

    async def notify_circuit_open(self, profile_name: str, reason: str):
        alert = AlertPayload(
            event_type="circuit_breaker_open",
            severity=AlertSeverity.CRITICAL,
            service_id="system",
            profile_name=profile_name,
            message=f"Upstream circuit for '{profile_name}' is OPEN. Failing fast to protect callers.",
            details={"reason": reason},
        )
        return await self.dispatch(alert)
