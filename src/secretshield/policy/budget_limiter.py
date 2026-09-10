"""Sliding-window budget limiter and rate-limiting engine."""

from collections import deque
from datetime import datetime, timezone, timedelta
import time
from typing import Dict, Optional, Tuple
from pydantic import BaseModel, Field


class BudgetExceededError(Exception):
    """Raised when a service exceeds its hourly or daily spending limit."""

    def __init__(self, message: str, limit_type: str, limit_value: float, current_spend: float):
        super().__init__(message)
        self.limit_type = limit_type
        self.limit_value = limit_value
        self.current_spend = current_spend


class RateLimitExceededError(Exception):
    """Raised when a service exceeds requests per minute."""


class ServiceBudget(BaseModel):
    """Financial budget and rate limits configured for a service."""
    service_id: str
    daily_limit_usd: float = Field(default=100.0, ge=0.0)
    hourly_limit_usd: float = Field(default=20.0, ge=0.0)
    rate_limit_rpm: int = Field(default=600, ge=1)  # 600 requests / minute default


class BudgetLimiter:
    """Tracks per-service spending and request rates over sliding time windows."""

    def __init__(self):
        self._budgets: Dict[str, ServiceBudget] = {}
        # service_id -> deque of (monotonic_timestamp, cost_usd)
        self._transactions: Dict[str, deque[Tuple[float, float]]] = {}

    def set_budget(self, budget: ServiceBudget) -> None:
        """Configure or update budget limits for a service."""
        self._budgets[budget.service_id] = budget
        if budget.service_id not in self._transactions:
            self._transactions[budget.service_id] = deque()

    def get_budget(self, service_id: str) -> Optional[ServiceBudget]:
        """Retrieve budget configuration for service."""
        return self._budgets.get(service_id)

    def _prune_old_transactions(self, service_id: str, now: float) -> deque[Tuple[float, float]]:
        """Remove transactions older than 24 hours (86,400 seconds)."""
        txs = self._transactions.get(service_id)
        if txs is None:
            txs = deque()
            self._transactions[service_id] = txs
            return txs

        cutoff_24h = now - 86400.0
        while txs and txs[0][0] < cutoff_24h:
            txs.popleft()
        return txs

    def check_budget(self, service_id: str, estimated_cost: float = 0.0) -> None:
        """Check whether the service has budget to perform the request.

        Args:
            service_id: Microservice calling the proxy.
            estimated_cost: Anticipated cost of this request.

        Raises:
            BudgetExceededError: If daily or hourly limit is exceeded.
            RateLimitExceededError: If requests-per-minute threshold is hit.
        """
        budget = self._budgets.get(service_id)
        if not budget:
            # If no explicit budget configured, default to unmetered
            return

        now = time.monotonic()
        txs = self._prune_old_transactions(service_id, now)

        cutoff_1m = now - 60.0
        cutoff_1h = now - 3600.0

        count_1m = 0
        spend_1h = 0.0
        spend_24h = 0.0

        for ts, cost in txs:
            spend_24h += cost
            if ts >= cutoff_1h:
                spend_1h += cost
            if ts >= cutoff_1m:
                count_1m += 1

        # Check RPM
        if count_1m >= budget.rate_limit_rpm:
            raise RateLimitExceededError(
                f"Rate limit exceeded for '{service_id}': max {budget.rate_limit_rpm} requests/min"
            )

        # Check Hourly Budget
        if (spend_1h + estimated_cost) > budget.hourly_limit_usd:
            raise BudgetExceededError(
                message=f"Hourly budget limit of ${budget.hourly_limit_usd:.2f} reached for '{service_id}' "
                f"(spent: ${spend_1h:.2f})",
                limit_type="hourly",
                limit_value=budget.hourly_limit_usd,
                current_spend=spend_1h,
            )

        # Check Daily Budget
        if (spend_24h + estimated_cost) > budget.daily_limit_usd:
            raise BudgetExceededError(
                message=f"Daily budget limit of ${budget.daily_limit_usd:.2f} reached for '{service_id}' "
                f"(spent: ${spend_24h:.2f})",
                limit_type="daily",
                limit_value=budget.daily_limit_usd,
                current_spend=spend_24h,
            )

    def record_spend(self, service_id: str, cost_usd: float) -> None:
        """Record an actual transaction spend for a service."""
        now = time.monotonic()
        txs = self._prune_old_transactions(service_id, now)
        txs.append((now, max(cost_usd, 0.0)))

    def get_metrics(self, service_id: str) -> Dict[str, float]:
        """Get current spending totals and percentage consumed."""
        budget = self._budgets.get(service_id)
        if not budget:
            return {
                "hourly_spent": 0.0,
                "daily_spent": 0.0,
                "hourly_limit": 0.0,
                "daily_limit": 0.0,
                "hourly_percent": 0.0,
                "daily_percent": 0.0,
            }

        now = time.monotonic()
        txs = self._prune_old_transactions(service_id, now)
        cutoff_1h = now - 3600.0

        spend_1h = sum(cost for ts, cost in txs if ts >= cutoff_1h)
        spend_24h = sum(cost for _, cost in txs)

        hourly_pct = (spend_1h / budget.hourly_limit_usd * 100.0) if budget.hourly_limit_usd > 0 else 0.0
        daily_pct = (spend_24h / budget.daily_limit_usd * 100.0) if budget.daily_limit_usd > 0 else 0.0

        return {
            "hourly_spent": spend_1h,
            "daily_spent": spend_24h,
            "hourly_limit": budget.hourly_limit_usd,
            "daily_limit": budget.daily_limit_usd,
            "hourly_percent": min(hourly_pct, 100.0),
            "daily_percent": min(daily_pct, 100.0),
        }

    @staticmethod
    def format_rfc7807_problem(exc: Exception, instance_path: str) -> Dict[str, Any]:
        """Format RFC 7807 Problem Details JSON for HTTP 429 response."""
        now_iso = datetime.now(timezone.utc).isoformat()
        reset_time = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

        if isinstance(exc, BudgetExceededError):
            return {
                "type": "https://secretshield.dev/errors/budget-exhausted",
                "title": f"{exc.limit_type.capitalize()} Budget Exhausted",
                "status": 429,
                "detail": str(exc),
                "instance": instance_path,
                "limit_usd": exc.limit_value,
                "current_spend_usd": round(exc.current_spend, 4),
                "reset_at": reset_time,
                "timestamp": now_iso,
            }
        else:
            return {
                "type": "https://secretshield.dev/errors/rate-limit-exceeded",
                "title": "Rate Limit Exceeded",
                "status": 429,
                "detail": str(exc),
                "instance": instance_path,
                "reset_at": reset_time,
                "timestamp": now_iso,
            }
