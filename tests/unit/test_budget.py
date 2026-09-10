"""Unit tests for BudgetLimiter and CostEstimator."""

import pytest

from secretshield.policy.budget_limiter import (
    BudgetExceededError,
    BudgetLimiter,
    RateLimitExceededError,
    ServiceBudget,
)
from secretshield.policy.cost_models import CostEstimator


def test_cost_estimator_ai_tokens():
    """Verify OpenAI token count calculates correct dollar amount."""
    response_payload = {
        "model": "gpt-4o-2024-05-13",
        "usage": {
            "prompt_tokens": 1000,  # 1000 / 1M * $2.50 = $0.0025
            "completion_tokens": 500,  # 500 / 1M * $10.00 = $0.0050
            "total_tokens": 1500,
        },
    }
    cost = CostEstimator.estimate_from_response("openai-chat", response_payload)
    assert abs(cost - 0.0075) < 0.00001


def test_cost_estimator_fixed_fees():
    """Verify fixed fees for Stripe and Twilio."""
    assert CostEstimator.estimate_from_response("stripe-charges") == 0.30
    assert CostEstimator.estimate_from_response("twilio-sms") == 0.0079
    assert CostEstimator.estimate_from_response("custom-api") == CostEstimator.DEFAULT_FALLBACK_COST


def test_budget_limiter_allows_under_quota():
    """Verify requests under budget are allowed."""
    limiter = BudgetLimiter()
    limiter.set_budget(
        ServiceBudget(
            service_id="cart-service",
            daily_limit_usd=10.0,
            hourly_limit_usd=5.0,
            rate_limit_rpm=10,
        )
    )

    # Initial check passes
    limiter.check_budget("cart-service", estimated_cost=1.0)
    limiter.record_spend("cart-service", cost_usd=1.0)

    metrics = limiter.get_metrics("cart-service")
    assert metrics["hourly_spent"] == 1.0
    assert metrics["hourly_percent"] == 20.0


def test_budget_limiter_hourly_exhaustion():
    """Verify exceeding hourly budget raises BudgetExceededError."""
    limiter = BudgetLimiter()
    limiter.set_budget(
        ServiceBudget(
            service_id="worker",
            daily_limit_usd=100.0,
            hourly_limit_usd=2.0,
            rate_limit_rpm=100,
        )
    )

    limiter.record_spend("worker", cost_usd=1.50)

    # Adding $1.00 would exceed $2.00 hourly limit
    with pytest.raises(BudgetExceededError) as exc_info:
        limiter.check_budget("worker", estimated_cost=1.0)

    assert exc_info.value.limit_type == "hourly"
    assert exc_info.value.limit_value == 2.0


def test_budget_limiter_daily_exhaustion():
    """Verify exceeding daily budget raises BudgetExceededError."""
    limiter = BudgetLimiter()
    limiter.set_budget(
        ServiceBudget(
            service_id="worker",
            daily_limit_usd=5.0,
            hourly_limit_usd=50.0,
            rate_limit_rpm=100,
        )
    )

    limiter.record_spend("worker", cost_usd=4.80)

    with pytest.raises(BudgetExceededError) as exc_info:
        limiter.check_budget("worker", estimated_cost=0.50)

    assert exc_info.value.limit_type == "daily"


def test_budget_limiter_rate_limit_rpm():
    """Verify exceeding rate limit RPM raises RateLimitExceededError."""
    limiter = BudgetLimiter()
    limiter.set_budget(
        ServiceBudget(
            service_id="fast-service",
            daily_limit_usd=100.0,
            hourly_limit_usd=100.0,
            rate_limit_rpm=3,
        )
    )

    limiter.record_spend("fast-service", 0.01)
    limiter.record_spend("fast-service", 0.01)
    limiter.record_spend("fast-service", 0.01)

    with pytest.raises(RateLimitExceededError):
        limiter.check_budget("fast-service")


def test_rfc7807_formatting():
    """Verify problem details structure meets RFC 7807 format."""
    exc = BudgetExceededError("Limit hit", limit_type="daily", limit_value=50.0, current_spend=50.1)
    problem = BudgetLimiter.format_rfc7807_problem(exc, instance_path="/proxy/stripe/charge")

    assert problem["status"] == 429
    assert problem["limit_usd"] == 50.0
    assert problem["instance"] == "/proxy/stripe/charge"
    assert "reset_at" in problem
