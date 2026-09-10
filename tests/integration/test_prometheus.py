"""Integration tests for Prometheus metrics registry and text exposition."""

from secretshield.metrics.prometheus import PrometheusRegistry
from secretshield.policy.budget_limiter import BudgetLimiter, ServiceBudget
from secretshield.proxy.cache import ResponseCache
from secretshield.proxy.resilience import CircuitBreakerRegistry


def test_prometheus_render_format():
    """Verify Prometheus text format renders standard HELP, TYPE, and metric lines."""
    registry = PrometheusRegistry()
    registry.record_request(
        service_id="order-service",
        profile_name="stripe",
        status_code=200,
        latency_ms=120.0,
        cost_usd=0.30,
    )
    registry.record_request(
        service_id="order-service",
        profile_name="stripe",
        status_code=500,
        latency_ms=50.0,
        cost_usd=0.0,
    )

    budget_limiter = BudgetLimiter()
    budget_limiter.set_budget(ServiceBudget(service_id="order-service", daily_limit_usd=10.0))
    budget_limiter.record_spend("order-service", cost_usd=2.5)

    circuit_registry = CircuitBreakerRegistry()
    circuit_registry.get("stripe")

    cache = ResponseCache()
    cache.hits = 42
    cache.misses = 8

    rendered = registry.render_prometheus_text(
        budget_limiter=budget_limiter,
        circuit_registry=circuit_registry,
        cache=cache,
    )

    # Validate output lines
    assert "# HELP secretshield_requests_total" in rendered
    assert "# TYPE secretshield_requests_total counter" in rendered
    assert (
        'secretshield_requests_total{service_id="order-service",profile="stripe",status="200"} 1'
        in rendered
    )
    assert (
        'secretshield_requests_total{service_id="order-service",profile="stripe",status="500"} 1'
        in rendered
    )
    assert (
        'secretshield_cost_usd_total{service_id="order-service",profile="stripe"} 0.300000'
        in rendered
    )
    assert 'secretshield_budget_daily_consumed_ratio{service_id="order-service"} 0.2500' in rendered
    assert 'secretshield_circuit_breaker_open{profile="stripe"} 0' in rendered
    assert "secretshield_cache_hits_total 42" in rendered
    assert "secretshield_cache_misses_total 8" in rendered
