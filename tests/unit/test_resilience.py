"""Unit tests for CircuitBreaker and CircuitBreakerRegistry."""

import pytest

from secretshield.proxy.resilience import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitBreakerRegistry,
    CircuitState,
)


def test_circuit_breaker_initial_state():
    """Verify circuit breaker begins in CLOSED state and allows execution."""
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
    assert cb.state == CircuitState.CLOSED
    cb.check_can_execute()  # Should not raise


def test_circuit_breaker_trips_on_consecutive_failures():
    """Verify circuit trips to OPEN when failure threshold is exceeded."""
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)

    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN

    with pytest.raises(CircuitBreakerOpenError):
        cb.check_can_execute()


def test_circuit_breaker_recovery_to_half_open():
    """Verify circuit transitions to HALF_OPEN after recovery timeout expires."""
    import time

    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05, half_open_success_threshold=1)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN

    time.sleep(0.06)
    assert cb.state == CircuitState.HALF_OPEN

    # Success in half open closes circuit
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_circuit_breaker_registry():
    """Verify registry maintains distinct breakers per profile."""
    registry = CircuitBreakerRegistry(failure_threshold=2)
    b1 = registry.get("stripe")
    b2 = registry.get("openai")

    assert b1 is not b2
    assert registry.get("stripe") is b1
