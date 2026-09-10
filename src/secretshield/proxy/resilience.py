"""Resilience patterns: Circuit breaker and retry mechanics."""

import time
from enum import Enum


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    """Raised when an upstream circuit is open due to repeated failures."""


class CircuitBreaker:
    """Per-profile circuit breaker tracking failures and protecting microservices."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_success_threshold: int = 2,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_success_threshold = half_open_success_threshold

        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._last_state_change = time.monotonic()

    @property
    def state(self) -> CircuitState:
        """Evaluate and return current state considering recovery timeout."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_state_change
            if elapsed >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._consecutive_successes = 0
                self._last_state_change = time.monotonic()
        return self._state

    def check_can_execute(self) -> None:
        """Raise CircuitBreakerOpenError if circuit is open."""
        if self.state == CircuitState.OPEN:
            raise CircuitBreakerOpenError(
                "Upstream circuit is OPEN due to repeated errors. Failing fast."
            )

    def record_success(self) -> None:
        """Record a successful upstream request."""
        if self._state == CircuitState.HALF_OPEN:
            self._consecutive_successes += 1
            if self._consecutive_successes >= self.half_open_success_threshold:
                self._state = CircuitState.CLOSED
                self._consecutive_failures = 0
                self._last_state_change = time.monotonic()
        else:
            self._consecutive_failures = 0

    def record_failure(self) -> None:
        """Record a failed upstream request (network failure or 5xx response)."""
        self._consecutive_failures += 1
        self._last_state_change = time.monotonic()
        if (
            self._state == CircuitState.HALF_OPEN
            or self._consecutive_failures >= self.failure_threshold
        ):
            self._state = CircuitState.OPEN


class CircuitBreakerRegistry:
    """Registry maintaining circuit breakers per profile."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, profile_name: str) -> CircuitBreaker:
        """Get or create circuit breaker for profile."""
        if profile_name not in self._breakers:
            self._breakers[profile_name] = CircuitBreaker(
                failure_threshold=self.failure_threshold,
                recovery_timeout=self.recovery_timeout,
            )
        return self._breakers[profile_name]
