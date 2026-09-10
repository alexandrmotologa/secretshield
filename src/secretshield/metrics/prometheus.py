"""Prometheus metrics collector and text exposition format generator."""

from collections import defaultdict
from typing import Dict, Tuple


class PrometheusRegistry:
    """Collects runtime metrics and formats them in standard Prometheus exposition syntax."""

    def __init__(self):
        # (service_id, profile, status_code) -> count
        self._requests_total: Dict[Tuple[str, str, int], int] = defaultdict(int)
        # (service_id, profile) -> cost_usd
        self._cost_total: Dict[Tuple[str, str], float] = defaultdict(float)
        # profile -> (count, sum_seconds)
        self._latency: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, 0.0))

    def record_request(
        self,
        service_id: str,
        profile_name: str,
        status_code: int,
        latency_ms: float,
        cost_usd: float,
    ) -> None:
        """Record telemetry for a proxied request."""
        self._requests_total[(service_id, profile_name, status_code)] += 1
        self._cost_total[(service_id, profile_name)] += cost_usd

        count, total_sec = self._latency[profile_name]
        self._latency[profile_name] = (count + 1, total_sec + (latency_ms / 1000.0))

    def render_prometheus_text(
        self,
        budget_limiter=None,
        circuit_registry=None,
        cache=None,
    ) -> str:
        """Generate Prometheus exposition text format."""
        lines = []

        # 1. Total Requests
        lines.append("# HELP secretshield_requests_total Total number of proxied HTTP requests.")
        lines.append("# TYPE secretshield_requests_total counter")
        for (sid, prof, status), count in sorted(self._requests_total.items()):
            lines.append(
                f'secretshield_requests_total{{service_id="{sid}",profile="{prof}",status="{status}"}} {count}'
            )

        # 2. Total Cost
        lines.append(
            "# HELP secretshield_cost_usd_total Cumulative cost in USD of external API calls."
        )
        lines.append("# TYPE secretshield_cost_usd_total counter")
        for (sid, prof), cost in sorted(self._cost_total.items()):
            lines.append(
                f'secretshield_cost_usd_total{{service_id="{sid}",profile="{prof}"}} {cost:.6f}'
            )

        # 3. Request Latency
        lines.append(
            "# HELP secretshield_request_duration_seconds Latency summary of proxied requests."
        )
        lines.append("# TYPE secretshield_request_duration_seconds summary")
        for prof, (count, sum_sec) in sorted(self._latency.items()):
            lines.append(f'secretshield_request_duration_seconds_count{{profile="{prof}"}} {count}')
            lines.append(
                f'secretshield_request_duration_seconds_sum{{profile="{prof}"}} {sum_sec:.4f}'
            )

        # 4. Budget Ratio
        if budget_limiter:
            lines.append(
                "# HELP secretshield_budget_daily_consumed_ratio Ratio of daily budget spent (0.0 - 1.0)."
            )
            lines.append("# TYPE secretshield_budget_daily_consumed_ratio gauge")
            for sid, budget in budget_limiter._budgets.items():
                metrics = budget_limiter.get_metrics(sid)
                ratio = metrics.get("daily_percent", 0.0) / 100.0
                lines.append(
                    f'secretshield_budget_daily_consumed_ratio{{service_id="{sid}"}} {ratio:.4f}'
                )

        # 5. Circuit Breaker States
        if circuit_registry:
            lines.append(
                "# HELP secretshield_circuit_breaker_open Whether the circuit is currently open (1=open, 0=closed)."
            )
            lines.append("# TYPE secretshield_circuit_breaker_open gauge")
            for prof, breaker in circuit_registry._breakers.items():
                is_open = 1 if breaker.state.value == "open" else 0
                lines.append(f'secretshield_circuit_breaker_open{{profile="{prof}"}} {is_open}')

        # 6. Cache Hits & Misses
        if cache:
            lines.append("# HELP secretshield_cache_hits_total Number of cache hits.")
            lines.append("# TYPE secretshield_cache_hits_total counter")
            lines.append(f"secretshield_cache_hits_total {cache.hits}")
            lines.append("# HELP secretshield_cache_misses_total Number of cache misses.")
            lines.append("# TYPE secretshield_cache_misses_total counter")
            lines.append(f"secretshield_cache_misses_total {cache.misses}")

        return "\n".join(lines) + "\n"
