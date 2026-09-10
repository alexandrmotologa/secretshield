"""Cost estimation models for AI providers and fixed-fee APIs."""

from typing import Any, Dict, Optional


class CostEstimator:
    """Calculates request cost in USD based on provider pricing tables."""

    # Pricing per 1,000,000 tokens (USD)
    # [input_per_m, output_per_m]
    AI_MODELS = {
        "gpt-4o": (2.50, 10.00),
        "gpt-4o-mini": (0.15, 0.60),
        "o3-mini": (1.10, 4.40),
        "claude-3-7-sonnet": (3.00, 15.00),
        "claude-3-5-haiku": (0.80, 4.00),
    }

    # Fixed fee per successful transaction/call
    FIXED_FEES = {
        "stripe": 0.30,       # $0.30 per payment charge
        "twilio": 0.0079,     # $0.0079 per SMS
        "sendgrid": 0.001,    # $0.001 per email
    }

    DEFAULT_FALLBACK_COST = 0.0005  # $0.0005 default per proxy request

    @classmethod
    def estimate_from_response(
        cls,
        profile_name: str,
        response_json: Optional[Dict[str, Any]] = None,
        default_cost: Optional[float] = None,
    ) -> float:
        """Estimate cost from response JSON or provider defaults.

        Args:
            profile_name: Name of the target profile (e.g. 'openai', 'stripe').
            response_json: Parsed response body if available.
            default_cost: Custom fallback cost.

        Returns:
            Cost in USD.
        """
        lower_profile = profile_name.lower()

        # 1. Check for AI token usage inside OpenAI / Anthropic responses
        if response_json and isinstance(response_json, dict):
            usage = response_json.get("usage")
            model = response_json.get("model", "")

            if isinstance(usage, dict):
                prompt_tokens = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
                completion_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0

                # Match model pricing
                for known_model, (in_cost, out_cost) in cls.AI_MODELS.items():
                    if known_model in model.lower():
                        cost = (prompt_tokens / 1_000_000 * in_cost) + (
                            completion_tokens / 1_000_000 * out_cost
                        )
                        return max(cost, 0.00001)

        # 2. Check for fixed provider fee
        for provider, fee in cls.FIXED_FEES.items():
            if provider in lower_profile:
                return fee

        # 3. Fallback cost
        if default_cost is not None:
            return default_cost
        return cls.DEFAULT_FALLBACK_COST
