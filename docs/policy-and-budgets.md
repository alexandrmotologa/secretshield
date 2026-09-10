# Policy and budget enforcement

SecretShield enforces access control and financial spending limits before outbound requests leave the proxy.

## Caller authentication

Microservices authenticate to SecretShield using either:

1. Service tokens: Short-lived HMAC-SHA256 tokens signed by a shared secret or SecretShield key.
2. Static service keys: Configured pre-shared tokens passed in the `X-Service-Token` header alongside `X-Service-Id`.

If authentication fails, the proxy terminates the request with HTTP 401 Unauthorized without reaching the vault or external network.

## Role-based access control (RBAC)

Each service has an entry defining which profiles and HTTP methods it is permitted to invoke:

```json
{
  "service_id": "order-service",
  "allowed_profiles": ["stripe", "tax-calculator"],
  "allowed_methods": ["GET", "POST"],
  "allowed_paths": ["/v1/charges", "/v1/refunds"]
}
```

If a service attempts to invoke an unlisted profile or method, SecretShield rejects the call with HTTP 403 Forbidden.

## Budget and quota engine

Runaway loops in client code can cause substantial financial damage when calling paid APIs. SecretShield tracks usage with a sliding window budget tracker.

Budgets are configured with:
- Hourly limit in USD
- Daily limit in USD
- Maximum requests per minute (rate limit)

### Cost calculation

SecretShield calculates request costs using two strategies:

1. Static cost per request: Useful for payment processors, SMS gateways, and verification services (e.g. $0.30 fixed fee per Stripe charge).
2. Dynamic token-based pricing: For AI providers such as OpenAI and Anthropic, SecretShield inspects response headers or token consumption fields (e.g. `prompt_tokens` and `completion_tokens`) and applies model-specific pricing tables to decrement the service budget.

When a caller exhausts its budget, SecretShield responds with HTTP 429 Too Many Requests and an RFC 7807 problem details JSON payload:

```json
{
  "type": "https://secretshield.dev/errors/budget-exhausted",
  "title": "Daily Budget Exhausted",
  "status": 429,
  "detail": "Service 'order-service' has reached its daily limit of $50.00.",
  "instance": "/proxy/stripe/v1/charges",
  "reset_at": "2026-09-11T00:00:00Z"
}
```
