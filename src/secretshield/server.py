"""FastAPI proxy application integrating auth, RBAC, budgets, vault, and audit trail."""

import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from secretshield.audit.logger import AuditLogger
from secretshield.config import settings
from secretshield.policy.authenticator import AuthenticationError, TokenAuthenticator
from secretshield.policy.budget_limiter import (
    BudgetExceededError,
    BudgetLimiter,
    RateLimitExceededError,
)
from secretshield.policy.cost_models import CostEstimator
from secretshield.policy.rbac import PermissionDeniedError, PolicyEngine
from secretshield.proxy.forwarder import ProxyForwarder
from secretshield.proxy.redactor import SecretRedactor
from secretshield.vault.cipher import VaultCipher
from secretshield.vault.store import VaultStore


class AppState:
    """Holds global singleton services during application lifecycle."""

    cipher: VaultCipher
    vault_store: VaultStore
    authenticator: TokenAuthenticator
    policy_engine: PolicyEngine
    budget_limiter: BudgetLimiter
    audit_logger: AuditLogger
    forwarder: ProxyForwarder
    recent_events: list = []


state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup and clean up on shutdown."""
    state.cipher = VaultCipher(settings.master_key_bytes)
    state.vault_store = VaultStore(settings.vault_db_path, state.cipher)
    await state.vault_store.init_db()

    state.authenticator = TokenAuthenticator(jwt_secret=settings.jwt_secret)
    state.policy_engine = PolicyEngine(default_deny=False)  # Allow by default unless rules defined
    state.budget_limiter = BudgetLimiter()
    state.audit_logger = AuditLogger(settings.audit_db_path)
    await state.audit_logger.init_db()

    state.forwarder = ProxyForwarder(
        vault_store=state.vault_store,
        timeout=settings.timeout_seconds,
        max_connections=settings.max_keepalive_connections,
    )
    yield
    await state.forwarder.aclose()


app = FastAPI(
    title="SecretShield",
    description="Zero-Trust Outbound Credential Proxy & Dynamic Token Broker",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0", "timestamp": time.time()}


@app.api_route(
    "/proxy/{profile_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
)
async def proxy_request(
    profile_name: str,
    path: str,
    request: Request,
    x_service_id: str | None = Header(None, alias="X-Service-Id"),
    x_service_token: str | None = Header(None, alias="X-Service-Token"),
    authorization: str | None = Header(None),
):
    """Authenticate downstream caller, enforce policy, inject credentials, and stream response."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    token = x_service_token or authorization

    # 1. Zero-Trust Caller Authentication
    try:
        if token or x_service_id:
            caller = state.authenticator.authenticate(service_id=x_service_id, token=token)
            service_id = caller.service_id
        else:
            # Fallback identity if no service headers provided in dev
            service_id = "anonymous-caller"
    except AuthenticationError as exc:
        event = {
            "timestamp": time.strftime("%H:%M:%S"),
            "service_id": x_service_id or "unknown",
            "profile": profile_name,
            "status": 401,
            "detail": str(exc),
        }
        state.recent_events.append(event)
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    # 2. RBAC Policy Enforcement
    try:
        state.policy_engine.enforce(
            caller=state.authenticator.authenticate(service_id=service_id, token=token)
            if token
            else None or type("DummyCaller", (), {"service_id": service_id})(),
            profile_name=profile_name,
            method=request.method,
            path=path,
        )
    except PermissionDeniedError as exc:
        state.recent_events.append(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "service_id": service_id,
                "profile": profile_name,
                "status": 403,
                "detail": str(exc),
            }
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # 3. Budget & Rate Limit Verification
    try:
        state.budget_limiter.check_budget(service_id=service_id)
    except (BudgetExceededError, RateLimitExceededError) as exc:
        problem = BudgetLimiter.format_rfc7807_problem(exc, instance_path=request.url.path)
        state.recent_events.append(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "service_id": service_id,
                "profile": profile_name,
                "status": 429,
                "detail": str(exc),
            }
        )
        return JSONResponse(status_code=429, content=problem, media_type="application/problem+json")

    # 4. Outbound Credential Injection & Forwarding
    raw_body = await request.body()
    query_params = dict(request.query_params)
    inbound_headers = dict(request.headers)

    status_code, resp_headers, stream, latency_ms = await state.forwarder.forward(
        profile_name=profile_name,
        path=path,
        method=request.method,
        headers=inbound_headers,
        query_params=query_params,
        content=raw_body if raw_body else None,
    )

    # 5. Buffer small text/json payloads for redaction & cost estimation
    content_type = resp_headers.get("content-type", "").lower()
    is_text = "json" in content_type or "text" in content_type

    estimated_cost = 0.0005
    collected_chunks = []
    if is_text:
        async for chunk in stream:
            collected_chunks.append(chunk)
        full_body = b"".join(collected_chunks)

        try:
            body_text = full_body.decode("utf-8")
            # Redact response body
            redacted_text = SecretRedactor.redact_text(body_text)
            final_content = redacted_text.encode("utf-8")

            # Try parsing json for AI token cost estimation
            try:
                parsed_json = json.loads(body_text)
                estimated_cost = CostEstimator.estimate_from_response(
                    profile_name=profile_name,
                    response_json=parsed_json,
                )
            except Exception:
                estimated_cost = CostEstimator.estimate_from_response(profile_name=profile_name)

        except UnicodeDecodeError:
            final_content = full_body

        # Update budget spend
        state.budget_limiter.record_spend(service_id=service_id, cost_usd=estimated_cost)

        # 6. Record to Hash-Chained Audit Ledger
        await state.audit_logger.log_request(
            service_id=service_id,
            profile_name=profile_name,
            method=request.method,
            path=path,
            status_code=status_code,
            latency_ms=latency_ms,
            cost_usd=estimated_cost,
            client_ip=client_ip,
            metadata={"query": query_params},
        )

        state.recent_events.append(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "service_id": service_id,
                "profile": profile_name,
                "method": request.method,
                "status": status_code,
                "latency_ms": round(latency_ms, 1),
                "cost_usd": estimated_cost,
            }
        )
        if len(state.recent_events) > 100:
            state.recent_events.pop(0)

        # Update Content-Length header for redacted body
        resp_headers["content-length"] = str(len(final_content))
        return Response(content=final_content, status_code=status_code, headers=resp_headers)

    else:
        # Binary stream passthrough
        state.budget_limiter.record_spend(service_id=service_id, cost_usd=estimated_cost)
        await state.audit_logger.log_request(
            service_id=service_id,
            profile_name=profile_name,
            method=request.method,
            path=path,
            status_code=status_code,
            latency_ms=latency_ms,
            cost_usd=estimated_cost,
            client_ip=client_ip,
        )
        return StreamingResponse(stream, status_code=status_code, headers=resp_headers)


@app.get("/admin/metrics")
async def get_metrics():
    """Retrieve runtime telemetry and budget consumption."""
    return {
        "recent_events": state.recent_events[-20:],
        "budgets": {
            sid: state.budget_limiter.get_metrics(sid) for sid in state.budget_limiter._budgets
        },
    }
