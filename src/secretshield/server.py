"""FastAPI proxy application with Transparent Proxying, DLP, Caching, Prometheus & Web UI."""

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)

from secretshield.alert.dispatcher import AlertDispatcher
from secretshield.audit.logger import AuditLogger
from secretshield.audit.verifier import AuditChainVerifier
from secretshield.config import settings
from secretshield.metrics.prometheus import PrometheusRegistry
from secretshield.policy.authenticator import AuthenticationError, TokenAuthenticator
from secretshield.policy.budget_limiter import (
    BudgetExceededError,
    BudgetLimiter,
    RateLimitExceededError,
)
from secretshield.policy.cost_models import CostEstimator
from secretshield.policy.rbac import PermissionDeniedError, PolicyEngine
from secretshield.proxy.cache import ResponseCache
from secretshield.proxy.dlp import DLPViolationError, InboundDLPGuard
from secretshield.proxy.forwarder import ProxyForwarder
from secretshield.proxy.redactor import SecretRedactor
from secretshield.vault.cipher import VaultCipher
from secretshield.vault.store import InjectionType, VaultStore


class AppState:
    """Holds global singleton services during application lifecycle."""

    cipher: VaultCipher
    vault_store: VaultStore
    authenticator: TokenAuthenticator
    policy_engine: PolicyEngine
    budget_limiter: BudgetLimiter
    audit_logger: AuditLogger
    forwarder: ProxyForwarder
    cache: ResponseCache
    dlp_guard: InboundDLPGuard
    alert_dispatcher: AlertDispatcher
    prometheus: PrometheusRegistry
    recent_events: list


state = AppState()
state.recent_events = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup and clean up on shutdown."""
    state.cipher = VaultCipher(settings.master_key_bytes)
    state.vault_store = VaultStore(settings.vault_db_path, state.cipher)
    await state.vault_store.init_db()

    state.authenticator = TokenAuthenticator(jwt_secret=settings.jwt_secret)
    state.policy_engine = PolicyEngine(default_deny=False)
    state.budget_limiter = BudgetLimiter()
    state.audit_logger = AuditLogger(settings.audit_db_path)
    await state.audit_logger.init_db()

    state.cache = ResponseCache(max_entries=1000, default_ttl_seconds=3600)
    state.dlp_guard = InboundDLPGuard()
    state.alert_dispatcher = AlertDispatcher()
    state.prometheus = PrometheusRegistry()

    state.forwarder = ProxyForwarder(
        vault_store=state.vault_store,
        timeout=settings.timeout_seconds,
        max_connections=settings.max_keepalive_connections,
    )
    yield
    await state.forwarder.aclose()
    await state.alert_dispatcher.aclose()


app = FastAPI(
    title="SecretShield",
    description="Zero-Trust Outbound Credential Proxy & Dynamic Token Broker",
    version="0.1.0",
    lifespan=lifespan,
)

UI_DIR = Path(__file__).parent / "ui"


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0", "timestamp": time.time()}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """Expose Prometheus plain-text metrics."""
    return state.prometheus.render_prometheus_text(
        budget_limiter=state.budget_limiter,
        circuit_registry=state.forwarder.circuit_registry,
        cache=state.cache,
    )


# ----------------------------------------------------------------------
# Web Dashboard Endpoints
# ----------------------------------------------------------------------


@app.get("/")
@app.get("/ui")
async def serve_ui():
    """Serve the Web Dashboard HTML interface."""
    index_file = UI_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h2>SecretShield Web UI index.html not found</h2>")


@app.get("/ui/{filename}")
async def serve_ui_static(filename: str):
    """Serve static CSS and JS assets for the Web Dashboard."""
    asset_path = UI_DIR / filename
    if asset_path.exists() and asset_path.is_file():
        media_type = (
            "text/css"
            if filename.endswith(".css")
            else ("application/javascript" if filename.endswith(".js") else "text/plain")
        )
        return FileResponse(asset_path, media_type=media_type)
    raise HTTPException(status_code=404, detail="Asset not found")


@app.get("/admin/metrics")
async def get_metrics():
    """Retrieve runtime telemetry, budget consumption, and cache stats."""
    return {
        "recent_events": state.recent_events[-20:],
        "budgets": {
            sid: state.budget_limiter.get_metrics(sid) for sid in state.budget_limiter._budgets
        },
        "cache": state.cache.get_stats(),
    }


@app.get("/admin/profiles")
async def get_admin_profiles():
    """List all configured profiles with masked secrets."""
    return await state.vault_store.list_profiles()


@app.post("/admin/profiles")
async def create_admin_profile(payload: dict):
    """Create a profile from web UI."""
    profile = await state.vault_store.set_profile(
        name=payload["name"],
        base_url=payload["base_url"],
        secret=payload["secret"],
        domains=payload.get("domains", []),
        injection_type=InjectionType(payload.get("injection_type", "bearer")),
        header_name=payload.get("header_name", "Authorization"),
        header_prefix=payload.get("header_prefix", "Bearer "),
    )
    return profile


@app.delete("/admin/profiles/{name}")
async def delete_admin_profile(name: str):
    """Delete a profile from the vault."""
    deleted = await state.vault_store.delete_profile(name)
    if not deleted:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"deleted": True}


@app.get("/admin/audit/recent")
async def get_admin_audit_recent():
    """Get recent audit ledger entries."""
    return await state.audit_logger.get_recent_entries(limit=50)


@app.post("/admin/audit/verify")
async def verify_admin_audit():
    """Verify cryptographic SHA-256 hash chain of the audit database."""
    is_valid, err, count = await AuditChainVerifier.verify_chain(settings.audit_db_path)
    return {
        "is_valid": is_valid,
        "error": err,
        "verified_count": count,
    }


# ----------------------------------------------------------------------
# Outbound Proxy Core (Explicit & Transparent Forwarding)
# ----------------------------------------------------------------------


async def handle_proxy_execution(
    profile_name: str,
    path: str,
    request: Request,
    service_id: str,
    token: str | None,
):
    """Internal shared handler for both explicit /proxy/ and transparent proxy routing."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. RBAC Policy Enforcement
    try:
        caller = type("DummyCaller", (), {"service_id": service_id})()
        state.policy_engine.enforce(
            caller=caller,
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

    # 2. Budget Verification
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
        if isinstance(exc, BudgetExceededError):
            await state.alert_dispatcher.notify_budget_exhausted(
                service_id, exc.current_spend, exc.limit_value
            )
        return JSONResponse(status_code=429, content=problem, media_type="application/problem+json")

    # 3. Read Body & Inbound DLP Guard Inspection
    raw_body = await request.body()
    query_params = dict(request.query_params)
    inbound_headers = dict(request.headers)

    try:
        dlp_res = state.dlp_guard.inspect_payload(raw_body, context=profile_name)
        processed_body = dlp_res.sanitized_content
    except DLPViolationError as exc:
        state.recent_events.append(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "service_id": service_id,
                "profile": profile_name,
                "status": 422,
                "detail": f"DLP Block: {len(exc.violations)} violation(s)",
            }
        )
        return JSONResponse(
            status_code=422,
            content={
                "error": "DLP_VIOLATION",
                "message": str(exc),
                "violations": [v.model_dump() for v in exc.violations],
            },
        )

    # 4. Check Response Cache for Idempotent/Deterministic calls
    cache_key = state.cache.generate_cache_key(
        profile_name=profile_name,
        method=request.method,
        path=path,
        query_params=query_params,
        content=processed_body,
    )
    cached_hit = state.cache.get(cache_key)
    if cached_hit:
        status_code, c_headers, c_body = cached_hit
        state.prometheus.record_request(
            service_id=service_id,
            profile_name=profile_name,
            status_code=status_code,
            latency_ms=0.5,
            cost_usd=0.0,
        )
        return Response(content=c_body, status_code=status_code, headers=c_headers)

    # 5. Outbound Credential Injection & Streaming
    status_code, resp_headers, stream, latency_ms = await state.forwarder.forward(
        profile_name=profile_name,
        path=path,
        method=request.method,
        headers=inbound_headers,
        query_params=query_params,
        content=processed_body if processed_body else None,
    )

    content_type = resp_headers.get("content-type", "").lower()
    is_text = "json" in content_type or "text" in content_type

    estimated_cost = 0.0005
    if is_text:
        collected_chunks = []
        async for chunk in stream:
            collected_chunks.append(chunk)
        full_body = b"".join(collected_chunks)

        try:
            body_text = full_body.decode("utf-8")
            redacted_text = SecretRedactor.redact_text(body_text)
            final_content = redacted_text.encode("utf-8")

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

        # Update budget spend & record Prometheus metrics
        state.budget_limiter.record_spend(service_id=service_id, cost_usd=estimated_cost)
        state.prometheus.record_request(
            service_id=service_id,
            profile_name=profile_name,
            status_code=status_code,
            latency_ms=latency_ms,
            cost_usd=estimated_cost,
        )

        # Store in cache if 200 OK
        if status_code == 200:
            state.cache.set(cache_key, status_code, resp_headers, final_content)

        # Check for 80% budget warning alert
        metrics_after = state.budget_limiter.get_metrics(service_id)
        if metrics_after.get("daily_percent", 0.0) >= 80.0:
            await state.alert_dispatcher.notify_budget_warning(
                service_id=service_id,
                spent=metrics_after["daily_spent"],
                limit=metrics_after["daily_limit"],
                percent=metrics_after["daily_percent"],
            )

        # Record to immutable audit ledger
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

        resp_headers["content-length"] = str(len(final_content))
        return Response(content=final_content, status_code=status_code, headers=resp_headers)

    else:
        # Binary stream passthrough
        state.budget_limiter.record_spend(service_id=service_id, cost_usd=estimated_cost)
        state.prometheus.record_request(
            service_id=service_id,
            profile_name=profile_name,
            status_code=status_code,
            latency_ms=latency_ms,
            cost_usd=estimated_cost,
        )
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


@app.api_route(
    "/proxy/{profile_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
)
async def proxy_explicit_route(
    profile_name: str,
    path: str,
    request: Request,
    x_service_id: str | None = Header(None, alias="X-Service-Id"),
    x_service_token: str | None = Header(None, alias="X-Service-Token"),
    authorization: str | None = Header(None),
):
    """Explicit proxy route targeting a specific profile by name."""
    token = x_service_token or authorization
    try:
        if token or x_service_id:
            caller = state.authenticator.authenticate(service_id=x_service_id, token=token)
            service_id = caller.service_id
        else:
            service_id = "anonymous-caller"
    except AuthenticationError as exc:
        state.recent_events.append(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "service_id": x_service_id or "unknown",
                "profile": profile_name,
                "status": 401,
                "detail": str(exc),
            }
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    return await handle_proxy_execution(
        profile_name=profile_name,
        path=path,
        request=request,
        service_id=service_id,
        token=token,
    )


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def transparent_forward_proxy_route(
    full_path: str,
    request: Request,
    x_service_id: str | None = Header(None, alias="X-Service-Id"),
    x_service_token: str | None = Header(None, alias="X-Service-Token"),
    authorization: str | None = Header(None),
):
    """Transparent forward proxy: handles requests directed at external hostnames via HTTP_PROXY."""
    # Exclude reserved internal routes
    first_segment = full_path.split("/")[0].lower()
    if first_segment in {"ui", "metrics", "health", "admin", "proxy"}:
        raise HTTPException(status_code=404, detail="Not Found")

    host_header = request.headers.get("host", "")
    profile = await state.vault_store.get_profile_by_host(host_header)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"Transparent proxy: no profile matching Host '{host_header}' found in vault",
        )

    token = x_service_token or authorization
    service_id = x_service_id or "transparent-caller"

    return await handle_proxy_execution(
        profile_name=profile.name,
        path=full_path,
        request=request,
        service_id=service_id,
        token=token,
    )
