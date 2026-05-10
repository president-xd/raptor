"""
RAPTOR | Application Factory
Wires FastAPI middleware, mounts routers, and starts background services.
All domain logic lives in dedicated modules (auth_core, database, pipeline_runner, etc.).
"""
from __future__ import annotations

import json
import os
import sys
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

# Ensure the backend package directory is on sys.path when invoked directly
sys.path.insert(0, os.path.dirname(__file__))

import config as _config
from config import API_HOST, API_PORT, SESSION_COOKIE_NAME, validate_startup_config
from auth_core import (
    MUTATING_METHODS,
    _extract_api_key,
    _is_trusted_origin,
    _json_auth_error,
    _principal,
    _request_id_from_headers,
    _set_request_principal,
    _trusted_sso_principal,
    _valid_session_token,
)
from database import init_db
from auth_core import bootstrap_admin_user
from pipeline_runner import start_optional_services
import metrics_store

# ── Validate configuration early so bad deploys fail loudly ──────────────────
validate_startup_config()


# ── Lifespan (startup / shutdown hooks) ──────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    bootstrap_admin_user()
    start_optional_services()
    logger.info("RAPTOR API started")
    yield
    logger.info("RAPTOR API shutting down")


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="RAPTOR API",
    description=(
        "Retrieval-Augmented Persistent Threat Orchestration and Reasoning — "
        "SOC investigation platform."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if _config.RAPTOR_PRODUCTION else "/docs",
    redoc_url=None if _config.RAPTOR_PRODUCTION else "/redoc",
    openapi_url=None if _config.RAPTOR_PRODUCTION else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_config.CORS_ALLOW_ORIGINS,
    allow_credentials=_config.CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Mount routers ─────────────────────────────────────────────────────────────

from routers import auth, investigations, analysis, intelligence, admin, health

app.include_router(auth.router)
app.include_router(investigations.router)
app.include_router(analysis.router)
app.include_router(intelligence.router)
app.include_router(admin.router)
app.include_router(health.router)


# ── Middleware: request context + metrics ─────────────────────────────────────

@app.middleware("http")
async def request_context_and_metrics(request: Request, call_next):
    request_id = _request_id_from_headers(request)
    request.state.request_id = request_id
    started = time.perf_counter()
    status_code = 500
    response = None
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        elapsed = time.perf_counter() - started
        metrics_store.record_request(status_code, elapsed)
        logger.info(
            json.dumps(
                {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_ms": round(elapsed * 1000, 2),
                },
                separators=(",", ":"),
            )
        )
        if response is not None:
            response.headers.setdefault("X-Request-ID", request_id)


# ── Middleware: security headers ──────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if hasattr(request.state, "request_id"):
        response.headers.setdefault("X-Request-ID", request.state.request_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'"
        ),
    )
    if _config.RAPTOR_PRODUCTION:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"
        )
    return response


# ── Middleware: CSRF guard ────────────────────────────────────────────────────

@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    """Block cross-origin browser mutations. API-key service calls bypass CSRF."""
    if request.method not in MUTATING_METHODS or not request.url.path.startswith("/api/"):
        return await call_next(request)
    if request.url.path == "/api/v1/auth/session":
        return await call_next(request)

    supplied = _extract_api_key(request)
    import hmac as _hmac
    _api_key = _config.RAPTOR_API_KEY
    if supplied and _api_key and _hmac.compare_digest(supplied, _api_key):
        return await call_next(request)

    if not request.cookies.get(SESSION_COOKIE_NAME):
        return await call_next(request)

    from urllib.parse import urlparse as _urlparse

    origin = request.headers.get("origin", "")
    referrer = request.headers.get("referer", "")
    referrer_origin = ""
    if referrer:
        parsed = _urlparse(referrer)
        if parsed.scheme and parsed.netloc:
            referrer_origin = f"{parsed.scheme}://{parsed.netloc}"

    if _is_trusted_origin(origin) or _is_trusted_origin(referrer_origin):
        return await call_next(request)

    metrics_store.inc_auth_failures()
    return _json_auth_error(
        request,
        403,
        {"detail": "Trusted Origin or Referer required for browser mutations"},
    )


# ── Middleware: authentication ────────────────────────────────────────────────

@app.middleware("http")
async def optional_api_key_auth(request: Request, call_next):
    """Enforce authentication on all /api/ routes."""
    import hmac as _hmac

    path = request.url.path
    public_paths = {"/", "/api/v1/auth/session"}
    if not _config.RAPTOR_PRODUCTION:
        public_paths.update({"/docs", "/redoc", "/openapi.json"})

    if getattr(request, "method", "GET") == "OPTIONS":
        return await call_next(request)
    if path in public_paths:
        return await call_next(request)
    if _config.RAPTOR_AUTH_EXEMPT_HEALTH and path == "/api/v1/health":
        return await call_next(request)
    if not path.startswith("/api/"):
        return await call_next(request)

    # 1. Static API key
    _api_key = _config.RAPTOR_API_KEY
    supplied = _extract_api_key(request)
    if supplied and _api_key and _hmac.compare_digest(supplied, _api_key):
        _set_request_principal(
            request, _principal("api-key", ["service"], "default", "api-key")
        )
        return await call_next(request)

    # 2. Trusted SSO proxy headers
    sso_principal = _trusted_sso_principal(request)
    if sso_principal:
        _set_request_principal(request, sso_principal)
        return await call_next(request)

    # 3. Browser session cookie
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    principal = _valid_session_token(session_token)
    if principal:
        _set_request_principal(request, principal)
        return await call_next(request)

    # 4. Local-dev auth-disabled mode (localhost only)
    if _config.RAPTOR_ALLOW_AUTH_DISABLED and not _config.RAPTOR_API_KEY:
        client = getattr(request, "client", None)
        if getattr(client, "host", "") not in {"127.0.0.1", "::1", "localhost", "testclient"}:
            return _json_auth_error(
                request,
                401,
                {"detail": "Auth-disabled mode is restricted to localhost"},
            )
        _set_request_principal(
            request, _principal("anonymous", ["analyst", "viewer"], "default")
        )
        return await call_next(request)

    metrics_store.inc_auth_failures()
    return _json_auth_error(
        request,
        401,
        {"detail": "Valid API key or browser session required"},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting RAPTOR API on {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=int(API_PORT))
