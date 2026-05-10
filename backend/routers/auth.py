"""
RAPTOR | Auth Router
POST /api/v1/auth/session  — create browser session
GET  /api/v1/auth/me       — introspect current principal
POST /api/v1/auth/logout   — revoke session
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request, Response

from auth_core import (
    _principal,
    authenticate_user,
    create_session,
    enforce_rate_limit,
    _make_session_token,
    require_role,
    revoke_session,
)
from config import RAPTOR_API_KEY, RAPTOR_SESSION_COOKIE_SECURE, RAPTOR_SESSION_TTL_SECONDS, SESSION_COOKIE_NAME
from models import AuthSessionRequest, AuthSessionResponse, PrincipalResponse
import metrics_store

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/session", response_model=AuthSessionResponse)
async def create_auth_session(
    payload: AuthSessionRequest, response: Response, request: Request
) -> AuthSessionResponse:
    """Create a server-side browser session from credentials or service API key."""
    enforce_rate_limit(request, "auth")

    principal = None
    if payload.api_key:
        if not RAPTOR_API_KEY or not hmac.compare_digest(payload.api_key, RAPTOR_API_KEY):
            metrics_store.inc_auth_failures()
            raise HTTPException(status_code=401, detail="Invalid API key")
        principal = _principal("api-key", ["service"], "default", "api-key")
    elif payload.username and payload.password:
        principal = authenticate_user(payload.username, payload.password)
    else:
        raise HTTPException(
            status_code=400, detail="api_key or username/password is required"
        )

    token = _make_session_token()
    create_session(principal.get("user_id") or "api-key", token)

    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=RAPTOR_SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
        max_age=RAPTOR_SESSION_TTL_SECONDS,
    )
    return AuthSessionResponse(
        authenticated=True,
        actor=principal["actor"],
        roles=principal["roles"],
        tenant_id=principal["tenant_id"],
    )


@router.get("/me", response_model=PrincipalResponse)
async def get_current_principal(request: Request) -> PrincipalResponse:
    """Return the authenticated principal for the current request."""
    principal = require_role(request, "viewer")
    return PrincipalResponse(
        actor=principal["actor"],
        roles=principal["roles"],
        tenant_id=principal["tenant_id"],
    )


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    """Revoke the current browser session."""
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if token:
        revoke_session(token)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"authenticated": False}
