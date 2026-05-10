"""
RAPTOR | Admin Router
GET  /api/v1/audit                   — audit log (admin or per-investigation)
GET  /api/v1/metrics                 — Prometheus-compatible metrics
GET  /api/v1/users                   — list users (admin)
POST /api/v1/users                   — create user (admin)
GET  /api/v1/users/{id}              — get user (admin)
PUT  /api/v1/users/{id}              — update user (admin)
DELETE /api/v1/users/{id}            — disable user (admin)
GET  /api/v1/admin/schema/status     — applied DB migrations
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response

from auth_core import (
    _has_role,
    _password_hash,
    audit_log,
    ensure_investigation_access,
    require_role,
)
from database import (
    _utcnow,
    db_connect,
    get_user_by_id,
    list_audit_entries,
    list_schema_migrations,
    list_users,
)
from metrics_store import get_metrics_text
from models import (
    AuditEntry,
    AuditLogResponse,
    SchemaMigration,
    SchemaStatusResponse,
    UserCreateRequest,
    UserListResponse,
    UserResponse,
    UserUpdateRequest,
)

router = APIRouter(tags=["admin"])


# ── Audit ─────────────────────────────────────────────────────────────────────

@router.get("/api/v1/audit", response_model=AuditLogResponse)
async def get_audit_log(
    request: Request,
    limit: int = 100,
    investigation_id: Optional[str] = None,
) -> AuditLogResponse:
    """List recent append-only audit entries.

    Callers with *viewer* role may filter by investigation_id (which enforces
    tenant isolation).  Unfiltered access requires *admin* role.
    """
    if investigation_id:
        ensure_investigation_access(request, investigation_id, "viewer")
    else:
        require_role(request, "admin")

    entries = list_audit_entries(limit=limit, investigation_id=investigation_id)
    audit_log(request, "audit.viewed", investigation_id, {"limit": limit})
    return AuditLogResponse(
        entries=[AuditEntry(**entry) for entry in entries],
        total_count=len(entries),
    )


# ── Metrics ───────────────────────────────────────────────────────────────────

@router.get("/api/v1/metrics")
async def metrics(request: Request) -> Response:
    """Expose Prometheus-format operational counters."""
    require_role(request, "viewer")
    text, content_type = get_metrics_text()
    return Response(text, media_type=content_type)


# ── Schema / DB migrations ────────────────────────────────────────────────────

@router.get("/api/v1/admin/schema/status", response_model=SchemaStatusResponse)
async def get_schema_status(request: Request) -> SchemaStatusResponse:
    """Return the list of applied DB migrations and the active DB engine."""
    require_role(request, "admin")
    from config import RAPTOR_DB_ENGINE

    rows = list_schema_migrations()
    audit_log(request, "admin.schema_status.viewed", None, {"count": len(rows)})
    return SchemaStatusResponse(
        migrations=[SchemaMigration(**r) for r in rows],
        total_count=len(rows),
        db_engine=RAPTOR_DB_ENGINE,
    )


# ── User management ───────────────────────────────────────────────────────────

@router.get("/api/v1/users", response_model=UserListResponse)
async def list_all_users(request: Request) -> UserListResponse:
    """List all users in the caller's tenant (or all tenants for global admins)."""
    principal = require_role(request, "admin")
    tenant_id = (
        None
        if _has_role(principal, "admin") and "service" in principal.get("roles", [])
        else principal.get("tenant_id")
    )
    rows = list_users(tenant_id=tenant_id)
    audit_log(request, "users.listed", None, {"count": len(rows)})
    return UserListResponse(
        users=[_user_row_to_response(r) for r in rows],
        total_count=len(rows),
    )


@router.post("/api/v1/users", response_model=UserResponse, status_code=201)
async def create_user(request: Request, payload: UserCreateRequest) -> UserResponse:
    """Create a new local user account."""
    require_role(request, "admin")
    user_id = str(uuid.uuid4())
    conn = db_connect()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (payload.username,)
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=409, detail="Username already exists"
            )
        allowed_roles = {"viewer", "analyst", "admin"}
        roles = [r for r in payload.roles if r in allowed_roles] or ["viewer"]
        conn.execute(
            """
            INSERT INTO users
            (id, username, password_hash, roles, tenant_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                payload.username,
                _password_hash(payload.password),
                json.dumps(roles),
                payload.tenant_id,
                _utcnow(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    audit_log(
        request,
        "user.created",
        None,
        {"username": payload.username, "roles": roles, "tenant_id": payload.tenant_id},
    )
    row = get_user_by_id(user_id)
    return _user_row_to_response(row)  # type: ignore[arg-type]


@router.get("/api/v1/users/{user_id}", response_model=UserResponse)
async def get_user(request: Request, user_id: str) -> UserResponse:
    """Fetch a single user by ID."""
    require_role(request, "admin")
    row = get_user_by_id(user_id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_row_to_response(row)


@router.put("/api/v1/users/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request, user_id: str, payload: UserUpdateRequest
) -> UserResponse:
    """Update password, roles, or disabled state for a user."""
    require_role(request, "admin")
    row = get_user_by_id(user_id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    updates: dict = {}
    if payload.password is not None:
        updates["password_hash"] = _password_hash(payload.password)
    if payload.roles is not None:
        allowed = {"viewer", "analyst", "admin"}
        updates["roles"] = json.dumps(
            [r for r in payload.roles if r in allowed] or ["viewer"]
        )
    if payload.disabled is not None:
        updates["disabled"] = 1 if payload.disabled else 0
    if payload.tenant_id is not None:
        updates["tenant_id"] = payload.tenant_id

    if updates:
        conn = db_connect()
        try:
            sets = ", ".join(f"{k} = ?" for k in updates)
            conn.execute(
                f"UPDATE users SET {sets} WHERE id = ?",
                [*updates.values(), user_id],
            )
            conn.commit()
        finally:
            conn.close()

    audit_log(
        request,
        "user.updated",
        None,
        {"user_id": user_id, "fields": list(updates.keys())},
    )
    return _user_row_to_response(get_user_by_id(user_id))  # type: ignore[arg-type]


@router.delete("/api/v1/users/{user_id}", status_code=204)
async def delete_user(request: Request, user_id: str) -> None:
    """Disable a user account (soft delete — accounts are never hard-deleted)."""
    require_role(request, "admin")
    row = get_user_by_id(user_id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    conn = db_connect()
    try:
        conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
    audit_log(request, "user.disabled", None, {"user_id": user_id})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _user_row_to_response(row: dict) -> UserResponse:
    return UserResponse(
        id=str(row.get("id", "")),
        username=str(row.get("username", "")),
        roles=json.loads(row.get("roles") or '["viewer"]'),
        tenant_id=str(row.get("tenant_id", "default")),
        disabled=bool(row.get("disabled", False)),
        created_at=str(row.get("created_at", "")),
        last_login_at=str(row.get("last_login_at", "")),
    )
