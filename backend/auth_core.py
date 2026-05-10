"""
RAPTOR | Authentication Core
Session management, RBAC enforcement, password hashing, and principal resolution.

Import chain: config → database → auth_core
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sqlite3
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from loguru import logger

import config as _config
from config import (
    CORS_ALLOW_CREDENTIALS,
    CORS_ALLOW_ORIGINS,
    CSRF_TRUSTED_ORIGINS,
    RAPTOR_ALLOW_AUTH_DISABLED,
    RAPTOR_API_KEY,
    RAPTOR_AUTH_LOCK_SECONDS,
    RAPTOR_AUTH_MAX_FAILURES,
    RAPTOR_BOOTSTRAP_ADMIN_DISABLED,
    RAPTOR_BOOTSTRAP_ADMIN_PASSWORD,
    RAPTOR_BOOTSTRAP_ADMIN_USERNAME,
    RAPTOR_PRODUCTION,
    RAPTOR_REQUIRE_RBAC,
    RAPTOR_SESSION_COOKIE_SECURE,
    RAPTOR_SESSION_IDLE_TIMEOUT_SECONDS,
    RAPTOR_SESSION_TTL_SECONDS,
    RAPTOR_SSO_ROLES_HEADER,
    RAPTOR_SSO_TENANT_HEADER,
    RAPTOR_SSO_USER_HEADER,
    RAPTOR_TRUSTED_PROXY_CIDRS,
    RAPTOR_TRUSTED_SSO_ENABLED,
    SESSION_COOKIE_NAME,
)
from database import db_connect, db_get, _utcnow
import metrics_store

# ── Role ordering ─────────────────────────────────────────────────────────────

ROLE_ORDER: dict[str, int] = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
    "service": 3,
    "system": 3,
}

# ── Rate-limiting constants ───────────────────────────────────────────────────

MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

RATE_LIMIT_RULES: dict[str, tuple[int, int]] = {
    "auth":      (10,  60),
    "upload":    (20, 300),
    "query":     (60, 300),
    "connector": (30, 300),
}

# In-memory sliding-window buckets (per-worker; Redis is the multi-process store)
RATE_LIMIT_BUCKETS: dict[tuple[str, str], list[float]] = {}

ALLOWED_FEED_HOSTS: frozenset[str] = frozenset({
    "www.cisa.gov",
    "cisa.gov",
    "raw.githubusercontent.com",
})

REQUEST_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]")

# ── Password & token helpers ──────────────────────────────────────────────────

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _password_hash(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 210_000
    )
    return f"pbkdf2_sha256$210000${salt}${base64.b64encode(digest).decode('ascii')}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt, expected = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(rounds)
        )
        return hmac.compare_digest(base64.b64encode(digest).decode("ascii"), expected)
    except Exception:
        return False


def _make_session_token() -> str:
    return secrets.token_urlsafe(32)


# ── Principal helpers ─────────────────────────────────────────────────────────

def _principal(
    actor: str = "anonymous",
    roles: Optional[list[str]] = None,
    tenant_id: str = "default",
    user_id: str = "",
) -> dict:
    return {
        "actor": actor,
        "roles": roles or ["viewer"],
        "tenant_id": tenant_id or "default",
        "user_id": user_id,
    }


def _has_role(principal: dict, required: str) -> bool:
    level = max(ROLE_ORDER.get(role, 0) for role in principal.get("roles", []))
    return level >= ROLE_ORDER.get(required, 0)


def _request_principal(request: Optional[Request]) -> dict:
    if request is None:
        return _principal("system", ["system"], "system", "system")
    state = getattr(request, "state", None)
    return getattr(state, "principal", _principal())


def _set_request_principal(request: Request, principal: dict) -> None:
    if not hasattr(request, "state"):
        request.state = type("State", (), {})()  # type: ignore[assignment]
    request.state.principal = principal


def require_role(request: Request, role: str) -> dict:
    principal = _request_principal(request)
    if not _config.RAPTOR_REQUIRE_RBAC:
        return principal
    if _config.RAPTOR_ALLOW_AUTH_DISABLED and principal["actor"] == "anonymous":
        return principal
    if not _has_role(principal, role):
        raise HTTPException(status_code=403, detail=f"{role} role required")
    return principal


# ── Session management ────────────────────────────────────────────────────────

def _valid_session_token(token: str) -> Optional[dict]:
    if not token:
        return None
    conn = db_connect()
    conn.row_factory = sqlite3.Row  # type: ignore[assignment]
    try:
        row = conn.execute(
            """
            SELECT s.id, s.expires_at, s.revoked_at, s.last_seen_at, s.created_at,
                   u.id AS user_id, u.username, u.roles, u.tenant_id, u.disabled
            FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (_token_hash(token),),
        ).fetchone()
        if not row or row["revoked_at"] or row["disabled"]:
            return None
        now = time.time()
        if float(row["expires_at"]) < now:
            return None
        # Idle-timeout: reject sessions that have been inactive too long
        if RAPTOR_SESSION_IDLE_TIMEOUT_SECONDS > 0:
            last_activity = row["last_seen_at"] or row["created_at"] or ""
            if last_activity:
                try:
                    from datetime import datetime, timezone
                    last_ts = datetime.fromisoformat(str(last_activity)).timestamp()
                    if now - last_ts > RAPTOR_SESSION_IDLE_TIMEOUT_SECONDS:
                        return None
                except Exception:
                    pass
        conn.execute(
            "UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?",
            (_utcnow(), row["id"]),
        )
        conn.commit()
        return _principal(
            row["username"],
            json.loads(row["roles"] or "[]"),
            row["tenant_id"],
            row["user_id"],
        )
    finally:
        conn.close()


def create_session(user_id: str, token: str) -> None:
    """Persist a new browser session token."""
    expires_at = time.time() + _config.RAPTOR_SESSION_TTL_SECONDS
    conn = db_connect()
    try:
        conn.execute(
            """
            INSERT INTO auth_sessions (id, user_id, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), user_id, _token_hash(token), expires_at, _utcnow()),
        )
        conn.commit()
    finally:
        conn.close()


def revoke_session(token: str) -> None:
    """Mark a session as revoked (logout)."""
    conn = db_connect()
    try:
        conn.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ?",
            (_utcnow(), _token_hash(token)),
        )
        conn.commit()
    finally:
        conn.close()


# ── User authentication ───────────────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> dict:
    """Validate credentials, enforce lockout, and return a principal on success."""
    conn = db_connect()
    conn.row_factory = sqlite3.Row  # type: ignore[assignment]
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        now = time.time()

        if not row or row["disabled"]:
            metrics_store.inc_auth_failures()
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if row["locked_until"] and float(row["locked_until"]) > now:
            metrics_store.inc_auth_failures()
            raise HTTPException(
                status_code=429,
                detail="Account temporarily locked after failed attempts",
            )

        if not _verify_password(password, row["password_hash"]):
            failures = int(row["failed_attempts"] or 0) + 1
            locked_until = (
                now + _config.RAPTOR_AUTH_LOCK_SECONDS
                if failures >= _config.RAPTOR_AUTH_MAX_FAILURES
                else 0
            )
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (failures, locked_until, row["id"]),
            )
            conn.commit()
            metrics_store.inc_auth_failures()
            raise HTTPException(status_code=401, detail="Invalid username or password")

        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_at = ? WHERE id = ?",
            (_utcnow(), row["id"]),
        )
        conn.commit()
        return _principal(
            row["username"],
            json.loads(row["roles"] or "[]"),
            row["tenant_id"],
            row["id"],
        )
    finally:
        conn.close()


def bootstrap_admin_user() -> None:
    """Create (or disable) the local bootstrap admin on startup.

    If RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true the account is disabled on every
    startup — set this flag in production once real admin accounts exist.
    """
    conn = db_connect()
    try:
        # Ensure the api-key service account always exists
        conn.execute(
            """
            INSERT OR IGNORE INTO users (id, username, password_hash, roles, tenant_id, created_at)
            VALUES ('api-key', 'api-key', '', ?, 'default', ?)
            """,
            (json.dumps(["service"]), _utcnow()),
        )

        if _config.RAPTOR_BOOTSTRAP_ADMIN_DISABLED:
            conn.execute(
                "UPDATE users SET disabled = 1 WHERE username = ?",
                (_config.RAPTOR_BOOTSTRAP_ADMIN_USERNAME,),
            )
            logger.info(
                "Bootstrap admin disabled (RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true)"
            )
            conn.commit()
            return

        if not _config.RAPTOR_BOOTSTRAP_ADMIN_PASSWORD:
            conn.commit()
            return

        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (_config.RAPTOR_BOOTSTRAP_ADMIN_USERNAME,),
        ).fetchone()
        if not existing:
            conn.execute(
                """
                INSERT INTO users (id, username, password_hash, roles, tenant_id, created_at)
                VALUES (?, ?, ?, ?, 'default', ?)
                """,
                (
                    str(uuid.uuid4()),
                    _config.RAPTOR_BOOTSTRAP_ADMIN_USERNAME,
                    _password_hash(_config.RAPTOR_BOOTSTRAP_ADMIN_PASSWORD),
                    json.dumps(["admin", "analyst", "viewer"]),
                    _utcnow(),
                ),
            )
        conn.commit()
    finally:
        conn.close()


# ── Investigation access control ──────────────────────────────────────────────

def ensure_investigation_access(
    request: Request, inv_id: str, role: str = "viewer"
) -> dict:
    """Verify the caller has *role* and can see *inv_id*; return the DB record."""
    principal = require_role(request, role)
    record = db_get(inv_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Admins and service accounts see everything
    if _has_role(principal, "admin") or "service" in principal.get("roles", []):
        return record

    # Tenant isolation
    if record.get("tenant_id") != principal.get("tenant_id"):
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Owner isolation (empty owner_id means accessible to all tenant members)
    owner_id = record.get("owner_id") or ""
    if owner_id and owner_id != principal.get("user_id"):
        raise HTTPException(status_code=404, detail="Investigation not found")

    return record


# ── Actor resolution ──────────────────────────────────────────────────────────

def _authenticated_actor(request: Request) -> str:
    """Derive an audit actor from trusted auth state, never from user-supplied headers."""
    principal = getattr(getattr(request, "state", None), "principal", None)
    if principal and principal.get("actor"):
        return str(principal["actor"])
    if not _config.RAPTOR_API_KEY:
        return "local-auth-disabled" if _config.RAPTOR_ALLOW_AUTH_DISABLED else "unauthenticated"
    supplied = _extract_api_key(request)
    if supplied and hmac.compare_digest(supplied, _config.RAPTOR_API_KEY):
        return "api-key"
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if _valid_session_token(session_token):
        return "browser-session"
    return "authenticated-request"


# ── Origin / CORS helpers ─────────────────────────────────────────────────────

def _is_trusted_origin(origin: str) -> bool:
    return bool(origin) and origin.rstrip("/") in {
        o.rstrip("/") for o in CSRF_TRUSTED_ORIGINS
    }


def _is_allowed_cors_origin(origin: str) -> bool:
    if not origin:
        return False
    allowed = {o.rstrip("/") for o in _config.CORS_ALLOW_ORIGINS}
    return "*" in allowed or origin.rstrip("/") in allowed


def _json_auth_error(
    request: Request, status_code: int, content: dict
) -> JSONResponse:
    response = JSONResponse(status_code=status_code, content=content)
    origin = request.headers.get("origin", "")
    if _is_allowed_cors_origin(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        if _config.CORS_ALLOW_CREDENTIALS:
            response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


def _extract_api_key(request: Request) -> str:
    supplied = request.headers.get("x-raptor-api-key", "")
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        supplied = auth_header.split(" ", 1)[1].strip()
    return supplied


def _request_id_from_headers(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "").strip()
    if supplied:
        cleaned = REQUEST_ID_RE.sub("", supplied)[:80]
        if cleaned:
            return cleaned
    return uuid.uuid4().hex


# ── Trusted proxy / SSO ───────────────────────────────────────────────────────

def _request_from_trusted_proxy(request: Request) -> bool:
    client = getattr(request, "client", None)
    host = getattr(client, "host", "")
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
        return any(
            address in ipaddress.ip_network(cidr, strict=False)
            for cidr in _config.RAPTOR_TRUSTED_PROXY_CIDRS
        )
    except ValueError:
        return host in {"localhost", "testclient"}


def _trusted_sso_principal(request: Request) -> Optional[dict]:
    if not _config.RAPTOR_TRUSTED_SSO_ENABLED or not _request_from_trusted_proxy(request):
        return None
    actor = request.headers.get(_config.RAPTOR_SSO_USER_HEADER, "").strip()
    if not actor:
        return None
    roles_raw = request.headers.get(_config.RAPTOR_SSO_ROLES_HEADER, "viewer")
    roles = [r.strip().lower() for r in re.split(r"[, ]+", roles_raw) if r.strip()]
    allowed_roles = {"viewer", "analyst", "admin"}
    roles = [r for r in roles if r in allowed_roles] or ["viewer"]
    tenant_id = (
        request.headers.get(_config.RAPTOR_SSO_TENANT_HEADER, "default").strip() or "default"
    )
    user_id = hashlib.sha256(
        f"sso:{tenant_id}:{actor}".encode("utf-8")
    ).hexdigest()[:32]
    return _principal(actor, roles, tenant_id, user_id)


# ── Rate limiting ─────────────────────────────────────────────────────────────

def _client_rate_key(request: Optional[Request]) -> str:
    if request is None:
        return "system"
    principal = getattr(getattr(request, "state", None), "principal", None)
    if principal and principal.get("user_id"):
        return f"user:{principal['user_id']}"
    client = getattr(request, "client", None)
    return f"ip:{getattr(client, 'host', 'unknown')}"


def enforce_rate_limit(request: Optional[Request], bucket: str) -> None:
    from config import RAPTOR_RATE_LIMIT_BACKEND
    from database import _redis_send_command

    limit, window = RATE_LIMIT_RULES.get(bucket, (60, 60))
    client_key = _client_rate_key(request)

    if RAPTOR_RATE_LIMIT_BACKEND == "redis" and _redis_rate_limit_redis(
        client_key, bucket, limit, window
    ):
        return

    key = (client_key, bucket)
    now = time.time()
    recent = [t for t in RATE_LIMIT_BUCKETS.get(key, []) if now - t < window]
    if len(recent) >= limit:
        if bucket == "auth":
            metrics_store.inc_auth_failures()
        raise HTTPException(status_code=429, detail="Rate limit exceeded; retry later")
    recent.append(now)
    RATE_LIMIT_BUCKETS[key] = recent


def _redis_rate_limit_redis(
    client_key: str, bucket: str, limit: int, window: int
) -> bool:
    """Multi-process rate limit via Redis INCR+EXPIRE. Returns False on any error."""
    from database import _redis_send_command

    try:
        safe_key = hashlib.sha256(
            f"{client_key}:{bucket}".encode("utf-8")
        ).hexdigest()
        redis_key = f"raptor:ratelimit:{safe_key}"
        response = _redis_send_command("INCR", redis_key)
        if not response or response.startswith(b"-"):
            return False
        current = 0
        if response.startswith(b":"):
            current = int(response[1:].split(b"\r\n", 1)[0])
        if current == 1:
            _redis_send_command("EXPIRE", redis_key, str(max(int(window), 1)))
        if current > limit:
            raise HTTPException(
                status_code=429, detail="Rate limit exceeded; retry later"
            )
        return True
    except HTTPException:
        raise
    except Exception:
        return False


# ── Feed URL validation ───────────────────────────────────────────────────────

# ── Audit log helper ─────────────────────────────────────────────────────────

def audit_log(
    request: Optional[Request],
    action: str,
    investigation_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    """Resolve actor and IP from *request*, then append a tamper-evident audit entry."""
    from database import audit_log as _db_audit_log  # avoid top-level cycle

    actor = "system"
    ip_address = ""
    if request is not None:
        actor = _authenticated_actor(request)
        client = getattr(request, "client", None)
        if client:
            ip_address = getattr(client, "host", "")
    _db_audit_log(actor, action, investigation_id, detail, ip_address)


def validate_feed_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FEED_HOSTS:
        raise RuntimeError(
            "External feed URL must be HTTPS and on the approved allowlist"
        )
    return url
