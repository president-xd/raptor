"""
RAPTOR | Health Router
GET /api/v1/health          — fast liveness probe (no external calls)
GET /api/v1/health/detailed — subsystem status (bounded TCP probes)
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from fastapi import APIRouter, Request

from auth_core import _has_role, audit_log, require_role
from config import (
    CISA_KEV_CACHE_PATH,
    ELASTICSEARCH_URL,
    EVIDENCE_DIR,
    EVIDENCE_ENCRYPTION_KEY,
    LLM_API_KEY,
    LLM_MODEL,
    LLM_PROVIDER,
    RAPTOR_API_KEY,
    RAPTOR_ALLOW_AUTH_DISABLED,
    RAPTOR_DB_ENGINE,
    RAPTOR_PRODUCTION,
    REDIS_URL,
    WEAVIATE_URL,
)
from database import _utcnow, db_connect

router = APIRouter(tags=["health"])


@router.get("/api/v1/health")
async def health_check() -> dict:
    """Fast liveness probe — does not touch any external service."""
    db_status = "healthy"
    try:
        conn = db_connect(timeout=1)
        conn.execute("SELECT 1")
        conn.close()
    except Exception:
        db_status = "degraded"

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "service": "RAPTOR API",
        "version": "1.0.0",
        "timestamp": _utcnow(),
        "subsystems": {
            "api": {"status": "healthy", "detail": "FastAPI runtime responsive"},
            "database": {
                "status": db_status,
                "backend": RAPTOR_DB_ENGINE,
                "detail": "query ok" if db_status == "healthy" else "query failed",
            },
        },
    }


@router.get("/api/v1/health/detailed")
async def health_check_detailed(request: Request) -> dict:
    """Bounded subsystem health — TCP probes with 500 ms timeout each."""
    principal = require_role(request, "viewer")
    full_details = _has_role(principal, "admin") or "service" in principal.get("roles", [])

    checks: dict = {
        "api": {"status": "healthy", "detail": "FastAPI runtime responsive"},
        "database": {"status": "healthy", "backend": RAPTOR_DB_ENGINE, "detail": ""},
        "auth": {
            "status": "healthy",
            "detail": "API key auth enabled" if RAPTOR_API_KEY else "API key missing",
        },
        "evidence": {"status": "healthy", "detail": ""},
        "evidence_encryption": {"status": "healthy", "detail": ""},
        "neo4j": {"status": "degraded", "detail": "unreachable"},
        "weaviate": {"status": "degraded", "detail": "unreachable"},
        "elasticsearch": {"status": "degraded", "detail": "unreachable"},
        "redis": {"status": "degraded", "detail": "unreachable"},
        "cisa_kev": {"status": "degraded", "detail": "not cached"},
        "llm": {
            "status": "degraded",
            "detail": f"{LLM_PROVIDER} API key missing",
        },
    }

    # ── Database ──────────────────────────────────────────────────────────────
    try:
        conn = db_connect(timeout=1)
        conn.execute("SELECT 1")
        conn.close()
        checks["database"] = {
            "status": "healthy",
            "backend": RAPTOR_DB_ENGINE,
            "detail": "query ok",
        }
    except Exception as exc:
        checks["database"] = {
            "status": "degraded",
            "backend": RAPTOR_DB_ENGINE,
            "detail": str(exc),
        }

    # ── Evidence store ────────────────────────────────────────────────────────
    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        test_path = EVIDENCE_DIR / ".health"
        test_path.write_text("ok", encoding="utf-8")
        test_path.unlink(missing_ok=True)
        checks["evidence"] = {"status": "healthy", "detail": str(EVIDENCE_DIR)}
    except Exception as exc:
        checks["evidence"] = {"status": "degraded", "detail": str(exc)}

    checks["evidence_encryption"] = (
        {"status": "healthy", "detail": "EVIDENCE_ENCRYPTION_KEY configured"}
        if EVIDENCE_ENCRYPTION_KEY
        else {
            "status": "degraded",
            "detail": "EVIDENCE_ENCRYPTION_KEY missing; evidence stored without encryption",
        }
    )

    # ── External services (TCP probes) ────────────────────────────────────────
    import os
    checks["neo4j"] = _tcp_status("Neo4j", os.getenv("NEO4J_URI", "bolt://localhost:7687"), 7687)
    checks["weaviate"] = _tcp_status("Weaviate", WEAVIATE_URL, 8080)
    checks["elasticsearch"] = _tcp_status("Elasticsearch", ELASTICSEARCH_URL, 9200)

    # Redis: send a PING without requiring an extra package
    try:
        parsed = urlparse(REDIS_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        with socket.create_connection((host, port), timeout=0.5) as conn:  # type: ignore[assignment]
            conn.sendall(b"*1\r\n$4\r\nPING\r\n")
            resp = conn.recv(32)
        ready = resp.startswith(b"+PONG")
        checks["redis"] = {
            "status": "healthy" if ready else "degraded",
            "detail": (
                "connected; used for rate limiting and JSON cache"
                if ready
                else "unexpected ping response"
            ),
        }
    except Exception as exc:
        checks["redis"] = {"status": "degraded", "detail": str(exc)}

    # ── CISA KEV cache ────────────────────────────────────────────────────────
    if CISA_KEV_CACHE_PATH.exists():
        checks["cisa_kev"] = {
            "status": "healthy",
            "detail": f"cached at {CISA_KEV_CACHE_PATH}",
        }
    else:
        checks["cisa_kev"] = {
            "status": "degraded",
            "detail": "cache not populated; call GET /api/v1/threat-feeds/cisa-kev",
        }

    # ── LLM ──────────────────────────────────────────────────────────────────
    if LLM_API_KEY:
        checks["llm"] = {
            "status": "healthy",
            "detail": f"{LLM_PROVIDER}/{LLM_MODEL} configured",
        }

    # ── Auth ──────────────────────────────────────────────────────────────────
    if not RAPTOR_API_KEY and not RAPTOR_ALLOW_AUTH_DISABLED:
        checks["auth"] = {
            "status": "degraded",
            "detail": "RAPTOR_API_KEY missing and auth-disabled mode is not allowed",
        }
    elif not RAPTOR_API_KEY and RAPTOR_ALLOW_AUTH_DISABLED:
        checks["auth"] = {
            "status": "degraded",
            "detail": "API key auth explicitly disabled for local development",
        }

    overall = (
        "degraded"
        if any(v.get("status") != "healthy" for v in checks.values())
        else "healthy"
    )

    # Redact detail strings for non-admin callers
    if not full_details:
        for entry in checks.values():
            if "detail" in entry:
                entry["detail"] = "redacted; admin role required"

    return {
        "status": overall,
        "service": "RAPTOR API",
        "version": "1.0.0",
        "timestamp": _utcnow(),
        "subsystems": checks,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _endpoint_host_port(endpoint: str, default_port: int) -> tuple[str, int]:
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname, parsed.port or default_port
    cleaned = (
        endpoint.replace("http://", "")
        .replace("https://", "")
        .replace("bolt://", "")
        .split("/")[0]
    )
    if ":" in cleaned:
        host, port_str = cleaned.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host, default_port
    return cleaned or "localhost", default_port


def _tcp_status(
    name: str, endpoint: str, default_port: int, timeout_s: float = 0.5
) -> dict:
    try:
        host, port = _endpoint_host_port(endpoint, default_port)
        with socket.create_connection((host, port), timeout=timeout_s):
            pass
        return {"status": "healthy", "detail": f"{name} reachable at {host}:{port}"}
    except Exception as exc:
        return {"status": "degraded", "detail": str(exc)}
