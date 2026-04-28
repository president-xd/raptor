"""
RAPTOR | FastAPI Application
All 7 API endpoints per spec Section 7.1.
Background processing with persistent SQLite job state.
"""
import os
import sys
import json
import uuid
import asyncio
import sqlite3
import traceback
import socket
import hashlib
import hmac
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

# Ensure backend dir is on path
sys.path.insert(0, os.path.dirname(__file__))

from config import (
    API_HOST,
    API_PORT,
    DB_PATH,
    MAX_UPLOAD_BYTES,
    CORS_ALLOW_ORIGINS,
    CORS_ALLOW_CREDENTIALS,
    ELASTICSEARCH_URL,
    ELASTIC_INDEX_PREFIX,
    WEAVIATE_URL,
    ELASTIC_POLL_ENABLED,
    ELASTIC_POLL_QUERY,
    ELASTIC_POLL_INTERVAL_SECONDS,
    ELASTIC_POLL_WINDOW_MINUTES,
    REDIS_URL,
    REDIS_CACHE_TTL_SECONDS,
    RAPTOR_API_KEY,
    RAPTOR_AUTH_EXEMPT_HEALTH,
    RAPTOR_ALLOW_AUTH_DISABLED,
    RAPTOR_SESSION_COOKIE_SECURE,
    EVIDENCE_DIR,
    CISA_KEV_URL,
    CISA_KEV_CACHE_PATH,
)
from schema import (
    RaptorEvent, Finding, AnalysisResult, AttributionResult,
    SimulationPrediction, AttackGraph
)
from models import (
    InvestigateResponse, InvestigationStatus, InvestigationReport, InvestigationListResponse,
    InvestigationListItem, InvestigateTextRequest,
    SimulateRequest, SimulationResponse,
    QueryRequest, QueryResponse,
    APTProfileSummary, APTProfileListResponse,
    EvidenceFileSummary, EvidenceListResponse,
    AuthSessionRequest, AuthSessionResponse,
    AuditEntry, AuditLogResponse,
    CisaKevVulnerability, CisaKevResponse,
    ElasticPollRequest, ElasticPollResponse, ElasticPollStatus,
)

# ─── App Setup ────────────────────────────────────────────────────────

app = FastAPI(
    title="RAPTOR API",
    description="Retrieval-Augmented Persistent Threat Orchestration and Reasoning",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _make_session_token() -> str:
    expires_at = str(int(time.time()) + (8 * 60 * 60))
    signature = hmac.new(
        RAPTOR_API_KEY.encode("utf-8"),
        expires_at.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{expires_at}.{signature}"


def _valid_session_token(token: str) -> bool:
    if not RAPTOR_API_KEY or "." not in token:
        return False
    expires_at, supplied_signature = token.split(".", 1)
    try:
        if int(expires_at) < int(time.time()):
            return False
    except ValueError:
        return False
    expected_signature = hmac.new(
        RAPTOR_API_KEY.encode("utf-8"),
        expires_at.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(supplied_signature, expected_signature)


@app.middleware("http")
async def optional_api_key_auth(request: Request, call_next):
    """Require an API key when RAPTOR_API_KEY is configured."""
    path = request.url.path
    public_paths = {"/", "/docs", "/redoc", "/openapi.json", "/api/v1/auth/session"}
    if path in public_paths:
        return await call_next(request)
    if RAPTOR_AUTH_EXEMPT_HEALTH and path == "/api/v1/health":
        return await call_next(request)
    if not path.startswith("/api/"):
        return await call_next(request)

    if not RAPTOR_API_KEY:
        if RAPTOR_ALLOW_AUTH_DISABLED:
            return await call_next(request)
        return JSONResponse(
            status_code=503,
            content={"detail": "RAPTOR_API_KEY is not configured; API routes are unavailable"},
        )

    supplied = request.headers.get("x-raptor-api-key", "")
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        supplied = auth_header.split(" ", 1)[1].strip()
    if not supplied:
        session_token = request.cookies.get("raptor_session", "")
        if _valid_session_token(session_token):
            supplied = RAPTOR_API_KEY

    if not hmac.compare_digest(supplied, RAPTOR_API_KEY):
        return JSONResponse(
            status_code=401,
            content={"detail": "Valid X-RAPTOR-API-Key or Bearer token required"},
        )

    return await call_next(request)

# ─── SQLite Job State ────────────────────────────────────────────────

def init_db():
    """Initialize SQLite database for job tracking."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            name TEXT DEFAULT '',
            source TEXT DEFAULT '',
            input_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued',
            progress INTEGER DEFAULT 0,
            current_phase TEXT DEFAULT '',
            error TEXT,
            findings_json TEXT,
            attack_sequence_json TEXT,
            anomalies_json TEXT,
            attribution_json TEXT,
            graph_json TEXT,
            narrative_report TEXT,
            event_count INTEGER DEFAULT 0,
            technique_count INTEGER DEFAULT 0,
            created_at TEXT,
            completed_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            original_filename TEXT DEFAULT '',
            stored_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER DEFAULT 0,
            content_type TEXT DEFAULT '',
            source TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT DEFAULT '',
            action TEXT NOT NULL,
            investigation_id TEXT,
            detail_json TEXT DEFAULT '{}',
            ip_address TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS elastic_poll_state (
            name TEXT PRIMARY KEY,
            enabled INTEGER DEFAULT 0,
            query TEXT DEFAULT '',
            interval_seconds INTEGER DEFAULT 0,
            window_minutes INTEGER DEFAULT 0,
            last_polled_at TEXT DEFAULT '',
            last_status TEXT DEFAULT '',
            last_error TEXT DEFAULT '',
            investigation_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS elastic_seen_events (
            event_key TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            hit_index TEXT DEFAULT '',
            hit_id TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END
    """)
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(investigations)").fetchall()
    }
    migrations = {
        "name": "ALTER TABLE investigations ADD COLUMN name TEXT DEFAULT ''",
        "source": "ALTER TABLE investigations ADD COLUMN source TEXT DEFAULT ''",
        "input_bytes": "ALTER TABLE investigations ADD COLUMN input_bytes INTEGER DEFAULT 0",
    }
    for column, statement in migrations.items():
        if column not in existing_columns:
            conn.execute(statement)
    conn.execute(
        """
        INSERT OR IGNORE INTO elastic_poll_state
        (name, enabled, query, interval_seconds, window_minutes)
        VALUES ('default', ?, ?, ?, ?)
        """,
        (
            1 if ELASTIC_POLL_ENABLED else 0,
            ELASTIC_POLL_QUERY,
            ELASTIC_POLL_INTERVAL_SECONDS,
            ELASTIC_POLL_WINDOW_MINUTES,
        ),
    )
    conn.execute(
        """
        UPDATE elastic_poll_state
        SET enabled = ?, query = ?, interval_seconds = ?, window_minutes = ?
        WHERE name = 'default'
        """,
        (
            1 if ELASTIC_POLL_ENABLED else 0,
            ELASTIC_POLL_QUERY,
            ELASTIC_POLL_INTERVAL_SECONDS,
            ELASTIC_POLL_WINDOW_MINUTES,
        ),
    )
    conn.commit()
    conn.close()

init_db()


def db_get(inv_id: str) -> Optional[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def db_update(inv_id: str, **kwargs):
    conn = sqlite3.connect(str(DB_PATH))
    sets = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [inv_id]
    conn.execute(f"UPDATE investigations SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def db_create(inv_id: str, metadata: Optional[dict] = None, input_bytes: int = 0):
    metadata = metadata or {}
    name = str(metadata.get("case_name") or "").strip()
    if not name:
        filename = str(metadata.get("filename") or "").strip()
        if filename:
            name = filename
    source = str(metadata.get("source") or "file").strip()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """
        INSERT INTO investigations (id, name, source, input_bytes, status, created_at)
        VALUES (?, ?, ?, ?, 'queued', ?)
        """,
        (inv_id, name, source, input_bytes, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def _safe_filename(value: str, default: str = "raw.log") -> str:
    name = Path(value or default).name
    cleaned = "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "_" for ch in name)
    return cleaned or default


def store_evidence_file(
    investigation_id: str,
    content: bytes,
    metadata: Optional[dict] = None,
) -> dict:
    """Persist raw evidence bytes and record metadata in SQLite."""
    metadata = metadata or {}
    case_dir = EVIDENCE_DIR / investigation_id
    case_dir.mkdir(parents=True, exist_ok=True)

    original = _safe_filename(metadata.get("filename") or metadata.get("case_name") or "raw.log")
    source = str(metadata.get("source") or "unknown")
    stored_name = f"{time.time_ns()}_{uuid.uuid4().hex[:12]}_{original}"
    stored_path = case_dir / stored_name
    stored_path.write_bytes(content)

    sha256 = hashlib.sha256(content).hexdigest()
    created_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.execute(
        """
        INSERT INTO evidence_files
        (investigation_id, original_filename, stored_path, sha256, size_bytes,
         content_type, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            investigation_id,
            original,
            str(stored_path),
            sha256,
            len(content),
            str(metadata.get("content_type") or "text/plain"),
            source,
            created_at,
        ),
    )
    conn.commit()
    evidence_id = cur.lastrowid
    conn.close()
    return {
        "id": evidence_id,
        "investigation_id": investigation_id,
        "original_filename": original,
        "stored_path": str(stored_path),
        "sha256": sha256,
        "size_bytes": len(content),
        "content_type": str(metadata.get("content_type") or "text/plain"),
        "source": source,
        "created_at": created_at,
    }


def list_evidence_files(investigation_id: str) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, investigation_id, original_filename, stored_path, sha256,
               size_bytes, content_type, source, created_at
        FROM evidence_files
        WHERE investigation_id = ?
        ORDER BY id DESC
        """,
        (investigation_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def audit_log(
    request: Optional[Request],
    action: str,
    investigation_id: Optional[str] = None,
    detail: Optional[dict] = None,
):
    """Append a lightweight audit event."""
    actor = "system"
    ip_address = ""
    if request is not None:
        actor = _authenticated_actor(request)
        if request.client:
            ip_address = request.client.host

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """
        INSERT INTO audit_log
        (timestamp, actor, action, investigation_id, detail_json, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            actor,
            action,
            investigation_id,
            json.dumps(detail or {}, default=str),
            ip_address,
        ),
    )
    conn.commit()
    conn.close()


def _authenticated_actor(request: Request) -> str:
    """Derive audit actor from trusted authentication state, not user-supplied identity headers."""
    if not RAPTOR_API_KEY:
        return "local-auth-disabled" if RAPTOR_ALLOW_AUTH_DISABLED else "unauthenticated"

    supplied = request.headers.get("x-raptor-api-key", "")
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        supplied = auth_header.split(" ", 1)[1].strip()
    if supplied and hmac.compare_digest(supplied, RAPTOR_API_KEY):
        return "api-key"

    session_token = request.cookies.get("raptor_session", "")
    if _valid_session_token(session_token):
        return "browser-session"

    return "authenticated-request"


def list_audit_entries(limit: int = 100, investigation_id: Optional[str] = None) -> list[dict]:
    safe_limit = max(1, min(limit, 500))
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if investigation_id:
        rows = conn.execute(
            """
            SELECT id, timestamp, actor, action, investigation_id, detail_json, ip_address
            FROM audit_log
            WHERE investigation_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (investigation_id, safe_limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, timestamp, actor, action, investigation_id, detail_json, ip_address
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    conn.close()

    entries = []
    for row in rows:
        item = dict(row)
        try:
            item["detail"] = json.loads(item.pop("detail_json") or "{}")
        except Exception:
            item["detail"] = {}
        entries.append(item)
    return entries


def start_investigation_from_content(
    background_tasks: BackgroundTasks,
    log_content: str,
    metadata: Optional[dict] = None,
    raw_bytes: Optional[bytes] = None,
) -> InvestigateResponse:
    """Validate log text, persist a queued job, and launch the pipeline."""
    if not log_content or not log_content.strip():
        raise HTTPException(status_code=400, detail="Investigation input is empty")

    byte_count = len(log_content.encode("utf-8", errors="replace"))
    if byte_count > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Input too large ({byte_count} bytes). Max allowed is {MAX_UPLOAD_BYTES} bytes.",
        )

    investigation_id = str(uuid.uuid4())
    db_create(investigation_id, metadata, byte_count)
    store_evidence_file(
        investigation_id,
        raw_bytes if raw_bytes is not None else log_content.encode("utf-8", errors="replace"),
        metadata,
    )
    background_tasks.add_task(run_investigation, investigation_id, log_content, metadata or {})

    logger.info(f"Investigation {investigation_id} started ({byte_count} bytes)")
    return InvestigateResponse(
        investigation_id=investigation_id,
        status="queued",
        message=f"Investigation started. {byte_count} bytes of logs received.",
    )


def start_investigation_now(
    log_content: str,
    metadata: Optional[dict] = None,
    raw_bytes: Optional[bytes] = None,
) -> InvestigateResponse:
    """Create an investigation outside FastAPI BackgroundTasks."""
    if not log_content or not log_content.strip():
        raise HTTPException(status_code=400, detail="Investigation input is empty")

    byte_count = len(log_content.encode("utf-8", errors="replace"))
    if byte_count > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Input too large ({byte_count} bytes). Max allowed is {MAX_UPLOAD_BYTES} bytes.",
        )

    investigation_id = str(uuid.uuid4())
    db_create(investigation_id, metadata, byte_count)
    store_evidence_file(
        investigation_id,
        raw_bytes if raw_bytes is not None else log_content.encode("utf-8", errors="replace"),
        metadata,
    )
    thread = threading.Thread(
        target=run_investigation,
        args=(investigation_id, log_content, metadata or {}),
        daemon=True,
    )
    thread.start()
    audit_log(
        None,
        "investigation.created",
        investigation_id,
        {
            "source": metadata.get("source") or "unknown",
            "case_name": metadata.get("case_name") or "",
            "filename": metadata.get("filename") or "",
        },
    )
    return InvestigateResponse(
        investigation_id=investigation_id,
        status="queued",
        message=f"Investigation started. {byte_count} bytes of logs received.",
    )


def fetch_elasticsearch_logs(
    query: str,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    limit: int = 500,
) -> str:
    """Fetch matching Elasticsearch documents and serialize them as JSON lines."""
    if not query or not query.strip():
        raise HTTPException(status_code=400, detail="Elasticsearch query is required")

    try:
        from elasticsearch import Elasticsearch

        client = Elasticsearch(ELASTICSEARCH_URL, request_timeout=10)
        filters = []
        time_range = {}
        if time_range_start:
            time_range["gte"] = time_range_start
        if time_range_end:
            time_range["lte"] = time_range_end
        if time_range:
            filters.append({"range": {"@timestamp": time_range}})

        response = client.search(
            index=f"{ELASTIC_INDEX_PREFIX}*",
            body={
                "query": {
                    "bool": {
                        "must": [{"query_string": {"query": query}}],
                        "filter": filters,
                    }
                },
                "size": max(1, min(limit, 1000)),
                "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
            },
            ignore_unavailable=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            raise HTTPException(status_code=404, detail="No Elasticsearch events matched that query")
        lines = []
        for hit in hits:
            source = hit.get("_source", {}) or {}
            event = dict(source)
            event["_raptor_elastic"] = {
                "index": hit.get("_index", ""),
                "id": hit.get("_id", ""),
                "sort": hit.get("sort", []),
            }
            lines.append(json.dumps(event, default=str))
        return "\n".join(lines)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Elasticsearch investigation query failed: {e}")
        raise HTTPException(status_code=503, detail=f"Elasticsearch unavailable: {e}")


def _redis_send_command(*parts: str) -> Optional[bytes]:
    """Tiny Redis RESP client for cache use without an extra dependency."""
    try:
        parsed = urlparse(REDIS_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        db = parsed.path.strip("/") if parsed.path and parsed.path != "/" else ""

        def encode_command(*command_parts: str) -> bytes:
            payload = f"*{len(command_parts)}\r\n".encode("utf-8")
            for part in command_parts:
                raw = str(part).encode("utf-8")
                payload += f"${len(raw)}\r\n".encode("utf-8") + raw + b"\r\n"
            return payload

        def read_response(conn) -> bytes:
            chunks = []
            while True:
                try:
                    chunk = conn.recv(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    data = b"".join(chunks)
                    if data.startswith((b"+", b"-", b":")) and data.endswith(b"\r\n"):
                        break
                    if data.startswith(b"$") and b"\r\n" in data:
                        head, body = data.split(b"\r\n", 1)
                        expected = int(head[1:])
                        if expected < 0 or len(body) >= expected + 2:
                            break
                    if data.startswith(b"*") and parts and str(parts[0]).upper() != "GET":
                        break
                except socket.timeout:
                    break
            return b"".join(chunks)

        with socket.create_connection((host, port), timeout=3) as raw_conn:
            conn = raw_conn
            if parsed.scheme == "rediss":
                import ssl
                conn = ssl.create_default_context().wrap_socket(raw_conn, server_hostname=host)
            conn.settimeout(1)
            if parsed.password:
                auth_parts = ("AUTH", parsed.username, parsed.password) if parsed.username else ("AUTH", parsed.password)
                conn.sendall(encode_command(*auth_parts))
                auth_response = read_response(conn)
                if auth_response.startswith(b"-"):
                    logger.debug(f"Redis AUTH failed: {auth_response[:120]!r}")
                    return None
            if db:
                conn.sendall(encode_command("SELECT", db))
                select_response = read_response(conn)
                if select_response.startswith(b"-"):
                    logger.debug(f"Redis SELECT failed: {select_response[:120]!r}")
                    return None
            conn.sendall(encode_command(*parts))
            return read_response(conn)
    except Exception as e:
        logger.debug(f"Redis command skipped: {e}")
        return None


def redis_get_json(key: str) -> Optional[dict]:
    response = _redis_send_command("GET", key)
    if not response or response.startswith(b"$-1"):
        return None
    try:
        head, body = response.split(b"\r\n", 1)
        if not head.startswith(b"$"):
            return None
        length = int(head[1:])
        raw = body[:length]
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def redis_set_json(key: str, value: dict, ttl_seconds: int = REDIS_CACHE_TTL_SECONDS) -> bool:
    payload = json.dumps(value, default=str)
    if ttl_seconds > 0:
        response = _redis_send_command("SET", key, payload, "EX", str(ttl_seconds))
    else:
        response = _redis_send_command("SET", key, payload)
    return bool(response and response.startswith(b"+OK"))


def fetch_cisa_kev(refresh: bool = False) -> dict:
    """Fetch the CISA KEV catalog with Redis and file cache fallback."""
    cache_key = "raptor:cisa_kev"
    if not refresh:
        cached = redis_get_json(cache_key)
        if cached:
            return cached
        if CISA_KEV_CACHE_PATH.exists():
            try:
                return json.loads(CISA_KEV_CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass

    try:
        import requests
        response = requests.get(
            CISA_KEV_URL,
            timeout=30,
            headers={"User-Agent": "RAPTOR/1.0 threat-intel-connector"},
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as e:
        if CISA_KEV_CACHE_PATH.exists():
            logger.warning(f"CISA KEV refresh failed, using file cache: {e}")
            return json.loads(CISA_KEV_CACHE_PATH.read_text(encoding="utf-8"))
        raise HTTPException(status_code=503, detail=f"CISA KEV feed unavailable: {e}")

    payload["_raptor_cached_at"] = datetime.utcnow().isoformat()
    payload["_raptor_source"] = CISA_KEV_URL
    CISA_KEV_CACHE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    redis_set_json(cache_key, payload)
    return payload


def db_list(limit: int = 25) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, name, source, input_bytes, status, progress, current_phase, error,
               event_count, technique_count, created_at, completed_at,
               attribution_json, graph_json
        FROM investigations
        ORDER BY datetime(created_at) DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [_summarize_investigation_row(dict(row)) for row in rows]


def update_elastic_poll_state(**kwargs):
    if not kwargs:
        return
    conn = sqlite3.connect(str(DB_PATH))
    sets = ", ".join(f"{key} = ?" for key in kwargs)
    values = list(kwargs.values()) + ["default"]
    conn.execute(f"UPDATE elastic_poll_state SET {sets} WHERE name = ?", values)
    conn.commit()
    conn.close()


def get_elastic_poll_state() -> dict:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT enabled, query, interval_seconds, window_minutes,
               last_polled_at, last_status, last_error, investigation_count
        FROM elastic_poll_state
        WHERE name = 'default'
        """
    ).fetchone()
    conn.close()
    if not row:
        return {}
    data = dict(row)
    data["enabled"] = bool(data.get("enabled"))
    return data


def increment_elastic_poll_investigations():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """
        UPDATE elastic_poll_state
        SET investigation_count = coalesce(investigation_count, 0) + 1
        WHERE name = 'default'
        """
    )
    conn.commit()
    conn.close()


def filter_new_elasticsearch_events(content: str) -> tuple[str, int]:
    """Drop Elasticsearch events already ingested by previous poll runs."""
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return "", 0

    now = datetime.utcnow().isoformat()
    accepted: list[str] = []
    duplicates = 0
    conn = sqlite3.connect(str(DB_PATH))
    try:
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"raw": line}
            meta = event.get("_raptor_elastic", {}) if isinstance(event, dict) else {}
            hit_index = str(meta.get("index", ""))
            hit_id = str(meta.get("id", ""))
            if hit_index and hit_id:
                event_key = f"{hit_index}:{hit_id}"
            else:
                event_key = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
            try:
                conn.execute(
                    """
                    INSERT INTO elastic_seen_events
                    (event_key, first_seen_at, last_seen_at, hit_index, hit_id)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (event_key, now, now, hit_index, hit_id),
                )
                accepted.append(line)
            except sqlite3.IntegrityError:
                duplicates += 1
                conn.execute(
                    "UPDATE elastic_seen_events SET last_seen_at = ? WHERE event_key = ?",
                    (now, event_key),
                )
        conn.commit()
    finally:
        conn.close()
    return "\n".join(accepted), duplicates


def _summarize_investigation_row(row: dict) -> dict:
    """Add frontend-ready summary fields without requiring extra database columns."""
    attribution = []
    try:
        attribution = json.loads(row.get("attribution_json") or "[]")
    except Exception:
        attribution = []

    top = attribution[0] if attribution else {}
    row["top_candidate"] = top.get("apt_name", "") if isinstance(top, dict) else ""
    row["confidence_score"] = float(top.get("confidence_score", 0.0) or 0.0) if isinstance(top, dict) else 0.0
    row["confidence_label"] = top.get("confidence_label", "") if isinstance(top, dict) else ""

    host_count = 0
    try:
        graph = json.loads(row.get("graph_json") or "{}")
        host_count = sum(1 for node in graph.get("nodes", []) if node.get("node_type") == "host")
    except Exception:
        host_count = 0
    row["host_count"] = host_count

    row["name"] = row.get("name") or f"Investigation {row.get('id', '')[:8]}"
    row["source"] = row.get("source") or "unknown"
    row["input_bytes"] = row.get("input_bytes") or 0
    row.pop("attribution_json", None)
    row.pop("graph_json", None)
    return row


# ─── Background Investigation Pipeline ──────────────────────────────

def run_investigation(investigation_id: str, log_content: str, metadata: Optional[dict] = None):
    """Full investigation pipeline running in background thread (sync, NOT async).
    
    IMPORTANT: This MUST be a sync function (not async) so that FastAPI's
    BackgroundTasks runs it in a thread pool. If this were async, it would
    block the event loop and make ALL endpoints unresponsive during analysis.
    """
    metadata = metadata or {}
    try:
        db_update(investigation_id, status="processing", progress=5,
                  current_phase="Parsing logs")

        # Phase 1: Parse and normalize logs
        from ingestion.normalizer import LogNormalizer
        normalizer = LogNormalizer()
        events = normalizer.normalize_content(log_content)
        db_update(investigation_id, progress=15,
                  current_phase="Log parsing complete", event_count=len(events))
        logger.info(f"[{investigation_id}] Parsed {len(events)} events")

        # Phase 2: RAG Analysis
        db_update(investigation_id, progress=25, current_phase="RAG analysis (LLM reasoning)")
        from rag.pipeline import analyze_events_batch
        analysis = analyze_events_batch(events)
        logger.info(f"[{investigation_id}] Analysis: {len(analysis.findings)} findings")

        # Phase 3: STIX Validation (non-negotiable)
        db_update(investigation_id, progress=45, current_phase="Validating technique IDs (STIX)")
        from attribution.stix_validator import validate_analysis_result
        analysis = validate_analysis_result(analysis)
        logger.info(f"[{investigation_id}] After validation: {len(analysis.findings)} findings")

        # Phase 4: Build Attack Graph
        db_update(investigation_id, progress=55, current_phase="Building attack graph")
        attack_graph = AttackGraph(investigation_id=investigation_id, nodes=[], edges=[])
        graph_json = attack_graph.model_dump_json()
        neo4j = None
        try:
            from graph.neo4j_client import Neo4jClient
            from graph.graph_builder import GraphBuilder
            neo4j = Neo4jClient()
            if neo4j.is_connected():
                neo4j.setup_schema()
                builder = GraphBuilder(neo4j)
                attack_graph = builder.build_graph(investigation_id, events, analysis)
                graph_json = attack_graph.model_dump_json()
            else:
                # Build graph without Neo4j (in-memory only)
                builder = GraphBuilder.__new__(GraphBuilder)
                builder.neo4j = type('Mock', (), {'run_write': lambda *a, **kw: None, 'run_query': lambda *a, **kw: []})()
                builder.investigation_id = investigation_id
                attack_graph = builder._build_sigma_graph(
                    builder._extract_hosts(events),
                    builder._extract_users(events),
                    builder._extract_techniques(analysis),
                    events, analysis
                )
                graph_json = attack_graph.model_dump_json()
        except Exception as e:
            logger.warning(f"Graph building error (non-fatal): {e}")
        finally:
            if neo4j:
                neo4j.close()

        # Phase 5: APT Attribution
        db_update(investigation_id, progress=70, current_phase="APT attribution scoring")
        from attribution.apt_profiles import load_apt_profiles
        from attribution.confidence import calculate_confidence

        observed_ttps = set()
        for f in analysis.findings:
            if f.technique_id:
                observed_ttps.add(f.technique_id)
        for tid in analysis.attack_sequence:
            observed_ttps.add(tid)

        apt_profiles = load_apt_profiles()
        apt_filters = [
            str(item).strip().lower()
            for item in metadata.get("apt_filters", [])
            if str(item).strip()
        ]
        if apt_filters:
            filtered_profiles = {}
            for apt_name, profile in apt_profiles.items():
                aliases = [str(alias).lower() for alias in profile.get("aliases", [])]
                haystack = [apt_name.lower(), *aliases]
                if any(filter_value in value for filter_value in apt_filters for value in haystack):
                    filtered_profiles[apt_name] = profile
            if filtered_profiles:
                apt_profiles = filtered_profiles
                analysis.anomalies.append(
                    f"APT focus filter applied: {', '.join(metadata.get('apt_filters', []))}"
                )
            else:
                analysis.anomalies.append(
                    f"APT focus filter matched no profiles; scored full library instead."
                )

        # Calculate campaign duration from events
        campaign_hours = 0
        if events:
            timestamps = sorted([e.timestamp for e in events if e.timestamp])
            if len(timestamps) >= 2:
                try:
                    from datetime import datetime as dt
                    t1 = dt.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                    t2 = dt.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                    campaign_hours = (t2 - t1).total_seconds() / 3600
                except Exception:
                    pass

        attribution_results = calculate_confidence(
            observed_ttps=observed_ttps,
            apt_profiles=apt_profiles,
            campaign_duration_hours=campaign_hours,
        )
        attribution_json = json.dumps([a.model_dump() for a in attribution_results])
        logger.info(f"[{investigation_id}] Attribution: {attribution_results[0].apt_name if attribution_results else 'None'}")

        # Phase 6: Generate Report
        db_update(investigation_id, progress=85, current_phase="Generating analyst report")
        from report.generator import generate_report

        graph_summary = {
            "hosts_compromised": sum(
                1 for n in (attack_graph.nodes or [])
                if n.node_type == "host" and bool(n.metadata.get("compromised"))
            ) if attack_graph else sum(1 for e in events if e.event_type == "lateral"),
            "total_events": len(events),
            "unique_hosts": len(set(e.source_host for e in events if e.source_host)),
            "campaign_duration_hours": campaign_hours,
        }

        narrative = generate_report(analysis, attribution_results, graph_summary, investigation_id)

        # Save results
        findings_json = json.dumps([f.model_dump() for f in analysis.findings])
        seq_json = json.dumps(analysis.attack_sequence)
        anomalies_json = json.dumps(analysis.anomalies)

        db_update(
            investigation_id,
            status="complete", progress=100,
            current_phase="Investigation complete",
            findings_json=findings_json,
            attack_sequence_json=seq_json,
            anomalies_json=anomalies_json,
            attribution_json=attribution_json,
            graph_json=graph_json,
            narrative_report=narrative,
            technique_count=len(analysis.findings),
            completed_at=datetime.utcnow().isoformat(),
        )
        logger.info(f"[{investigation_id}] Investigation complete!")

    except Exception as e:
        logger.error(f"[{investigation_id}] Investigation failed: {e}\n{traceback.format_exc()}")
        db_update(investigation_id, status="failed", error=str(e),
                  current_phase=f"Failed: {str(e)[:200]}")


def run_elasticsearch_poll_once(
    query: str = ELASTIC_POLL_QUERY,
    time_range_start: Optional[str] = None,
    time_range_end: Optional[str] = None,
    case_name: str = "",
    apt_filters: Optional[list[str]] = None,
) -> ElasticPollResponse:
    """Poll Elasticsearch once and create an investigation if events are found."""
    started_at = datetime.utcnow().isoformat()
    update_elastic_poll_state(last_polled_at=started_at, last_status="polling", last_error="")
    try:
        content = fetch_elasticsearch_logs(
            query=query,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
        )
    except HTTPException as e:
        if e.status_code == 404:
            update_elastic_poll_state(last_status="no_events", last_error="")
            return ElasticPollResponse(status="no_events", message=e.detail, event_bytes=0)
        update_elastic_poll_state(last_status="error", last_error=str(e.detail))
        raise

    content, duplicate_count = filter_new_elasticsearch_events(content)
    if not content.strip():
        update_elastic_poll_state(last_status="duplicate_events", last_error="")
        return ElasticPollResponse(
            status="no_events",
            message=f"All matched Elasticsearch events were already ingested ({duplicate_count} duplicates).",
            event_bytes=0,
        )

    metadata = {
        "source": "elasticsearch-poller",
        "filename": "elasticsearch_poll.jsonl",
        "case_name": case_name or f"Elasticsearch poll {started_at}",
        "elastic_query": query,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "apt_filters": apt_filters or [],
    }
    response = start_investigation_now(content, metadata=metadata)
    increment_elastic_poll_investigations()
    update_elastic_poll_state(
        last_status="investigation_created",
        last_error=f"deduped {duplicate_count} replayed events" if duplicate_count else "",
    )
    return ElasticPollResponse(
        status="investigation_created",
        message="Elasticsearch events queued for RAPTOR analysis.",
        investigation_id=response.investigation_id,
        event_bytes=len(content.encode("utf-8", errors="replace")),
    )


def elastic_poll_loop():
    """Simple opt-in Elasticsearch polling loop."""
    logger.info(
        f"Elasticsearch poller enabled: query={ELASTIC_POLL_QUERY!r}, "
        f"interval={ELASTIC_POLL_INTERVAL_SECONDS}s"
    )
    while True:
        try:
            run_elasticsearch_poll_once(
                query=ELASTIC_POLL_QUERY,
                time_range_start=f"now-{ELASTIC_POLL_WINDOW_MINUTES}m",
                time_range_end="now",
                case_name="Continuous Elasticsearch poll",
            )
        except Exception as e:
            logger.warning(f"Elasticsearch poller iteration failed: {e}")
            update_elastic_poll_state(last_status="error", last_error=str(e))
        time.sleep(max(30, ELASTIC_POLL_INTERVAL_SECONDS))


@app.on_event("startup")
def start_optional_elastic_poller():
    if not ELASTIC_POLL_ENABLED:
        return
    thread = threading.Thread(target=elastic_poll_loop, daemon=True)
    thread.start()


# ─── API Endpoints ───────────────────────────────────────────────────

@app.post("/api/v1/auth/session", response_model=AuthSessionResponse)
async def create_auth_session(payload: AuthSessionRequest, response: Response):
    """Exchange the operator-provided API key for an HttpOnly browser session cookie."""
    if not RAPTOR_API_KEY:
        raise HTTPException(status_code=503, detail="RAPTOR_API_KEY is not configured")
    if not hmac.compare_digest(payload.api_key, RAPTOR_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    response.set_cookie(
        "raptor_session",
        _make_session_token(),
        httponly=True,
        secure=RAPTOR_SESSION_COOKIE_SECURE,
        samesite="lax",
        max_age=8 * 60 * 60,
    )
    return AuthSessionResponse(authenticated=True)


@app.post("/api/v1/investigate", response_model=InvestigateResponse)
async def investigate(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    case_name: Optional[str] = Form(None),
):
    """
    Upload a log file and start an investigation.
    POST /api/v1/investigate
    """
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(content)} bytes). Max allowed is {MAX_UPLOAD_BYTES} bytes.",
        )

    log_content = content.decode('utf-8', errors='replace')
    response = start_investigation_from_content(
        background_tasks,
        log_content,
        {
            "source": "file",
            "filename": file.filename,
            "content_type": file.content_type or "application/octet-stream",
            "case_name": case_name or file.filename or "",
        },
        raw_bytes=content,
    )
    audit_log(
        request,
        "investigation.created",
        response.investigation_id,
        {"source": "file", "filename": file.filename, "case_name": case_name or file.filename or ""},
    )
    return response


@app.post("/api/v1/investigate/text", response_model=InvestigateResponse)
def investigate_text(request: Request, background_tasks: BackgroundTasks, payload: InvestigateTextRequest):
    """
    Start an investigation from pasted logs or an Elasticsearch query.
    POST /api/v1/investigate/text
    """
    log_content = payload.log_content or ""
    if not log_content.strip() and payload.elastic_query:
        log_content = fetch_elasticsearch_logs(
            payload.elastic_query,
            payload.time_range_start,
            payload.time_range_end,
        )

    response = start_investigation_from_content(
        background_tasks,
        log_content,
        {
            "source": payload.source,
            "filename": f"{payload.source or 'text'}_input.jsonl",
            "case_name": payload.case_name,
            "elastic_query": payload.elastic_query,
            "time_range_start": payload.time_range_start,
            "time_range_end": payload.time_range_end,
            "sensitivity": payload.sensitivity,
            "apt_filters": payload.apt_filters,
        },
    )
    audit_log(
        request,
        "investigation.created",
        response.investigation_id,
        {"source": payload.source, "case_name": payload.case_name},
    )
    return response


@app.get("/api/v1/investigations", response_model=InvestigationListResponse)
async def list_investigations(limit: int = 25):
    """List recent investigations for case management UX."""
    safe_limit = max(1, min(limit, 100))
    rows = db_list(safe_limit)
    items = [
        InvestigationListItem(
            investigation_id=row.get("id", ""),
            name=row.get("name") or "",
            source=row.get("source") or "",
            status=row.get("status", "queued"),
            progress=row.get("progress", 0) or 0,
            current_phase=row.get("current_phase") or "",
            event_count=row.get("event_count") or 0,
            technique_count=row.get("technique_count") or 0,
            host_count=row.get("host_count") or 0,
            input_bytes=row.get("input_bytes") or 0,
            top_candidate=row.get("top_candidate") or "",
            confidence_score=row.get("confidence_score") or 0.0,
            confidence_label=row.get("confidence_label") or "",
            created_at=row.get("created_at") or "",
            completed_at=row.get("completed_at"),
            error=row.get("error"),
        )
        for row in rows
    ]
    return InvestigationListResponse(investigations=items, total_count=len(items))


@app.get("/api/v1/investigate/{investigation_id}/status", response_model=InvestigationStatus)
async def get_status(investigation_id: str):
    """
    Check investigation status and progress.
    GET /api/v1/investigate/{id}/status
    """
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return InvestigationStatus(
        investigation_id=investigation_id,
        name=record.get("name") or "",
        status=record["status"],
        progress=record["progress"],
        current_phase=record["current_phase"] or "",
        error=record.get("error"),
    )


@app.get("/api/v1/investigate/{investigation_id}/report", response_model=InvestigationReport)
async def get_report(request: Request, investigation_id: str):
    """
    Get full investigation report.
    GET /api/v1/investigate/{id}/report
    """
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    findings = []
    if record.get("findings_json"):
        for f in json.loads(record["findings_json"]):
            findings.append(Finding(**f))

    attribution = []
    if record.get("attribution_json"):
        for a in json.loads(record["attribution_json"]):
            attribution.append(AttributionResult(**a))

    attack_seq = json.loads(record["attack_sequence_json"]) if record.get("attack_sequence_json") else []
    anomalies = json.loads(record["anomalies_json"]) if record.get("anomalies_json") else []
    audit_log(request, "report.viewed", investigation_id, {"status": record["status"]})

    return InvestigationReport(
        investigation_id=investigation_id,
        name=record.get("name") or "",
        status=record["status"],
        findings=findings,
        attack_sequence=attack_seq,
        anomalies=anomalies,
        attribution=attribution,
        narrative_report=record.get("narrative_report") or "",
        event_count=record.get("event_count") or 0,
        technique_count=record.get("technique_count") or 0,
        timestamp=record.get("created_at") or "",
    )


@app.get("/api/v1/investigate/{investigation_id}/graph")
async def get_graph(request: Request, investigation_id: str):
    """
    Get Sigma.js compatible attack graph JSON.
    GET /api/v1/investigate/{id}/graph
    """
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    graph_json = record.get("graph_json", "{}")
    audit_log(request, "graph.viewed", investigation_id, {})
    if graph_json:
        return JSONResponse(content=json.loads(graph_json))
    return JSONResponse(content={"nodes": [], "edges": []})


@app.get("/api/v1/investigate/{investigation_id}/evidence", response_model=EvidenceListResponse)
async def get_evidence(request: Request, investigation_id: str):
    """List persisted raw evidence metadata for an investigation."""
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    rows = list_evidence_files(investigation_id)
    audit_log(request, "evidence.listed", investigation_id, {"count": len(rows)})
    return EvidenceListResponse(
        investigation_id=investigation_id,
        evidence=[EvidenceFileSummary(**row) for row in rows],
        total_count=len(rows),
    )


@app.post("/api/v1/simulate", response_model=SimulationResponse)
def simulate(request: Request, payload: SimulateRequest):
    """
    Simulate next attack steps for attributed APT.
    POST /api/v1/simulate
    """
    record = db_get(payload.investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if record["status"] != "complete":
        raise HTTPException(status_code=400, detail="Investigation not complete yet")

    # Get attribution
    attribution_data = json.loads(record.get("attribution_json") or "[]")
    if not attribution_data:
        raise HTTPException(status_code=400, detail="No attribution data available")

    # Use specified APT group or top attribution
    target_apt = payload.apt_group
    attribution = None
    for a in attribution_data:
        attr = AttributionResult(**a)
        if target_apt and attr.apt_name == target_apt:
            attribution = attr
            break
        elif not target_apt:
            attribution = attr
            break

    if not attribution:
        attribution = AttributionResult(**attribution_data[0])

    if attribution.confidence_label in {"UNKNOWN", "LOW"}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Simulation blocked due to low-confidence attribution ({attribution.confidence_label}, "
                f"{attribution.confidence_score:.0%}). Refine evidence before prediction."
            ),
        )

    # Get findings for observed TTPs
    findings_data = json.loads(record.get("findings_json") or "[]")
    observed_ttps = [f.get("technique_id", "") for f in findings_data if f.get("technique_id")]

    compromised_hosts = []
    try:
        graph_data = json.loads(record.get("graph_json") or "{}")
        for node in graph_data.get("nodes", []):
            if node.get("node_type") == "host" and node.get("metadata", {}).get("compromised"):
                compromised_hosts.append(node.get("label") or node.get("id"))
    except Exception:
        compromised_hosts = []

    if not compromised_hosts:
        raise HTTPException(
            status_code=400,
            detail="Simulation requires at least one compromised host in the investigation graph.",
        )

    # Run simulation
    from simulation.predictor import predict_next_steps
    predictions = predict_next_steps(
        attribution=attribution,
        compromised_hosts=compromised_hosts,
        privilege_level="domain user / admin",
        observed_ttps=observed_ttps,
    )
    audit_log(
        request,
        "simulation.run",
        payload.investigation_id,
        {"apt_group": attribution.apt_name, "prediction_count": len(predictions)},
    )

    return SimulationResponse(
        investigation_id=payload.investigation_id,
        apt_group=attribution.apt_name,
        predictions=predictions,
        confidence=attribution.confidence_label,
    )


@app.get("/api/v1/apt/profiles", response_model=APTProfileListResponse)
def get_apt_profiles(request: Request):
    """
    List all APT group profiles with TTP counts.
    GET /api/v1/apt/profiles
    """
    from attribution.apt_profiles import load_apt_profiles, get_profile_summaries
    profiles = load_apt_profiles()
    summaries = get_profile_summaries(profiles)
    audit_log(request, "apt_profiles.listed", None, {"count": len(summaries)})

    return APTProfileListResponse(
        profiles=[APTProfileSummary(**s) for s in summaries],
        total_count=len(summaries),
    )


@app.post("/api/v1/query", response_model=QueryResponse)
def query(request: Request, payload: QueryRequest):
    """
    Natural language query against investigation.
    POST /api/v1/query
    """
    record = db_get(payload.investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if record["status"] != "complete":
        raise HTTPException(status_code=400, detail="Investigation not complete yet")

    from nlq.query_engine import QueryEngine
    neo4j = None
    try:
        from graph.neo4j_client import Neo4jClient
        neo4j = Neo4jClient()
    except Exception:
        neo4j = None

    engine = QueryEngine(neo4j_client=neo4j)
    try:
        result = engine.answer_question(payload.question, payload.investigation_id)
    finally:
        engine.close()
    audit_log(
        request,
        "query.asked",
        payload.investigation_id,
        {
            "query_type": result.get("query_type", ""),
            "question": payload.question[:200],
            "answer_preview": str(result.get("answer", ""))[:500],
            "source_count": len(result.get("sources", [])),
        },
    )

    return QueryResponse(
        answer=result.get("answer", ""),
        sources=result.get("sources", []),
        confidence=result.get("confidence", ""),
        query_type=result.get("query_type", ""),
    )


@app.get("/api/v1/audit", response_model=AuditLogResponse)
async def get_audit_log(
    request: Request,
    limit: int = 100,
    investigation_id: Optional[str] = None,
):
    """List recent append-only audit entries."""
    entries = list_audit_entries(limit=limit, investigation_id=investigation_id)
    audit_log(request, "audit.viewed", investigation_id, {"limit": limit})
    return AuditLogResponse(entries=[AuditEntry(**entry) for entry in entries], total_count=len(entries))


@app.get("/api/v1/threat-feeds/cisa-kev", response_model=CisaKevResponse)
def get_cisa_kev(
    request: Request,
    query: str = "",
    limit: int = 50,
    refresh: bool = False,
):
    """Fetch and cache the public CISA KEV catalog."""
    payload = fetch_cisa_kev(refresh=refresh)
    vulnerabilities = payload.get("vulnerabilities", [])
    if query:
        needle = query.lower()
        vulnerabilities = [
            item for item in vulnerabilities
            if needle in json.dumps(item, default=str).lower()
        ]
    safe_limit = max(1, min(limit, 500))
    selected = vulnerabilities[:safe_limit]
    audit_log(
        request,
        "threat_feed.cisa_kev.viewed",
        None,
        {"query": query, "limit": safe_limit, "refresh": refresh, "returned": len(selected)},
    )
    return {
        "title": payload.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
        "catalogVersion": payload.get("catalogVersion", ""),
        "dateReleased": payload.get("dateReleased", ""),
        "count": len(vulnerabilities),
        "source": payload.get("_raptor_source", CISA_KEV_URL),
        "cached_at": payload.get("_raptor_cached_at", ""),
        "vulnerabilities": selected,
    }


@app.post("/api/v1/threat-feeds/cisa-kev/sync", response_model=CisaKevResponse)
def sync_cisa_kev(request: Request):
    """Force refresh the CISA KEV catalog cache."""
    payload = fetch_cisa_kev(refresh=True)
    vulnerabilities = payload.get("vulnerabilities", [])
    audit_log(
        request,
        "threat_feed.cisa_kev.synced",
        None,
        {"count": len(vulnerabilities), "source": CISA_KEV_URL},
    )
    return {
        "title": payload.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
        "catalogVersion": payload.get("catalogVersion", ""),
        "dateReleased": payload.get("dateReleased", ""),
        "count": len(vulnerabilities),
        "source": payload.get("_raptor_source", CISA_KEV_URL),
        "cached_at": payload.get("_raptor_cached_at", ""),
        "vulnerabilities": vulnerabilities[:50],
    }


@app.post("/api/v1/ingest/elasticsearch/poll", response_model=ElasticPollResponse)
def poll_elasticsearch(request: Request, payload: ElasticPollRequest):
    """Poll Elasticsearch once and queue any returned events as an investigation."""
    response = run_elasticsearch_poll_once(
        query=payload.query,
        time_range_start=payload.time_range_start,
        time_range_end=payload.time_range_end,
        case_name=payload.case_name,
        apt_filters=payload.apt_filters,
    )
    audit_log(
        request,
        "elasticsearch.poll",
        response.investigation_id,
        {"status": response.status, "query": payload.query, "event_bytes": response.event_bytes},
    )
    return response


@app.get("/api/v1/ingest/elasticsearch/status", response_model=ElasticPollStatus)
async def get_elasticsearch_poll_status(request: Request):
    """Return the simple Elasticsearch poller state."""
    state = get_elastic_poll_state()
    audit_log(request, "elasticsearch.poll_status.viewed", None, {})
    return ElasticPollStatus(
        enabled=state.get("enabled", False),
        query=state.get("query", ELASTIC_POLL_QUERY),
        interval_seconds=state.get("interval_seconds", ELASTIC_POLL_INTERVAL_SECONDS),
        window_minutes=state.get("window_minutes", ELASTIC_POLL_WINDOW_MINUTES),
        last_polled_at=state.get("last_polled_at", ""),
        last_status=state.get("last_status", ""),
        last_error=state.get("last_error", ""),
        investigation_count=state.get("investigation_count", 0),
    )


# ─── Health Check ────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health_check():
    """Fast liveness check that does not touch external services."""
    sqlite_status = "healthy"
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=1)
        conn.execute("SELECT 1")
        conn.close()
    except Exception:
        sqlite_status = "degraded"

    return {
        "status": "healthy" if sqlite_status == "healthy" else "degraded",
        "service": "RAPTOR API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "subsystems": {
            "api": {"status": "healthy", "detail": "FastAPI runtime responsive"},
            "sqlite": {"status": sqlite_status, "detail": "query ok" if sqlite_status == "healthy" else "query failed"},
        },
    }


def _endpoint_host_port(endpoint: str, default_port: int) -> tuple[str, int]:
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname, parsed.port or default_port
    cleaned = endpoint.replace("http://", "").replace("https://", "").replace("bolt://", "").split("/")[0]
    if ":" in cleaned:
        host, port = cleaned.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    return cleaned or "localhost", default_port


def _tcp_status(name: str, endpoint: str, default_port: int, timeout_seconds: float = 0.5) -> dict:
    try:
        host, port = _endpoint_host_port(endpoint, default_port)
        with socket.create_connection((host, port), timeout=timeout_seconds):
            pass
        return {"status": "healthy", "detail": f"{name} reachable at {host}:{port}"}
    except Exception as e:
        return {"status": "degraded", "detail": str(e)}


@app.get("/api/v1/health/detailed")
async def health_check_detailed():
    """Bounded subsystem health for API/UI degraded-mode visibility."""
    checks = {
        "api": {"status": "healthy", "detail": "FastAPI runtime responsive"},
        "sqlite": {"status": "healthy", "detail": ""},
        "auth": {"status": "healthy", "detail": "API key auth enabled" if RAPTOR_API_KEY else "API key missing"},
        "evidence": {"status": "healthy", "detail": ""},
        "neo4j": {"status": "degraded", "detail": "unreachable"},
        "weaviate": {"status": "degraded", "detail": "unreachable"},
        "elasticsearch": {"status": "degraded", "detail": "unreachable"},
        "redis": {"status": "degraded", "detail": "unreachable"},
        "cisa_kev": {"status": "degraded", "detail": "not cached"},
        "llm": {"status": "degraded", "detail": "OPENROUTER_API_KEY missing"},
    }

    # SQLite
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=1)
        conn.execute("SELECT 1")
        conn.close()
        checks["sqlite"] = {"status": "healthy", "detail": "query ok"}
    except Exception as e:
        checks["sqlite"] = {"status": "degraded", "detail": str(e)}

    # Evidence store
    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        test_path = EVIDENCE_DIR / ".health"
        test_path.write_text("ok", encoding="utf-8")
        test_path.unlink(missing_ok=True)
        checks["evidence"] = {"status": "healthy", "detail": str(EVIDENCE_DIR)}
    except Exception as e:
        checks["evidence"] = {"status": "degraded", "detail": str(e)}

    checks["neo4j"] = _tcp_status("Neo4j", os.getenv("NEO4J_URI", "bolt://localhost:7687"), 7687)
    checks["weaviate"] = _tcp_status("Weaviate", WEAVIATE_URL, 8080)
    checks["elasticsearch"] = _tcp_status("Elasticsearch", ELASTICSEARCH_URL, 9200)

    # Redis, checked without requiring an extra Python package.
    try:
        parsed = urlparse(REDIS_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        with socket.create_connection((host, port), timeout=0.5) as conn:
            conn.sendall(b"*1\r\n$4\r\nPING\r\n")
            response = conn.recv(32)
        ready = response.startswith(b"+PONG")
        checks["redis"] = {
            "status": "healthy" if ready else "degraded",
            "detail": "connected; used for lightweight JSON cache" if ready else "unexpected ping response",
        }
    except Exception as e:
        checks["redis"] = {"status": "degraded", "detail": str(e)}

    # CISA KEV cache readiness
    if CISA_KEV_CACHE_PATH.exists():
        checks["cisa_kev"] = {"status": "healthy", "detail": f"cached at {CISA_KEV_CACHE_PATH}"}
    else:
        checks["cisa_kev"] = {"status": "degraded", "detail": "cache not populated; call /api/v1/threat-feeds/cisa-kev"}

    # LLM config readiness
    from config import OPENROUTER_API_KEY
    if OPENROUTER_API_KEY:
        checks["llm"] = {"status": "healthy", "detail": "api key configured"}
    if not RAPTOR_API_KEY and not RAPTOR_ALLOW_AUTH_DISABLED:
        checks["auth"] = {"status": "degraded", "detail": "RAPTOR_API_KEY missing and auth-disabled mode is not allowed"}
    elif not RAPTOR_API_KEY and RAPTOR_ALLOW_AUTH_DISABLED:
        checks["auth"] = {"status": "degraded", "detail": "API key auth explicitly disabled for local development"}

    overall = "healthy"
    if any(v["status"] != "healthy" for v in checks.values()):
        overall = "degraded"

    return {
        "status": overall,
        "service": "RAPTOR API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "subsystems": checks,
    }


# ─── Run ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting RAPTOR API on {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=int(API_PORT))
