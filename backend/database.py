"""
RAPTOR | Runtime Metadata Store
Provides the database connection abstraction (SQLite dev / PostgreSQL prod),
schema initialisation, and all persistence helpers used across the application.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from loguru import logger

from config import (
    CISA_KEV_CACHE_PATH,
    CISA_KEV_URL,
    ELASTIC_INDEX_PREFIX,
    ELASTIC_POLL_ENABLED,
    ELASTIC_POLL_INTERVAL_SECONDS,
    ELASTIC_POLL_QUERY,
    ELASTIC_POLL_WINDOW_MINUTES,
    ELASTICSEARCH_URL,
    EVIDENCE_RETENTION_DAYS,
    MAX_UPLOAD_BYTES,
    RAPTOR_DB_ENGINE,
    RAPTOR_DATABASE_URL,
    RAPTOR_PRODUCTION,
    REDIS_CACHE_TTL_SECONDS,
    REDIS_URL,
)

# ── Column allowlists (prevent SQL-injection via column-name interpolation) ──

ALLOWED_INVESTIGATION_UPDATE_COLUMNS: frozenset[str] = frozenset({
    "status", "progress", "current_phase", "error", "findings_json",
    "attack_sequence_json", "anomalies_json", "attribution_json", "graph_json",
    "narrative_report", "event_count", "technique_count", "completed_at",
})

ALLOWED_ELASTIC_POLL_UPDATE_COLUMNS: frozenset[str] = frozenset({
    "enabled", "query", "interval_seconds", "window_minutes", "last_polled_at",
    "last_status", "last_error", "investigation_count",
})


# ── Row / Result types ────────────────────────────────────────────────────────

class DbRow(dict):
    """Mapping row that also supports positional (index) access like sqlite3.Row."""

    def __init__(self, values: tuple, columns: list[str]) -> None:
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class DbResult:
    def __init__(
        self,
        rows: Optional[list] = None,
        columns: Optional[list[str]] = None,
        rowcount: int = -1,
        lastrowid: Any = None,
    ) -> None:
        self._rows = rows or []
        self._columns = columns or []
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self) -> Optional[DbRow]:
        if not self._rows:
            return None
        return DbRow(self._rows[0], self._columns)

    def fetchall(self) -> list[DbRow]:
        return [DbRow(row, self._columns) for row in self._rows]


# ── PostgreSQL adapter ────────────────────────────────────────────────────────

class PostgresConnection:
    """Thin psycopg3 wrapper that translates SQLite dialect SQL before execution."""

    def __init__(self, timeout: float = 30.0) -> None:
        import psycopg  # type: ignore[import]
        self._conn = psycopg.connect(RAPTOR_DATABASE_URL, connect_timeout=int(timeout))
        self.row_factory = None

    def close(self) -> None:
        self._conn.close()

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def execute(self, sql: str, params: tuple = ()) -> DbResult:
        sql, params = _postgres_sql(sql, params or ())
        with self._conn.cursor() as cursor:
            try:
                cursor.execute(sql, params)
            except Exception:
                self._conn.rollback()
                raise
            columns = [item.name for item in cursor.description] if cursor.description else []
            rows = cursor.fetchall() if cursor.description else []
            lastrowid = None
            upper = sql.lstrip().upper()
            if upper.startswith("INSERT INTO EVIDENCE_FILES") and rows:
                lastrowid = rows[0][0]
            return DbResult(rows=rows, columns=columns, rowcount=cursor.rowcount, lastrowid=lastrowid)

    def executemany(self, sql: str, seq_of_params: list) -> DbResult:
        sql, _ = _postgres_sql(sql, ())
        sql = _replace_qmark_params(sql)
        with self._conn.cursor() as cursor:
            try:
                cursor.executemany(sql, seq_of_params)
            except Exception:
                self._conn.rollback()
                raise
            return DbResult(rowcount=cursor.rowcount)


def _replace_qmark_params(sql: str) -> str:
    return sql.replace("?", "%s")


def _postgres_sql(sql: str, params: tuple) -> tuple[str, tuple]:
    """Translate SQLite dialect SQL fragments to PostgreSQL equivalents."""
    stripped = sql.strip()
    upper = " ".join(stripped.upper().split())

    if upper.startswith("PRAGMA TABLE_INFO("):
        table_name = stripped[stripped.find("(") + 1:stripped.rfind(")")].strip().strip("'\"")
        return (
            """
            SELECT ordinal_position - 1 AS cid, column_name AS name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table_name,),
        )

    if upper.startswith("CREATE TABLE"):
        sql = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
        sql = re.sub(r"\bREAL\b", "DOUBLE PRECISION", sql, flags=re.IGNORECASE)

    if "CREATE TRIGGER IF NOT EXISTS AUDIT_LOG_NO_UPDATE" in upper:
        return (
            """
            DO $do$
            BEGIN
                CREATE OR REPLACE FUNCTION audit_log_reject_update()
                RETURNS trigger AS $fn$
                BEGIN RAISE EXCEPTION 'audit_log is append-only'; END;
                $fn$ LANGUAGE plpgsql;
                DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
                CREATE TRIGGER audit_log_no_update
                BEFORE UPDATE ON audit_log
                FOR EACH ROW EXECUTE FUNCTION audit_log_reject_update();
            END $do$;
            """,
            (),
        )

    if "CREATE TRIGGER IF NOT EXISTS AUDIT_LOG_NO_DELETE" in upper:
        return (
            """
            DO $do$
            BEGIN
                CREATE OR REPLACE FUNCTION audit_log_reject_delete()
                RETURNS trigger AS $fn$
                BEGIN RAISE EXCEPTION 'audit_log is append-only'; END;
                $fn$ LANGUAGE plpgsql;
                DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log;
                CREATE TRIGGER audit_log_no_delete
                BEFORE DELETE ON audit_log
                FOR EACH ROW EXECUTE FUNCTION audit_log_reject_delete();
            END $do$;
            """,
            (),
        )

    if upper.startswith("INSERT OR IGNORE INTO"):
        sql = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", sql, count=1, flags=re.IGNORECASE)
        sql = f"{sql.rstrip()} ON CONFLICT DO NOTHING"

    if upper.startswith("INSERT OR REPLACE INTO JOB_QUEUE"):
        sql = """
            INSERT INTO job_queue
            (investigation_id, status, attempts, payload_json, next_run_at, created_at, updated_at)
            VALUES (%s, 'queued', 0, %s, %s, %s, %s)
            ON CONFLICT (investigation_id) DO UPDATE SET
                status = 'queued', attempts = 0,
                payload_json = EXCLUDED.payload_json,
                locked_by = '', locked_at = 0,
                next_run_at = EXCLUDED.next_run_at,
                last_error = '', updated_at = EXCLUDED.updated_at
        """
        return sql, params

    if upper.startswith("INSERT INTO EVIDENCE_FILES") and "RETURNING" not in upper:
        sql = f"{sql.rstrip()} RETURNING id"

    return _replace_qmark_params(sql), params


# ── Connection factory ────────────────────────────────────────────────────────

def db_connect(timeout: float = 30.0):
    """Return a live database connection for the configured backend."""
    if RAPTOR_DB_ENGINE == "postgresql":
        return PostgresConnection(timeout=timeout)
    conn = sqlite3.connect(str(_db_path()), timeout=timeout, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _db_path() -> Path:
    from config import DB_PATH  # imported here to avoid module-level side-effects during test
    return DB_PATH


# ── Utilities ─────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Schema initialisation ─────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables and run incremental column migrations.  Idempotent."""
    conn = db_connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            owner_id TEXT DEFAULT '',
            tenant_id TEXT DEFAULT 'default',
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
            encrypted INTEGER DEFAULT 0,
            encryption_key_id TEXT DEFAULT '',
            retention_expires_at TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            roles TEXT NOT NULL DEFAULT '["viewer"]',
            tenant_id TEXT NOT NULL DEFAULT 'default',
            disabled INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login_at TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at REAL NOT NULL,
            revoked_at TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            last_seen_at TEXT DEFAULT '',
            FOREIGN KEY(user_id) REFERENCES users(id)
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
            ip_address TEXT DEFAULT '',
            prev_hash TEXT DEFAULT '',
            entry_hash TEXT DEFAULT ''
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
        CREATE TABLE IF NOT EXISTS job_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'queued',
            attempts INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 3,
            payload_json TEXT NOT NULL,
            locked_by TEXT DEFAULT '',
            locked_at REAL DEFAULT 0,
            next_run_at REAL DEFAULT 0,
            last_error TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parser_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            parser TEXT DEFAULT '',
            raw_preview TEXT DEFAULT '',
            error TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    # Append-only enforcement on audit_log
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    """)

    # Incremental column migrations (idempotent ALTER TABLE)
    _run_column_migrations(conn, "investigations", {
        "owner_id":    "ALTER TABLE investigations ADD COLUMN owner_id TEXT DEFAULT ''",
        "tenant_id":   "ALTER TABLE investigations ADD COLUMN tenant_id TEXT DEFAULT 'default'",
        "name":        "ALTER TABLE investigations ADD COLUMN name TEXT DEFAULT ''",
        "source":      "ALTER TABLE investigations ADD COLUMN source TEXT DEFAULT ''",
        "input_bytes": "ALTER TABLE investigations ADD COLUMN input_bytes INTEGER DEFAULT 0",
    })
    _run_column_migrations(conn, "evidence_files", {
        "encrypted":          "ALTER TABLE evidence_files ADD COLUMN encrypted INTEGER DEFAULT 0",
        "encryption_key_id":  "ALTER TABLE evidence_files ADD COLUMN encryption_key_id TEXT DEFAULT ''",
        "retention_expires_at": "ALTER TABLE evidence_files ADD COLUMN retention_expires_at TEXT DEFAULT ''",
    })
    _run_column_migrations(conn, "audit_log", {
        "prev_hash":  "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT DEFAULT ''",
        "entry_hash": "ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT ''",
    })

    # Seed / sync Elasticsearch poll state
    conn.execute(
        """
        INSERT OR IGNORE INTO elastic_poll_state
        (name, enabled, query, interval_seconds, window_minutes)
        VALUES ('default', ?, ?, ?, ?)
        """,
        (1 if ELASTIC_POLL_ENABLED else 0, ELASTIC_POLL_QUERY,
         ELASTIC_POLL_INTERVAL_SECONDS, ELASTIC_POLL_WINDOW_MINUTES),
    )
    conn.execute(
        """
        UPDATE elastic_poll_state
        SET enabled = ?, query = ?, interval_seconds = ?, window_minutes = ?
        WHERE name = 'default'
        """,
        (1 if ELASTIC_POLL_ENABLED else 0, ELASTIC_POLL_QUERY,
         ELASTIC_POLL_INTERVAL_SECONDS, ELASTIC_POLL_WINDOW_MINUTES),
    )

    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        ("20260505_runtime_metadata_baseline", _utcnow()),
    )
    conn.commit()
    conn.close()


def _run_column_migrations(conn, table: str, migrations: dict[str, str]) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for column, statement in migrations.items():
        if column not in existing:
            conn.execute(statement)


# ── Investigation CRUD ────────────────────────────────────────────────────────

def db_get(inv_id: str) -> Optional[dict]:
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def db_create(inv_id: str, metadata: Optional[dict] = None, input_bytes: int = 0) -> None:
    metadata = metadata or {}
    name = str(metadata.get("case_name") or "").strip() or str(metadata.get("filename") or "").strip()
    source = str(metadata.get("source") or "file").strip()
    owner_id = str(metadata.get("owner_id") or "system")
    tenant_id = str(metadata.get("tenant_id") or "default")
    conn = db_connect()
    conn.execute(
        "INSERT INTO investigations (id, owner_id, tenant_id, name, source, input_bytes, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)",
        (inv_id, owner_id, tenant_id, name, source, input_bytes, _utcnow()),
    )
    conn.commit()
    conn.close()


def db_update(inv_id: str, **kwargs: Any) -> None:
    invalid = set(kwargs) - ALLOWED_INVESTIGATION_UPDATE_COLUMNS
    if invalid:
        raise ValueError(f"Unsupported investigation update columns: {', '.join(sorted(invalid))}")
    conn = db_connect()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    conn.execute(f"UPDATE investigations SET {sets} WHERE id = ?", [*kwargs.values(), inv_id])
    conn.commit()
    conn.close()


def db_list(limit: int = 25, principal: Optional[dict] = None) -> list[dict]:
    from auth_core import _has_role, _principal as make_principal
    principal = principal or make_principal("system", ["system"], "system")
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    cols = "id, owner_id, tenant_id, name, source, input_bytes, status, progress, current_phase, error, event_count, technique_count, created_at, completed_at, attribution_json, graph_json"
    if _has_role(principal, "admin") or "service" in principal.get("roles", []):
        rows = conn.execute(f"SELECT {cols} FROM investigations ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {cols} FROM investigations WHERE tenant_id = ? AND (owner_id = ? OR owner_id = '') ORDER BY created_at DESC LIMIT ?",
            (principal.get("tenant_id", "default"), principal.get("user_id", ""), limit),
        ).fetchall()
    conn.close()
    return [_summarize_investigation_row(dict(row)) for row in rows]


def _summarize_investigation_row(row: dict) -> dict:
    """Enrich a raw investigation row with frontend-ready summary fields."""
    attribution = []
    try:
        attribution = json.loads(row.get("attribution_json") or "[]")
    except Exception:
        pass
    top = attribution[0] if attribution else {}
    row["top_candidate"] = top.get("apt_name", "") if isinstance(top, dict) else ""
    row["confidence_score"] = float(top.get("confidence_score", 0.0) or 0.0) if isinstance(top, dict) else 0.0
    row["confidence_label"] = top.get("confidence_label", "") if isinstance(top, dict) else ""

    host_count = 0
    try:
        graph = json.loads(row.get("graph_json") or "{}")
        host_count = sum(1 for n in graph.get("nodes", []) if n.get("node_type") == "host")
    except Exception:
        pass
    row["host_count"] = host_count
    row["name"] = row.get("name") or f"Investigation {str(row.get('id', ''))[:8]}"
    row["source"] = row.get("source") or "unknown"
    row["input_bytes"] = row.get("input_bytes") or 0
    row.pop("attribution_json", None)
    row.pop("graph_json", None)
    return row


# ── Evidence files ────────────────────────────────────────────────────────────

def store_evidence_file(investigation_id: str, content: bytes, metadata: Optional[dict] = None) -> dict:
    """Encrypt, persist, and record metadata for a raw evidence file."""
    from evidence_crypto import encrypt_evidence
    from storage import get_storage

    metadata = metadata or {}
    original = _safe_filename(metadata.get("filename") or metadata.get("case_name") or "raw.log")
    source = str(metadata.get("source") or "unknown")
    stored_name = f"{time.time_ns()}_{uuid.uuid4().hex[:12]}_{original}"
    stored_content, encrypted, key_id = encrypt_evidence(content)
    stored_path = get_storage().write(f"{investigation_id}/{stored_name}", stored_content)

    sha256 = hashlib.sha256(content).hexdigest()
    created_at = _utcnow()
    retention_expires_at = datetime.fromtimestamp(
        time.time() + max(EVIDENCE_RETENTION_DAYS, 1) * 86400, timezone.utc
    ).isoformat()

    conn = db_connect()
    cur = conn.execute(
        """
        INSERT INTO evidence_files
        (investigation_id, original_filename, stored_path, sha256, size_bytes,
         content_type, source, encrypted, encryption_key_id, retention_expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (investigation_id, original, str(stored_path), sha256, len(content),
         str(metadata.get("content_type") or "text/plain"), source,
         1 if encrypted else 0, key_id, retention_expires_at, created_at),
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
        "encrypted": encrypted,
        "encryption_key_id": key_id,
        "retention_expires_at": retention_expires_at,
        "created_at": created_at,
    }


def list_evidence_files(investigation_id: str) -> list[dict]:
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, investigation_id, original_filename, sha256, size_bytes,
               content_type, source, encrypted, retention_expires_at, created_at
        FROM evidence_files WHERE investigation_id = ? ORDER BY id DESC
        """,
        (investigation_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def _safe_filename(value: str, default: str = "raw.log") -> str:
    name = Path(value or default).name
    cleaned = "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "_" for ch in name)
    return cleaned or default


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit_log(
    actor: str,
    action: str,
    investigation_id: Optional[str] = None,
    detail: Optional[dict] = None,
    ip_address: str = "",
) -> None:
    """Append a tamper-evident audit entry (hash-chained)."""
    timestamp = _utcnow()
    detail_json = json.dumps(detail or {}, default=str)
    conn = db_connect()
    prev = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev[0] if prev and prev[0] else ""
    entry_material = "|".join([timestamp, actor, action, investigation_id or "", detail_json, ip_address, prev_hash])
    entry_hash = hashlib.sha256(entry_material.encode("utf-8")).hexdigest()
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, action, investigation_id, detail_json, ip_address, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, actor, action, investigation_id, detail_json, ip_address, prev_hash, entry_hash),
    )
    conn.commit()
    conn.close()


def list_audit_entries(limit: int = 100, investigation_id: Optional[str] = None) -> list[dict]:
    safe_limit = max(1, min(limit, 500))
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    if investigation_id:
        rows = conn.execute(
            "SELECT id, timestamp, actor, action, investigation_id, detail_json, ip_address FROM audit_log WHERE investigation_id = ? ORDER BY id DESC LIMIT ?",
            (investigation_id, safe_limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, timestamp, actor, action, investigation_id, detail_json, ip_address FROM audit_log ORDER BY id DESC LIMIT ?",
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


def list_schema_migrations() -> list[dict]:
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT version, applied_at FROM schema_migrations ORDER BY applied_at ASC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ── Job queue ─────────────────────────────────────────────────────────────────

def enqueue_investigation_job(investigation_id: str, log_content: str, metadata: dict) -> None:
    now = _utcnow()
    conn = db_connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO job_queue (investigation_id, status, attempts, payload_json, next_run_at, created_at, updated_at) VALUES (?, 'queued', 0, ?, ?, ?, ?)",
            (investigation_id, json.dumps({"log_content": log_content, "metadata": metadata}, default=str), time.time(), now, now),
        )
        conn.commit()
    finally:
        conn.close()


def claim_next_investigation_job() -> Optional[dict]:
    from config import RAPTOR_PROCESS_ROLE  # avoid circular at module level
    import socket as _socket, os as _os
    worker_id = f"{_socket.gethostname()}-{_os.getpid()}-{uuid.uuid4().hex[:8]}"

    conn = db_connect()
    conn.row_factory = sqlite3.Row
    try:
        now = time.time()
        # Recover stale locks older than 1 hour
        conn.execute(
            "UPDATE job_queue SET status = 'queued', locked_by = '', locked_at = 0, updated_at = ?, last_error = 'recovered stale worker lock' WHERE status = 'running' AND locked_at < ?",
            (_utcnow(), now - 3600),
        )
        row = conn.execute(
            "SELECT * FROM job_queue WHERE status = 'queued' AND next_run_at <= ? ORDER BY id ASC LIMIT 1",
            (now,),
        ).fetchone()
        if not row:
            conn.commit()
            return None
        updated = conn.execute(
            "UPDATE job_queue SET status = 'running', attempts = attempts + 1, locked_by = ?, locked_at = ?, updated_at = ? WHERE id = ? AND status = 'queued'",
            (worker_id, now, _utcnow(), row["id"]),
        ).rowcount
        conn.commit()
        if not updated:
            return None
        job = dict(row)
        payload = json.loads(job.get("payload_json") or "{}")
        job["log_content"] = payload.get("log_content", "")
        job["metadata"] = payload.get("metadata", {})
        return job
    finally:
        conn.close()


def complete_investigation_job(job_id: int, failed: bool = False, error: str = "") -> None:
    conn = db_connect()
    try:
        if failed:
            row = conn.execute("SELECT attempts, max_attempts FROM job_queue WHERE id = ?", (job_id,)).fetchone()
            attempts, max_attempts = (row[0], row[1]) if row else (1, 1)
            status = "failed" if attempts >= max_attempts else "queued"
            next_run_at = time.time() + min(300, 2 ** max(attempts, 1))
            conn.execute(
                "UPDATE job_queue SET status = ?, locked_by = '', locked_at = 0, next_run_at = ?, last_error = ?, updated_at = ? WHERE id = ?",
                (status, next_run_at, error[:500], _utcnow(), job_id),
            )
        else:
            conn.execute(
                "UPDATE job_queue SET status = 'complete', locked_by = '', locked_at = 0, updated_at = ? WHERE id = ?",
                (_utcnow(), job_id),
            )
        conn.commit()
    finally:
        conn.close()


def store_parser_errors(investigation_id: str, errors: list[dict]) -> None:
    if not errors:
        return
    conn = db_connect()
    try:
        conn.executemany(
            "INSERT INTO parser_errors (investigation_id, parser, raw_preview, error, created_at) VALUES (?, ?, ?, ?, ?)",
            [(investigation_id, str(e.get("parser", "")), str(e.get("raw_preview", "")), str(e.get("error", "")), _utcnow()) for e in errors],
        )
        conn.commit()
    finally:
        conn.close()


# ── Elasticsearch poll state ──────────────────────────────────────────────────

def update_elastic_poll_state(**kwargs: Any) -> None:
    if not kwargs:
        return
    invalid = set(kwargs) - ALLOWED_ELASTIC_POLL_UPDATE_COLUMNS
    if invalid:
        raise ValueError(f"Unsupported Elasticsearch poll state columns: {', '.join(sorted(invalid))}")
    conn = db_connect()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    conn.execute(f"UPDATE elastic_poll_state SET {sets} WHERE name = ?", [*kwargs.values(), "default"])
    conn.commit()
    conn.close()


def get_elastic_poll_state() -> dict:
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT enabled, query, interval_seconds, window_minutes, last_polled_at, last_status, last_error, investigation_count FROM elastic_poll_state WHERE name = 'default'"
    ).fetchone()
    conn.close()
    if not row:
        return {}
    data = dict(row)
    data["enabled"] = bool(data.get("enabled"))
    return data


def increment_elastic_poll_investigations() -> None:
    conn = db_connect()
    conn.execute("UPDATE elastic_poll_state SET investigation_count = coalesce(investigation_count, 0) + 1 WHERE name = 'default'")
    conn.commit()
    conn.close()


def filter_new_elasticsearch_events(content: str) -> tuple[str, int]:
    """De-duplicate Elasticsearch events against previously ingested ones."""
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return "", 0

    now = _utcnow()
    accepted: list[str] = []
    duplicates = 0
    conn = db_connect()
    try:
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"raw": line}
            meta = event.get("_raptor_elastic", {}) if isinstance(event, dict) else {}
            hit_index = str(meta.get("index", ""))
            hit_id = str(meta.get("id", ""))
            event_key = f"{hit_index}:{hit_id}" if hit_index and hit_id else hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
            try:
                result = conn.execute(
                    "INSERT INTO elastic_seen_events (event_key, first_seen_at, last_seen_at, hit_index, hit_id) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    (event_key, now, now, hit_index, hit_id),
                )
                if result.rowcount:
                    accepted.append(line)
                else:
                    duplicates += 1
                    conn.execute("UPDATE elastic_seen_events SET last_seen_at = ? WHERE event_key = ?", (now, event_key))
            except sqlite3.IntegrityError:
                duplicates += 1
                conn.execute("UPDATE elastic_seen_events SET last_seen_at = ? WHERE event_key = ?", (now, event_key))
        conn.commit()
    finally:
        conn.close()
    return "\n".join(accepted), duplicates


# ── Redis cache utilities ─────────────────────────────────────────────────────

def _redis_send_command(*parts: str) -> Optional[bytes]:
    """Minimal Redis RESP client — avoids an extra runtime dependency."""
    import socket
    try:
        parsed = urlparse(REDIS_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        db_num = parsed.path.strip("/") if parsed.path and parsed.path != "/" else ""

        def _encode(*command_parts: str) -> bytes:
            payload = f"*{len(command_parts)}\r\n".encode()
            for part in command_parts:
                raw = str(part).encode()
                payload += f"${len(raw)}\r\n".encode() + raw + b"\r\n"
            return payload

        def _read(conn) -> bytes:
            chunks: list[bytes] = []
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
                auth_args = ("AUTH", parsed.username, parsed.password) if parsed.username else ("AUTH", parsed.password)
                conn.sendall(_encode(*auth_args))
                resp = _read(conn)
                if resp.startswith(b"-"):
                    return None
            if db_num:
                conn.sendall(_encode("SELECT", db_num))
                if _read(conn).startswith(b"-"):
                    return None
            conn.sendall(_encode(*parts))
            return _read(conn)
    except Exception as exc:
        logger.debug(f"Redis command skipped: {exc}")
        return None


def redis_get_json(key: str) -> Optional[dict]:
    response = _redis_send_command("GET", key)
    if not response or response.startswith(b"$-1"):
        return None
    try:
        head, body = response.split(b"\r\n", 1)
        if not head.startswith(b"$"):
            return None
        return json.loads(body[:int(head[1:])].decode())
    except Exception:
        return None


def redis_set_json(key: str, value: dict, ttl_seconds: int = REDIS_CACHE_TTL_SECONDS) -> bool:
    payload = json.dumps(value, default=str)
    if ttl_seconds > 0:
        response = _redis_send_command("SET", key, payload, "EX", str(ttl_seconds))
    else:
        response = _redis_send_command("SET", key, payload)
    return bool(response and response.startswith(b"+OK"))


# ── CISA KEV cache ────────────────────────────────────────────────────────────

def fetch_cisa_kev(refresh: bool = False) -> dict:
    """Fetch the CISA KEV catalog with Redis → file → live HTTP fallback chain."""
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
        import requests as _requests
        from config import validate_feed_url
        feed_url = validate_feed_url(CISA_KEV_URL)
        resp = _requests.get(feed_url, timeout=30, headers={"User-Agent": "RAPTOR/1.0 threat-intel-connector"})
        resp.raise_for_status()
        if len(resp.content) > 25 * 1024 * 1024:
            raise ValueError("CISA KEV feed response is unexpectedly large")
        payload = resp.json()
    except Exception as exc:
        if CISA_KEV_CACHE_PATH.exists():
            logger.warning(f"CISA KEV refresh failed, using file cache: {exc}")
            return json.loads(CISA_KEV_CACHE_PATH.read_text(encoding="utf-8"))
        from fastapi import HTTPException
        detail = "Threat feed temporarily unavailable" if RAPTOR_PRODUCTION else f"CISA KEV feed unavailable: {exc}"
        raise HTTPException(status_code=503, detail=detail)

    payload["_raptor_cached_at"] = _utcnow()
    payload["_raptor_source"] = CISA_KEV_URL
    CISA_KEV_CACHE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    redis_set_json(cache_key, payload)
    return payload


# ── User management ───────────────────────────────────────────────────────────

def list_users(tenant_id: Optional[str] = None) -> list[dict]:
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    if tenant_id:
        rows = conn.execute(
            "SELECT id, username, roles, tenant_id, disabled, created_at, last_login_at FROM users WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, username, roles, tenant_id, disabled, created_at, last_login_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    conn.close()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["roles"] = json.loads(item.get("roles") or "[]")
        except Exception:
            item["roles"] = ["viewer"]
        item["disabled"] = bool(item.get("disabled"))
        result.append(item)
    return result


def get_user_by_id(user_id: str) -> Optional[dict]:
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id, username, roles, tenant_id, disabled, created_at, last_login_at FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return None
    item = dict(row)
    try:
        item["roles"] = json.loads(item.get("roles") or "[]")
    except Exception:
        item["roles"] = ["viewer"]
    item["disabled"] = bool(item.get("disabled"))
    return item
