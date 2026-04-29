from helpers import BACKEND_DIR  # noqa: F401
import main as app_main


def normalize(sql: str) -> str:
    return " ".join(sql.split())


def test_postgres_adapter_translates_sqlite_schema_fragments():
    sql, params = app_main._postgres_sql(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            locked_at REAL DEFAULT 0
        )
        """,
        (),
    )

    rendered = normalize(sql)
    assert "BIGSERIAL PRIMARY KEY" in rendered
    assert "DOUBLE PRECISION" in rendered
    assert params == ()


def test_postgres_adapter_maps_table_info_introspection():
    sql, params = app_main._postgres_sql("PRAGMA table_info(investigations)", ())

    assert "information_schema.columns" in sql
    assert params == ("investigations",)


def test_postgres_adapter_maps_job_queue_upsert():
    sql, params = app_main._postgres_sql(
        """
        INSERT OR REPLACE INTO job_queue
        (investigation_id, status, attempts, payload_json, next_run_at, created_at, updated_at)
        VALUES (?, 'queued', 0, ?, ?, ?, ?)
        """,
        ("case-1", "{}", 1.0, "now", "now"),
    )

    rendered = normalize(sql)
    assert "ON CONFLICT (investigation_id) DO UPDATE" in rendered
    assert "locked_by = ''" in rendered
    assert params[0] == "case-1"


def test_postgres_adapter_returns_evidence_id_on_insert():
    sql, _params = app_main._postgres_sql(
        """
        INSERT INTO evidence_files
        (investigation_id, original_filename, stored_path, sha256, size_bytes,
         content_type, source, encrypted, encryption_key_id, retention_expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (),
    )

    assert normalize(sql).endswith("RETURNING id")
