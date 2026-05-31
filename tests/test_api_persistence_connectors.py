"""
API persistence connector tests.
Covers: evidence store, audit log tamper-proofing, auth middleware, RBAC,
session creation, Elasticsearch poll, CISA KEV connector, and rate limiting.

Updated to use the modular architecture (config / database / auth_core / evidence_crypto).
"""
import asyncio
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError
from starlette.responses import Response

from helpers import BACKEND_DIR  # noqa: F401 — adds backend dir to sys.path

import config as _config
import database
import auth_core
import evidence_crypto
import main as _main  # for middleware closures only
from models import (
    AuthSessionRequest,
    ElasticPollRequest,
    ElasticPollResponse,
    EvidenceFileSummary,
    QueryRequest,
)


def _patch_config(**kwargs):
    """Return a list of context managers that patch config attributes."""
    return [patch.object(_config, k, v) for k, v in kwargs.items()]


class ApiPersistenceConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        kev_dir = self.root / "intel"
        kev_dir.mkdir(parents=True, exist_ok=True)

        self._patches = _patch_config(
            DB_PATH=self.root / "raptor.db",
            EVIDENCE_DIR=self.root / "evidence",
            CISA_KEV_CACHE_PATH=kev_dir / "cisa_kev.json",
            RAPTOR_API_KEY="",
            RAPTOR_ALLOW_AUTH_DISABLED=True,
            RAPTOR_REQUIRE_RBAC=True,
            RAPTOR_BOOTSTRAP_ADMIN_USERNAME="admin",
            RAPTOR_BOOTSTRAP_ADMIN_PASSWORD="admin-secret",
            EVIDENCE_ENCRYPTION_KEY="",
            ELASTIC_POLL_ENABLED=False,
            ELASTIC_POLL_QUERY="*",
            ELASTIC_POLL_INTERVAL_SECONDS=300,
            ELASTIC_POLL_WINDOW_MINUTES=5,
            CORS_ALLOW_ORIGINS=["http://localhost:3100"],
            RAPTOR_PRODUCTION=False,
            RAPTOR_STORAGE_BACKEND="local",
            RAPTOR_DB_ENGINE="sqlite",
        )
        for p in self._patches:
            p.start()

        # Clear in-process rate-limit state between tests
        auth_core.RATE_LIMIT_BUCKETS.clear()
        database.init_db()
        auth_core.bootstrap_admin_user()

    def tearDown(self):
        auth_core.RATE_LIMIT_BUCKETS.clear()
        for p in self._patches:
            p.stop()
        self.tmp.cleanup()

    # ── API key auth middleware ────────────────────────────────────────────────

    def test_api_key_middleware_allows_docs_and_guards_api(self):
        class FakeURL:
            path = "/api/v1/investigations"

        class FakeRequest:
            url = FakeURL()
            method = "GET"
            headers: dict = {}
            cookies: dict = {}
            state = type("S", (), {})()

        async def call_next(_req):
            return "allowed"

        with patch.object(_config, "RAPTOR_API_KEY", "test-secret"):
            blocked = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))
            FakeRequest.headers = {"authorization": "Bearer test-secret"}
            allowed = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(allowed, "allowed")

    def test_api_key_middleware_keeps_cors_headers_on_auth_challenge(self):
        class FakeURL:
            path = "/api/v1/investigations"

        class FakeRequest:
            method = "GET"
            url = FakeURL()
            headers = {"origin": "http://ui.local"}
            cookies: dict = {}
            state = type("S", (), {})()

        async def call_next(_req):
            return "allowed"

        with (
            patch.object(_config, "RAPTOR_API_KEY", "test-secret"),
            patch.object(_config, "CORS_ALLOW_ORIGINS", ["http://ui.local"]),
            patch.object(_config, "CORS_ALLOW_CREDENTIALS", True),
        ):
            blocked = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(blocked.headers["access-control-allow-origin"], "http://ui.local")
        self.assertEqual(blocked.headers["access-control-allow-credentials"], "true")

    def test_api_key_middleware_allows_cors_preflight(self):
        class FakeURL:
            path = "/api/v1/investigations"

        class FakeRequest:
            method = "OPTIONS"
            url = FakeURL()
            headers = {"origin": "http://ui.local"}
            cookies: dict = {}
            state = type("S", (), {})()

        async def call_next(_req):
            return "allowed"

        with patch.object(_config, "RAPTOR_API_KEY", "test-secret"):
            allowed = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(allowed, "allowed")

    # ── CSRF guard ────────────────────────────────────────────────────────────

    def test_csrf_guard_blocks_untrusted_browser_session_mutation(self):
        class FakeURL:
            path = "/api/v1/investigate/text"

        class FakeRequest:
            method = "POST"
            url = FakeURL()
            headers = {"origin": "https://evil.example"}
            cookies = {"raptor_session": "session-token"}

        async def call_next(_req):
            return "allowed"

        with patch.object(_config, "RAPTOR_API_KEY", "test-secret"):
            blocked = asyncio.run(_main.csrf_guard(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 403)

    def test_csrf_guard_allows_api_key_service_mutation(self):
        class FakeURL:
            path = "/api/v1/investigate/text"

        class FakeRequest:
            method = "POST"
            url = FakeURL()
            headers = {"authorization": "Bearer test-secret"}
            cookies = {"raptor_session": "session-token"}

        async def call_next(_req):
            return "allowed"

        with patch.object(_config, "RAPTOR_API_KEY", "test-secret"):
            allowed = asyncio.run(_main.csrf_guard(FakeRequest(), call_next))

        self.assertEqual(allowed, "allowed")

    # ── Evidence store ────────────────────────────────────────────────────────

    def test_evidence_endpoint_lists_persisted_raw_upload_metadata(self):
        database.db_create("case-1", {"case_name": "Case One", "source": "file"}, input_bytes=18)
        database.store_evidence_file(
            "case-1",
            b'{"event":"one"}',
            {"filename": "raw.json", "content_type": "application/json", "source": "file"},
        )
        rows = database.list_evidence_files("case-1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["original_filename"], "raw.json")
        self.assertEqual(rows[0]["source"], "file")
        self.assertNotIn("stored_path", EvidenceFileSummary(**rows[0]).model_dump())

    def test_public_evidence_summary_model_does_not_expose_stored_path(self):
        summary = EvidenceFileSummary(
            investigation_id="case-1",
            original_filename="raw.json",
            stored_path="/secret/internal/path/raw.json",
            sha256="abc",
        )
        self.assertNotIn("stored_path", summary.model_dump())

    def test_evidence_encryption_records_metadata_and_hides_plaintext(self):
        with patch.object(_config, "EVIDENCE_ENCRYPTION_KEY", "test-evidence-key-with-enough-length"):
            content = b'{"secret":"do-not-store-cleartext"}'
            summary = database.store_evidence_file(
                "case-1",
                content,
                {"filename": "raw.json", "content_type": "application/json", "source": "file"},
            )

        stored_bytes = Path(summary["stored_path"]).read_bytes()
        self.assertTrue(summary["encrypted"])
        self.assertNotEqual(stored_bytes, content)
        with patch.object(_config, "EVIDENCE_ENCRYPTION_KEY", "test-evidence-key-with-enough-length"):
            self.assertEqual(evidence_crypto.decrypt_evidence(stored_bytes), content)
        self.assertIn("aes-256-gcm", summary["encryption_key_id"])
        self.assertEqual(summary["sha256"], hashlib.sha256(content).hexdigest())
        self.assertTrue(summary["retention_expires_at"])

    # ── Request model validation ──────────────────────────────────────────────

    def test_request_models_reject_oversized_security_sensitive_fields(self):
        with self.assertRaises(ValidationError):
            AuthSessionRequest(username="u", password="x" * 300)
        with self.assertRaises(ValidationError):
            QueryRequest(investigation_id="case-1", question="q" * 2500)
        with self.assertRaises(ValidationError):
            ElasticPollRequest(query="q" * 1200)

    # ── Audit log ─────────────────────────────────────────────────────────────

    def test_audit_log_endpoint_returns_structured_details(self):
        database.db_create("case-1", {"case_name": "Case One", "source": "test"}, input_bytes=1)
        database.audit_log("test-user", "query.asked", "case-1", {"question": "Which hosts?"})

        entries = database.list_audit_entries(investigation_id="case-1")
        self.assertGreaterEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "query.asked")
        self.assertEqual(entries[0]["detail"]["question"], "Which hosts?")

    def test_audit_actor_ignores_spoofable_identity_headers(self):
        with patch.object(_config, "RAPTOR_API_KEY", "test-secret"):
            class Client:
                host = "127.0.0.1"

            class FakeRequest:
                headers = {
                    "x-raptor-actor": "spoofed-admin",
                    "x-forwarded-user": "spoofed-user",
                    "x-raptor-api-key": "test-secret",
                }
                cookies: dict = {}
                client = Client()
                state = type("S", (), {})()

            auth_core.audit_log(FakeRequest(), "report.viewed", "case-1", {"status": "complete"})

        entry = database.list_audit_entries(investigation_id="case-1")[0]
        self.assertEqual(entry["actor"], "api-key")

    def test_audit_actor_uses_authenticated_principal_when_available(self):
        class State:
            principal = auth_core._principal("alice", ["analyst"], "default", "user-1")

        class Client:
            host = "127.0.0.1"

        class FakeRequest:
            state = State()
            headers = {"x-raptor-actor": "spoofed-admin"}
            cookies: dict = {}
            client = Client()

        auth_core.audit_log(FakeRequest(), "report.viewed", "case-1", {})
        entry = database.list_audit_entries(investigation_id="case-1")[0]
        self.assertEqual(entry["actor"], "alice")

    def test_audit_table_rejects_update_and_delete(self):
        database.audit_log("system", "report.viewed", "case-1", {"status": "complete"})

        db_path = str(_config.DB_PATH)
        conn = sqlite3.connect(db_path)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_log SET action = 'tampered'")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_log")
        finally:
            conn.close()

    def test_audit_hash_chain_links_entries(self):
        database.audit_log("system", "report.viewed", "case-1", {"status": "complete"})
        database.audit_log("system", "graph.viewed", "case-1", {"status": "complete"})

        conn = sqlite3.connect(str(_config.DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT prev_hash, entry_hash FROM audit_log ORDER BY id ASC"
            ).fetchall()
        finally:
            conn.close()

        self.assertEqual(rows[0]["prev_hash"], "")
        self.assertTrue(rows[0]["entry_hash"])
        self.assertEqual(rows[1]["prev_hash"], rows[0]["entry_hash"])

    # ── RBAC / access control ─────────────────────────────────────────────────

    def test_global_audit_log_requires_admin_role(self):
        class State:
            principal = auth_core._principal("viewer", ["viewer"], "default", "viewer-1")

        class FakeRequest:
            state = State()

        with self.assertRaises(HTTPException):
            auth_core.require_role(FakeRequest(), "admin")

    def test_sensitive_connector_mutations_require_analyst_role(self):
        class State:
            principal = auth_core._principal("viewer", ["viewer"], "default", "viewer-1")

        class FakeRequest:
            state = State()

        with self.assertRaises(HTTPException):
            auth_core.require_role(FakeRequest(), "analyst")

    def test_case_access_requires_owner_for_non_admin_user(self):
        database.db_create(
            "case-owned",
            {
                "case_name": "Owned",
                "source": "test",
                "tenant_id": "default",
                "owner_id": "owner-1",
            },
            input_bytes=5,
        )

        class State:
            principal = auth_core._principal("other", ["viewer"], "default", "owner-2")

        class FakeRequest:
            state = State()

        with self.assertRaises(HTTPException):
            auth_core.ensure_investigation_access(FakeRequest(), "case-owned", "viewer")

    # ── SSO / trusted proxy ───────────────────────────────────────────────────

    def test_trusted_sso_headers_require_trusted_proxy(self):
        class LocalClient:
            host = "127.0.0.1"

        class RemoteClient:
            host = "10.0.0.5"

        class LocalRequest:
            headers = {
                "x-forwarded-user": "alice",
                "x-forwarded-roles": "analyst,viewer",
                "x-forwarded-tenant": "tenant-a",
            }
            client = LocalClient()

        class RemoteRequest:
            headers = LocalRequest.headers
            client = RemoteClient()

        with (
            patch.object(_config, "RAPTOR_TRUSTED_SSO_ENABLED", True),
            patch.object(_config, "RAPTOR_TRUSTED_PROXY_CIDRS", ["127.0.0.1/32"]),
            patch.object(_config, "RAPTOR_SSO_USER_HEADER", "x-forwarded-user"),
            patch.object(_config, "RAPTOR_SSO_ROLES_HEADER", "x-forwarded-roles"),
            patch.object(_config, "RAPTOR_SSO_TENANT_HEADER", "x-forwarded-tenant"),
        ):
            principal = auth_core._trusted_sso_principal(LocalRequest())
            self.assertEqual(principal["actor"], "alice")
            self.assertIn("analyst", principal["roles"])
            self.assertEqual(principal["tenant_id"], "tenant-a")
            self.assertIsNone(auth_core._trusted_sso_principal(RemoteRequest()))

    # ── Schema migration ──────────────────────────────────────────────────────

    def test_schema_migration_baseline_is_recorded(self):
        conn = sqlite3.connect(str(_config.DB_PATH))
        try:
            version = conn.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                ("20260505_runtime_metadata_baseline",),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(version)

    def test_dynamic_update_helpers_reject_unknown_columns(self):
        database.db_create("case-1", {}, input_bytes=0)
        with self.assertRaises(ValueError):
            database.db_update("case-1", **{"status = 'complete' --": "x"})
        with self.assertRaises(ValueError):
            database.update_elastic_poll_state(**{"enabled = 1 --": 1})

    # ── External feed URL allowlist ───────────────────────────────────────────

    def test_external_feed_url_allowlist_blocks_internal_hosts(self):
        with self.assertRaises(RuntimeError):
            auth_core.validate_feed_url("http://127.0.0.1:8000/secrets")

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def test_rate_limit_enforcement_blocks_after_configured_threshold(self):
        auth_core.RATE_LIMIT_BUCKETS.clear()
        original_rules = dict(auth_core.RATE_LIMIT_RULES)
        auth_core.RATE_LIMIT_RULES["auth"] = (2, 60)
        try:
            auth_core.enforce_rate_limit(None, "auth")
            auth_core.enforce_rate_limit(None, "auth")
            with self.assertRaises(HTTPException) as ctx:
                auth_core.enforce_rate_limit(None, "auth")
            self.assertEqual(ctx.exception.status_code, 429)
        finally:
            auth_core.RATE_LIMIT_RULES.update(original_rules)

    # ── Auth session ──────────────────────────────────────────────────────────

    def test_auth_session_creates_server_side_record(self):
        """Authenticate admin → create session → verify DB record exists."""
        principal = auth_core.authenticate_user("admin", "admin-secret")
        token = auth_core._make_session_token()
        auth_core.create_session(principal["user_id"], token)

        conn = sqlite3.connect(str(_config.DB_PATH))
        try:
            count = conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
        finally:
            conn.close()

        self.assertEqual(principal["actor"], "admin")
        self.assertIn("admin", principal["roles"])
        self.assertEqual(count, 1)

        # Token must resolve back to the same principal
        resolved = auth_core._valid_session_token(token)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["actor"], "admin")

    # ── Durable job queue ─────────────────────────────────────────────────────

    def test_durable_queue_claims_pending_investigation(self):
        database.db_create("case-queue", {"case_name": "Queued", "source": "test"}, input_bytes=5)
        database.enqueue_investigation_job("case-queue", "event", {"source": "test"})
        claimed = database.claim_next_investigation_job()

        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["investigation_id"], "case-queue")
        self.assertEqual(claimed["log_content"], "event")

    # ── CISA KEV connector ────────────────────────────────────────────────────

    def test_cisa_kev_connector_uses_file_cache_and_filters(self):
        kev_payload = {
            "title": "Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2026.04.26",
            "dateReleased": "2026-04-26T00:00:00Z",
            "_raptor_cached_at": "2026-04-26T10:00:00Z",
            "_raptor_source": "cache",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-0001",
                    "vendorProject": "Example",
                    "product": "Gateway",
                    "vulnerabilityName": "Gateway command injection",
                    "dateAdded": "2026-04-26",
                    "shortDescription": "Command injection.",
                    "requiredAction": "Patch",
                    "dueDate": "2026-05-01",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "",
                },
                {
                    "cveID": "CVE-2026-0002",
                    "vendorProject": "Other",
                    "product": "Server",
                    "vulnerabilityName": "Server bug",
                    "dateAdded": "2026-04-26",
                    "shortDescription": "Other issue.",
                    "requiredAction": "Patch",
                    "dueDate": "2026-05-01",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                },
            ],
        }
        _config.CISA_KEV_CACHE_PATH.write_text(json.dumps(kev_payload), encoding="utf-8")

        with patch.object(database, "redis_get_json", return_value=None):
            payload = database.fetch_cisa_kev(refresh=False)

        vulns = [
            v for v in payload.get("vulnerabilities", [])
            if "gateway" in json.dumps(v, default=str).lower()
        ]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cveID"], "CVE-2026-0001")

    # ── Elasticsearch poll ────────────────────────────────────────────────────

    def test_elasticsearch_poll_records_no_event_state(self):
        from pipeline_runner import run_elasticsearch_poll_once

        with patch(
            "pipeline_runner.fetch_elasticsearch_logs",
            side_effect=HTTPException(status_code=404, detail="No Elasticsearch events matched"),
        ):
            response = run_elasticsearch_poll_once(query="powershell")

        state = database.get_elastic_poll_state()
        self.assertEqual(response.status, "no_events")
        self.assertEqual(response.event_bytes, 0)
        self.assertEqual(state["last_status"], "no_events")

    def test_elasticsearch_poll_deduplicates_replayed_hits(self):
        from pipeline_runner import run_elasticsearch_poll_once

        event = {
            "@timestamp": "2026-04-27T10:00:00Z",
            "message": "powershell execution",
            "_raptor_elastic": {"index": "raptor-events-1", "id": "hit-1"},
        }

        def fake_start(content, metadata=None, raw_bytes=None):
            return ElasticPollResponse(
                status="queued", investigation_id="case-elastic",
                message="queued", event_bytes=len(content),
            )

        with (
            patch("pipeline_runner.fetch_elasticsearch_logs", return_value=json.dumps(event)),
            patch("pipeline_runner.start_investigation_from_content", side_effect=fake_start),
        ):
            first = run_elasticsearch_poll_once(query="powershell")
            second = run_elasticsearch_poll_once(query="powershell")

        self.assertEqual(first.status, "investigation_created")
        self.assertEqual(second.status, "no_events")

    def test_elasticsearch_poll_endpoint_scopes_created_case_to_actor(self):
        from pipeline_runner import run_elasticsearch_poll_once

        captured: dict = {}

        def fake_poll(**kwargs):
            captured.update(kwargs)
            return ElasticPollResponse(status="no_events", message="none", event_bytes=0)

        class State:
            principal = auth_core._principal("analyst", ["analyst"], "tenant-a", "user-a")

        class FakeRequest:
            state = State()

        with patch("routers.intelligence.run_elasticsearch_poll_once", side_effect=fake_poll):
            from routers.intelligence import poll_elasticsearch
            poll_elasticsearch(FakeRequest(), ElasticPollRequest(query="powershell"))

        self.assertEqual(captured["owner_id"], "user-a")
        self.assertEqual(captured["tenant_id"], "tenant-a")

    # ── Production startup validation ─────────────────────────────────────────

    def test_production_startup_requires_sqlite_limit_acknowledgement(self):
        prod_config = dict(
            RAPTOR_PRODUCTION=True,
            RAPTOR_PROCESS_ROLE="api",
            RAPTOR_DB_ENGINE="sqlite",
            RAPTOR_DATABASE_URL="",
            RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS=False,
            RAPTOR_API_KEY="production-api-key",
            RAPTOR_ALLOW_AUTH_DISABLED=False,
            RAPTOR_REQUIRE_RBAC=True,
            RAPTOR_RATE_LIMIT_BACKEND="memory",
            RAPTOR_SESSION_COOKIE_SECURE=True,
            RAPTOR_BOOTSTRAP_ADMIN_PASSWORD="production-admin-password",
            EVIDENCE_ENCRYPTION_KEY="production-evidence-key-with-32-plus-bytes-of-entropy",
            NEO4J_PASSWORD="production-neo4j-password",
            CORS_ALLOW_ORIGINS=["https://raptor.example.com"],
        )
        with patch.multiple(_config, **prod_config):
            with self.assertRaisesRegex(RuntimeError, "SQLite is a single-node runtime store"):
                _config.validate_startup_config()

            with patch.object(_config, "RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS", True):
                with patch.multiple(_config, **prod_config):
                    with self.assertRaisesRegex(RuntimeError, "RAPTOR_RATE_LIMIT_BACKEND=redis"):
                        _config.validate_startup_config()

            with patch.multiple(
                _config,
                **{**prod_config,
                   "RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS": True,
                   "RAPTOR_RATE_LIMIT_BACKEND": "redis"},
            ):
                _config.validate_startup_config()


if __name__ == "__main__":
    unittest.main()
