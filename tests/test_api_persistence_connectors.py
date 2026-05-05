import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError
from starlette.responses import Response

from helpers import BACKEND_DIR  # noqa: F401
from models import AuthSessionRequest
import config as app_config
import main as app_main


class ApiPersistenceConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.originals = {
            "DB_PATH": app_main.DB_PATH,
            "EVIDENCE_DIR": app_main.EVIDENCE_DIR,
            "CISA_KEV_CACHE_PATH": app_main.CISA_KEV_CACHE_PATH,
            "RAPTOR_API_KEY": app_main.RAPTOR_API_KEY,
            "RAPTOR_ALLOW_AUTH_DISABLED": app_main.RAPTOR_ALLOW_AUTH_DISABLED,
            "RAPTOR_REQUIRE_RBAC": app_main.RAPTOR_REQUIRE_RBAC,
            "RAPTOR_BOOTSTRAP_ADMIN_USERNAME": app_main.RAPTOR_BOOTSTRAP_ADMIN_USERNAME,
            "RAPTOR_BOOTSTRAP_ADMIN_PASSWORD": app_main.RAPTOR_BOOTSTRAP_ADMIN_PASSWORD,
            "CORS_ALLOW_ORIGINS": app_main.CORS_ALLOW_ORIGINS,
            "EVIDENCE_ENCRYPTION_KEY": app_main.EVIDENCE_ENCRYPTION_KEY,
            "ELASTIC_POLL_ENABLED": app_main.ELASTIC_POLL_ENABLED,
            "ELASTIC_POLL_QUERY": app_main.ELASTIC_POLL_QUERY,
            "ELASTIC_POLL_INTERVAL_SECONDS": app_main.ELASTIC_POLL_INTERVAL_SECONDS,
            "ELASTIC_POLL_WINDOW_MINUTES": app_main.ELASTIC_POLL_WINDOW_MINUTES,
            "CISA_KEV_URL": app_main.CISA_KEV_URL,
            "RATE_LIMIT_BUCKETS": dict(app_main.RATE_LIMIT_BUCKETS),
        }
        app_main.DB_PATH = self.root / "raptor.db"
        app_main.EVIDENCE_DIR = self.root / "evidence"
        app_main.CISA_KEV_CACHE_PATH = self.root / "intel" / "cisa_kev.json"
        app_main.CISA_KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        app_main.RAPTOR_API_KEY = ""
        app_main.RAPTOR_ALLOW_AUTH_DISABLED = True
        app_main.RAPTOR_REQUIRE_RBAC = True
        app_main.RAPTOR_BOOTSTRAP_ADMIN_USERNAME = "admin"
        app_main.RAPTOR_BOOTSTRAP_ADMIN_PASSWORD = "admin-secret"
        app_main.EVIDENCE_ENCRYPTION_KEY = ""
        app_main.ELASTIC_POLL_ENABLED = False
        app_main.ELASTIC_POLL_QUERY = "*"
        app_main.ELASTIC_POLL_INTERVAL_SECONDS = 300
        app_main.ELASTIC_POLL_WINDOW_MINUTES = 5
        app_main.RATE_LIMIT_BUCKETS.clear()
        app_main.init_db()

    def tearDown(self):
        for name, value in self.originals.items():
            if name == "RATE_LIMIT_BUCKETS":
                app_main.RATE_LIMIT_BUCKETS.clear()
                app_main.RATE_LIMIT_BUCKETS.update(value)
            else:
                setattr(app_main, name, value)
        self.tmp.cleanup()

    def test_api_key_middleware_allows_docs_and_guards_api(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        class FakeURL:
            path = "/api/v1/investigations"

        class FakeRequest:
            url = FakeURL()
            headers = {}
            cookies = {}

        async def call_next(_request):
            return "allowed"

        blocked = asyncio.run(app_main.optional_api_key_auth(FakeRequest(), call_next))
        FakeRequest.headers = {"authorization": "Bearer test-secret"}
        allowed = asyncio.run(app_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(allowed, "allowed")

    def test_api_key_middleware_keeps_cors_headers_on_auth_challenge(self):
        app_main.RAPTOR_API_KEY = "test-secret"
        app_main.CORS_ALLOW_ORIGINS = ["http://ui.local"]

        class FakeURL:
            path = "/api/v1/investigations"

        class FakeRequest:
            method = "GET"
            url = FakeURL()
            headers = {"origin": "http://ui.local"}
            cookies = {}

        async def call_next(_request):
            return "allowed"

        blocked = asyncio.run(app_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(blocked.headers["access-control-allow-origin"], "http://ui.local")
        self.assertEqual(blocked.headers["access-control-allow-credentials"], "true")

    def test_api_key_middleware_allows_cors_preflight(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        class FakeURL:
            path = "/api/v1/investigations"

        class FakeRequest:
            method = "OPTIONS"
            url = FakeURL()
            headers = {"origin": "http://ui.local"}
            cookies = {}

        async def call_next(_request):
            return "allowed"

        allowed = asyncio.run(app_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(allowed, "allowed")

    def test_evidence_endpoint_lists_persisted_raw_upload_metadata(self):
        app_main.db_create("case-1", {"case_name": "Case One", "source": "file"}, input_bytes=18)
        app_main.store_evidence_file(
            "case-1",
            b'{"event":"one"}',
            {"filename": "raw.json", "content_type": "application/json", "source": "file"},
        )

        response = asyncio.run(app_main.get_evidence(None, "case-1"))

        payload = response.model_dump()
        self.assertEqual(payload["investigation_id"], "case-1")
        self.assertEqual(payload["total_count"], 1)
        self.assertEqual(payload["evidence"][0]["original_filename"], "raw.json")
        self.assertEqual(payload["evidence"][0]["source"], "file")
        self.assertNotIn("stored_path", payload["evidence"][0])

    def test_public_evidence_summary_model_does_not_expose_stored_path(self):
        summary = app_main.EvidenceFileSummary(
            investigation_id="case-1",
            original_filename="raw.json",
            stored_path="/secret/internal/path/raw.json",
            sha256="abc",
        )

        self.assertNotIn("stored_path", summary.model_dump())

    def test_request_models_reject_oversized_security_sensitive_fields(self):
        with self.assertRaises(ValidationError):
            app_main.AuthSessionRequest(username="u", password="x" * 300)
        with self.assertRaises(ValidationError):
            app_main.QueryRequest(investigation_id="case-1", question="q" * 2500)
        with self.assertRaises(ValidationError):
            app_main.ElasticPollRequest(query="q" * 1200)

    def test_evidence_encryption_records_metadata_and_hides_plaintext(self):
        app_main.EVIDENCE_ENCRYPTION_KEY = "test-evidence-key-with-enough-length"
        content = b'{"secret":"do-not-store-cleartext"}'

        summary = app_main.store_evidence_file(
            "case-1",
            content,
            {"filename": "raw.json", "content_type": "application/json", "source": "file"},
        )

        stored_bytes = Path(summary["stored_path"]).read_bytes()
        self.assertTrue(summary["encrypted"])
        self.assertNotEqual(stored_bytes, content)
        self.assertEqual(app_main.decrypt_evidence(stored_bytes), content)
        self.assertIn("aes-256-gcm", summary["encryption_key_id"])
        self.assertEqual(summary["sha256"], app_main.hashlib.sha256(content).hexdigest())
        self.assertTrue(summary["retention_expires_at"])

    def test_csrf_guard_blocks_untrusted_browser_session_mutation(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        class FakeURL:
            path = "/api/v1/investigate/text"

        class FakeRequest:
            method = "POST"
            url = FakeURL()
            headers = {"origin": "https://evil.example"}
            cookies = {"raptor_session": "session-token"}

        async def call_next(_request):
            return "allowed"

        blocked = asyncio.run(app_main.csrf_guard(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 403)

    def test_csrf_guard_allows_api_key_service_mutation(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        class FakeURL:
            path = "/api/v1/investigate/text"

        class FakeRequest:
            method = "POST"
            url = FakeURL()
            headers = {"authorization": "Bearer test-secret"}
            cookies = {"raptor_session": "session-token"}

        async def call_next(_request):
            return "allowed"

        allowed = asyncio.run(app_main.csrf_guard(FakeRequest(), call_next))

        self.assertEqual(allowed, "allowed")

    def test_audit_log_endpoint_returns_structured_details(self):
        app_main.db_create("case-1", {"case_name": "Case One", "source": "test"}, input_bytes=1)
        app_main.audit_log(None, "query.asked", "case-1", {"question": "Which hosts?"})

        response = asyncio.run(app_main.get_audit_log(None, investigation_id="case-1"))

        payload = response.model_dump()
        self.assertGreaterEqual(payload["total_count"], 1)
        self.assertEqual(payload["entries"][0]["action"], "query.asked")
        self.assertEqual(payload["entries"][0]["detail"]["question"], "Which hosts?")

    def test_global_audit_log_requires_admin_role(self):
        class State:
            principal = app_main._principal("viewer", ["viewer"], "default", "viewer-1")

        class FakeRequest:
            state = State()

        with self.assertRaises(HTTPException):
            asyncio.run(app_main.get_audit_log(FakeRequest()))

    def test_sensitive_connector_mutations_require_analyst_role(self):
        class State:
            principal = app_main._principal("viewer", ["viewer"], "default", "viewer-1")

        class FakeRequest:
            state = State()

        with self.assertRaises(HTTPException):
            app_main.sync_cisa_kev(FakeRequest())
        with self.assertRaises(HTTPException):
            app_main.poll_elasticsearch(FakeRequest(), app_main.ElasticPollRequest(query="*"))

    def test_elasticsearch_poll_endpoint_scopes_created_case_to_actor(self):
        class State:
            principal = app_main._principal("analyst", ["analyst"], "tenant-a", "user-a")

        class FakeRequest:
            state = State()

        captured = {}
        original_poll = app_main.run_elasticsearch_poll_once
        app_main.run_elasticsearch_poll_once = lambda **kwargs: captured.update(kwargs) or app_main.ElasticPollResponse(
            status="no_events",
            message="none",
            event_bytes=0,
        )
        try:
            app_main.poll_elasticsearch(FakeRequest(), app_main.ElasticPollRequest(query="powershell"))
        finally:
            app_main.run_elasticsearch_poll_once = original_poll

        self.assertEqual(captured["owner_id"], "user-a")
        self.assertEqual(captured["tenant_id"], "tenant-a")

    def test_production_startup_requires_sqlite_limit_acknowledgement(self):
        originals = {
            "RAPTOR_PRODUCTION": app_config.RAPTOR_PRODUCTION,
            "RAPTOR_PROCESS_ROLE": app_config.RAPTOR_PROCESS_ROLE,
            "RAPTOR_DB_ENGINE": app_config.RAPTOR_DB_ENGINE,
            "RAPTOR_DATABASE_URL": app_config.RAPTOR_DATABASE_URL,
            "RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS": app_config.RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS,
            "RAPTOR_API_KEY": app_config.RAPTOR_API_KEY,
            "RAPTOR_ALLOW_AUTH_DISABLED": app_config.RAPTOR_ALLOW_AUTH_DISABLED,
            "RAPTOR_REQUIRE_RBAC": app_config.RAPTOR_REQUIRE_RBAC,
            "RAPTOR_RATE_LIMIT_BACKEND": app_config.RAPTOR_RATE_LIMIT_BACKEND,
            "RAPTOR_SESSION_COOKIE_SECURE": app_config.RAPTOR_SESSION_COOKIE_SECURE,
            "RAPTOR_BOOTSTRAP_ADMIN_PASSWORD": app_config.RAPTOR_BOOTSTRAP_ADMIN_PASSWORD,
            "EVIDENCE_ENCRYPTION_KEY": app_config.EVIDENCE_ENCRYPTION_KEY,
            "NEO4J_PASSWORD": app_config.NEO4J_PASSWORD,
            "CORS_ALLOW_ORIGINS": app_config.CORS_ALLOW_ORIGINS,
        }
        try:
            app_config.RAPTOR_PRODUCTION = True
            app_config.RAPTOR_PROCESS_ROLE = "api"
            app_config.RAPTOR_DB_ENGINE = "sqlite"
            app_config.RAPTOR_DATABASE_URL = ""
            app_config.RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS = False
            app_config.RAPTOR_API_KEY = "production-api-key"
            app_config.RAPTOR_ALLOW_AUTH_DISABLED = False
            app_config.RAPTOR_REQUIRE_RBAC = True
            app_config.RAPTOR_RATE_LIMIT_BACKEND = "memory"
            app_config.RAPTOR_SESSION_COOKIE_SECURE = True
            app_config.RAPTOR_BOOTSTRAP_ADMIN_PASSWORD = "production-admin-password"
            app_config.EVIDENCE_ENCRYPTION_KEY = "production-evidence-key"
            app_config.NEO4J_PASSWORD = "production-neo4j-password"
            app_config.CORS_ALLOW_ORIGINS = ["https://raptor.example.com"]

            with self.assertRaisesRegex(RuntimeError, "SQLite is a single-node runtime store"):
                app_config.validate_startup_config()

            app_config.RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS = True
            with self.assertRaisesRegex(RuntimeError, "RAPTOR_RATE_LIMIT_BACKEND=redis"):
                app_config.validate_startup_config()

            app_config.RAPTOR_RATE_LIMIT_BACKEND = "redis"
            app_config.validate_startup_config()

            app_config.RAPTOR_DB_ENGINE = "postgresql"
            app_config.RAPTOR_DATABASE_URL = "postgresql://raptor:secret@postgres:5432/raptor"
            app_config.RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS = False
            app_config.validate_startup_config()
        finally:
            for name, value in originals.items():
                setattr(app_config, name, value)

    def test_audit_actor_ignores_spoofable_identity_headers(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        class Client:
            host = "127.0.0.1"

        class FakeRequest:
            headers = {
                "x-raptor-actor": "spoofed-admin",
                "x-forwarded-user": "spoofed-user",
                "x-raptor-api-key": "test-secret",
            }
            cookies = {}
            client = Client()

        app_main.audit_log(FakeRequest(), "report.viewed", "case-1", {"status": "complete"})
        entry = app_main.list_audit_entries(investigation_id="case-1")[0]

        self.assertEqual(entry["actor"], "api-key")

    def test_audit_actor_uses_authenticated_principal_when_available(self):
        class State:
            principal = app_main._principal("alice", ["analyst"], "default", "user-1")

        class Client:
            host = "127.0.0.1"

        class FakeRequest:
            state = State()
            headers = {"x-raptor-actor": "spoofed-admin"}
            cookies = {}
            client = Client()

        app_main.audit_log(FakeRequest(), "report.viewed", "case-1", {})
        entry = app_main.list_audit_entries(investigation_id="case-1")[0]

        self.assertEqual(entry["actor"], "alice")

    def test_trusted_sso_headers_require_trusted_proxy(self):
        originals = {
            "RAPTOR_TRUSTED_SSO_ENABLED": app_main.RAPTOR_TRUSTED_SSO_ENABLED,
            "RAPTOR_TRUSTED_PROXY_CIDRS": app_main.RAPTOR_TRUSTED_PROXY_CIDRS,
        }
        app_main.RAPTOR_TRUSTED_SSO_ENABLED = True
        app_main.RAPTOR_TRUSTED_PROXY_CIDRS = ["127.0.0.1/32"]

        class LocalClient:
            host = "127.0.0.1"

        class RemoteClient:
            host = "10.0.0.5"

        class LocalRequest:
            headers = {"x-forwarded-user": "alice", "x-forwarded-roles": "analyst,viewer", "x-forwarded-tenant": "tenant-a"}
            client = LocalClient()

        class RemoteRequest:
            headers = LocalRequest.headers
            client = RemoteClient()

        try:
            principal = app_main._trusted_sso_principal(LocalRequest())
            self.assertEqual(principal["actor"], "alice")
            self.assertIn("analyst", principal["roles"])
            self.assertEqual(principal["tenant_id"], "tenant-a")
            self.assertIsNone(app_main._trusted_sso_principal(RemoteRequest()))
        finally:
            for name, value in originals.items():
                setattr(app_main, name, value)

    def test_schema_migration_baseline_is_recorded(self):
        conn = sqlite3.connect(str(app_main.DB_PATH))
        try:
            version = conn.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                ("20260505_runtime_metadata_baseline",),
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(version)

    def test_dynamic_update_helpers_reject_unknown_columns(self):
        with self.assertRaises(ValueError):
            app_main.db_update("case-1", **{"status = 'complete' --": "x"})
        with self.assertRaises(ValueError):
            app_main.update_elastic_poll_state(**{"enabled = 1 --": 1})

    def test_external_feed_url_allowlist_blocks_internal_hosts(self):
        app_main.CISA_KEV_URL = "http://127.0.0.1:8000/secrets"

        with self.assertRaises(RuntimeError):
            app_main.fetch_cisa_kev(refresh=True)

    def test_rate_limit_enforcement_blocks_after_configured_threshold(self):
        app_main.RATE_LIMIT_BUCKETS.clear()
        app_main.RATE_LIMIT_RULES["auth"] = (2, 60)
        try:
            app_main.enforce_rate_limit(None, "auth")
            app_main.enforce_rate_limit(None, "auth")
            with self.assertRaises(HTTPException) as ctx:
                app_main.enforce_rate_limit(None, "auth")
            self.assertEqual(ctx.exception.status_code, 429)
        finally:
            app_main.RATE_LIMIT_RULES["auth"] = (10, 60)

    def test_audit_table_rejects_update_and_delete(self):
        app_main.audit_log(None, "report.viewed", "case-1", {"status": "complete"})

        conn = sqlite3.connect(str(app_main.DB_PATH))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_log SET action = 'tampered'")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_log")
        finally:
            conn.close()

    def test_audit_hash_chain_links_entries(self):
        app_main.audit_log(None, "report.viewed", "case-1", {"status": "complete"})
        app_main.audit_log(None, "graph.viewed", "case-1", {"status": "complete"})

        conn = sqlite3.connect(str(app_main.DB_PATH))
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
        self.assertTrue(rows[1]["entry_hash"])

    def test_auth_session_creates_server_side_record(self):
        response = Response()

        class Client:
            host = "127.0.0.1"

        class FakeRequest:
            state = type("State", (), {})()
            client = Client()

        payload = asyncio.run(
            app_main.create_auth_session(
                AuthSessionRequest(username="admin", password="admin-secret"),
                response,
                FakeRequest(),
            )
        )

        conn = sqlite3.connect(str(app_main.DB_PATH))
        try:
            count = conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
        finally:
            conn.close()

        self.assertTrue(payload.authenticated)
        self.assertEqual(payload.actor, "admin")
        self.assertIn("admin", payload.roles)
        self.assertEqual(count, 1)

    def test_durable_queue_claims_pending_investigation(self):
        app_main.db_create("case-queue", {"case_name": "Queued", "source": "test"}, input_bytes=5)
        app_main.enqueue_investigation_job("case-queue", "event", {"source": "test"})

        claimed = app_main.claim_next_investigation_job()

        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["investigation_id"], "case-queue")
        self.assertEqual(claimed["log_content"], "event")

    def test_case_access_requires_owner_for_non_admin_user(self):
        app_main.db_create(
            "case-owned",
            {"case_name": "Owned", "source": "test", "tenant_id": "default", "owner_id": "owner-1"},
            input_bytes=5,
        )

        class State:
            principal = app_main._principal("other", ["viewer"], "default", "owner-2")

        class FakeRequest:
            state = State()

        with self.assertRaises(HTTPException):
            app_main.ensure_investigation_access(FakeRequest(), "case-owned", "viewer")

    def test_cisa_kev_connector_uses_file_cache_and_filters(self):
        original_redis_get = app_main.redis_get_json
        original_redis_set = app_main.redis_set_json
        app_main.redis_get_json = lambda _key: None
        app_main.redis_set_json = lambda *_args, **_kwargs: False
        app_main.CISA_KEV_CACHE_PATH.write_text(
            json.dumps(
                {
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
            ),
            encoding="utf-8",
        )

        try:
            response = app_main.get_cisa_kev(None, query="gateway", limit=5)
        finally:
            app_main.redis_get_json = original_redis_get
            app_main.redis_set_json = original_redis_set

        payload = response
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["vulnerabilities"][0]["cveID"], "CVE-2026-0001")
        self.assertEqual(payload["source"], "cache")

    def test_elasticsearch_poll_records_no_event_state(self):
        original_fetch = app_main.fetch_elasticsearch_logs
        app_main.fetch_elasticsearch_logs = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            HTTPException(status_code=404, detail="No Elasticsearch events matched that query")
        )
        try:
            response = app_main.run_elasticsearch_poll_once(query="powershell")
        finally:
            app_main.fetch_elasticsearch_logs = original_fetch

        state = app_main.get_elastic_poll_state()
        self.assertEqual(response.status, "no_events")
        self.assertEqual(response.event_bytes, 0)
        self.assertEqual(state["last_status"], "no_events")

    def test_elasticsearch_poll_deduplicates_replayed_hits(self):
        original_fetch = app_main.fetch_elasticsearch_logs
        original_start = app_main.start_investigation_now
        started_payloads = []

        event = {
            "@timestamp": "2026-04-27T10:00:00Z",
            "message": "powershell execution",
            "_raptor_elastic": {"index": "raptor-events-1", "id": "hit-1"},
        }
        app_main.fetch_elasticsearch_logs = lambda *_args, **_kwargs: json.dumps(event)
        app_main.start_investigation_now = lambda content, metadata=None: started_payloads.append(content) or type(
            "Response",
            (),
            {"investigation_id": "case-elastic", "status": "queued", "message": "queued"},
        )()
        try:
            first = app_main.run_elasticsearch_poll_once(query="powershell")
            second = app_main.run_elasticsearch_poll_once(query="powershell")
        finally:
            app_main.fetch_elasticsearch_logs = original_fetch
            app_main.start_investigation_now = original_start

        self.assertEqual(first.status, "investigation_created")
        self.assertEqual(second.status, "no_events")
        self.assertEqual(len(started_payloads), 1)


if __name__ == "__main__":
    unittest.main()
