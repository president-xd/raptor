"""
Persistence connector tests.
Covers: evidence store, audit log tamper-proofing, Elasticsearch poll state,
and API key middleware logic.

Updated to use the modular architecture (config / database / auth_core).
"""
import asyncio
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import patch

from helpers import BACKEND_DIR  # noqa: F401 — adds backend/ to sys.path

import config as _config
import database
import auth_core


class PersistenceConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)

        # Patch config values to point at the test temp directory
        self._patches = [
            patch.object(_config, "DB_PATH", root / "raptor.db"),
            patch.object(_config, "EVIDENCE_DIR", root / "evidence"),
            patch.object(_config, "ELASTIC_POLL_ENABLED", False),
            patch.object(_config, "ELASTIC_POLL_QUERY", "*"),
            patch.object(_config, "ELASTIC_POLL_INTERVAL_SECONDS", 300),
            patch.object(_config, "ELASTIC_POLL_WINDOW_MINUTES", 5),
            patch.object(_config, "RAPTOR_API_KEY", ""),
            patch.object(_config, "RAPTOR_ALLOW_AUTH_DISABLED", True),
            patch.object(_config, "CORS_ALLOW_ORIGINS", ["http://localhost:3100"]),
            patch.object(_config, "RAPTOR_REQUIRE_RBAC", False),
            patch.object(_config, "RAPTOR_PRODUCTION", False),
            patch.object(_config, "EVIDENCE_ENCRYPTION_KEY", ""),
            patch.object(_config, "RAPTOR_BOOTSTRAP_ADMIN_PASSWORD", ""),
            patch.object(_config, "RAPTOR_BOOTSTRAP_ADMIN_DISABLED", False),
            patch.object(_config, "RAPTOR_STORAGE_BACKEND", "local"),
        ]
        for p in self._patches:
            p.start()

        database.init_db()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self.tmp.cleanup()

    # ── Evidence store ────────────────────────────────────────────────────────

    def test_evidence_store_persists_file_and_metadata(self):
        content = b'{"event": "powershell"}'
        summary = database.store_evidence_file(
            "case-1",
            content,
            {
                "filename": "../raw upload.json",
                "content_type": "application/json",
                "source": "file",
            },
        )

        self.assertEqual(summary["original_filename"], "raw_upload.json")
        self.assertEqual(summary["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(summary["size_bytes"], len(content))
        self.assertTrue(Path(summary["stored_path"]).is_file())

        rows = database.list_evidence_files("case-1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha256"], summary["sha256"])
        self.assertEqual(rows[0]["source"], "file")

    def test_evidence_store_avoids_same_second_filename_collision(self):
        meta = {"filename": "raw.json", "content_type": "application/json", "source": "file"}
        first = database.store_evidence_file("case-1", b"first", meta)
        second = database.store_evidence_file("case-1", b"second", meta)

        self.assertNotEqual(first["stored_path"], second["stored_path"])
        self.assertTrue(Path(first["stored_path"]).is_file())
        self.assertTrue(Path(second["stored_path"]).is_file())

    # ── Audit log ─────────────────────────────────────────────────────────────

    def test_audit_log_is_append_only(self):
        database.audit_log("test-user", "report.viewed", "case-1", {"status": "complete"})

        entries = database.list_audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "report.viewed")
        self.assertEqual(entries[0]["detail"]["status"], "complete")

        db_path = str(_config.DB_PATH)
        conn = sqlite3.connect(db_path)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_log SET action = 'tampered'")
        finally:
            conn.close()

        conn = sqlite3.connect(db_path)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_log")
        finally:
            conn.close()

    # ── Elasticsearch poll state ──────────────────────────────────────────────

    def test_elasticsearch_poller_state_tracks_environment_defaults(self):
        state = database.get_elastic_poll_state()
        self.assertFalse(state["enabled"])
        self.assertEqual(state["query"], "*")

        with (
            patch.object(_config, "ELASTIC_POLL_ENABLED", True),
            patch.object(_config, "ELASTIC_POLL_QUERY", "powershell OR mimikatz"),
            patch.object(_config, "ELASTIC_POLL_INTERVAL_SECONDS", 120),
            patch.object(_config, "ELASTIC_POLL_WINDOW_MINUTES", 15),
        ):
            database.init_db()
            state = database.get_elastic_poll_state()

        self.assertTrue(state["enabled"])
        self.assertEqual(state["query"], "powershell OR mimikatz")
        self.assertEqual(state["interval_seconds"], 120)
        self.assertEqual(state["window_minutes"], 15)

    # ── API key auth middleware ────────────────────────────────────────────────

    def test_api_key_middleware_guards_api_routes(self):
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
            import main as _main
            blocked = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))

            FakeRequest.headers = {"x-raptor-api-key": "test-secret"}
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
        ):
            import main as _main
            blocked = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(blocked.headers["access-control-allow-origin"], "http://ui.local")

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
            import main as _main
            allowed = asyncio.run(_main.optional_api_key_auth(FakeRequest(), call_next))

        self.assertEqual(allowed, "allowed")


if __name__ == "__main__":
    unittest.main()
