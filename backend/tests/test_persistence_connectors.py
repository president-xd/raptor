import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import main as app_main


class PersistenceConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.originals = {
            "DB_PATH": app_main.DB_PATH,
            "EVIDENCE_DIR": app_main.EVIDENCE_DIR,
            "ELASTIC_POLL_ENABLED": app_main.ELASTIC_POLL_ENABLED,
            "ELASTIC_POLL_QUERY": app_main.ELASTIC_POLL_QUERY,
            "ELASTIC_POLL_INTERVAL_SECONDS": app_main.ELASTIC_POLL_INTERVAL_SECONDS,
            "ELASTIC_POLL_WINDOW_MINUTES": app_main.ELASTIC_POLL_WINDOW_MINUTES,
            "RAPTOR_API_KEY": app_main.RAPTOR_API_KEY,
        }
        root = Path(self.tmp.name)
        app_main.DB_PATH = root / "raptor.db"
        app_main.EVIDENCE_DIR = root / "evidence"
        app_main.ELASTIC_POLL_ENABLED = False
        app_main.ELASTIC_POLL_QUERY = "*"
        app_main.ELASTIC_POLL_INTERVAL_SECONDS = 300
        app_main.ELASTIC_POLL_WINDOW_MINUTES = 5
        app_main.RAPTOR_API_KEY = ""
        app_main.init_db()

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(app_main, name, value)
        self.tmp.cleanup()

    def test_evidence_store_persists_file_and_metadata(self):
        content = b'{"event": "powershell"}'

        summary = app_main.store_evidence_file(
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

        rows = app_main.list_evidence_files("case-1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha256"], summary["sha256"])
        self.assertEqual(rows[0]["source"], "file")

    def test_audit_log_is_append_only(self):
        app_main.audit_log(None, "report.viewed", "case-1", {"status": "complete"})

        entries = app_main.list_audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "report.viewed")
        self.assertEqual(entries[0]["detail"]["status"], "complete")

        conn = sqlite3.connect(str(app_main.DB_PATH))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_log SET action = 'tampered'")
        finally:
            conn.close()

        conn = sqlite3.connect(str(app_main.DB_PATH))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_log")
        finally:
            conn.close()

    def test_elasticsearch_poller_state_tracks_environment_defaults(self):
        state = app_main.get_elastic_poll_state()
        self.assertFalse(state["enabled"])
        self.assertEqual(state["query"], "*")

        app_main.ELASTIC_POLL_ENABLED = True
        app_main.ELASTIC_POLL_QUERY = "powershell OR mimikatz"
        app_main.ELASTIC_POLL_INTERVAL_SECONDS = 120
        app_main.ELASTIC_POLL_WINDOW_MINUTES = 15
        app_main.init_db()

        state = app_main.get_elastic_poll_state()
        self.assertTrue(state["enabled"])
        self.assertEqual(state["query"], "powershell OR mimikatz")
        self.assertEqual(state["interval_seconds"], 120)
        self.assertEqual(state["window_minutes"], 15)

    def test_api_key_middleware_guards_api_routes(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        with TestClient(app_main.app) as client:
            blocked = client.get("/api/v1/investigations")
            allowed = client.get(
                "/api/v1/investigations",
                headers={"X-RAPTOR-API-Key": "test-secret"},
            )
            docs = client.get("/docs")

        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(docs.status_code, 200)


if __name__ == "__main__":
    unittest.main()
