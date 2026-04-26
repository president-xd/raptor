import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

from helpers import BACKEND_DIR  # noqa: F401
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
            "ELASTIC_POLL_ENABLED": app_main.ELASTIC_POLL_ENABLED,
            "ELASTIC_POLL_QUERY": app_main.ELASTIC_POLL_QUERY,
            "ELASTIC_POLL_INTERVAL_SECONDS": app_main.ELASTIC_POLL_INTERVAL_SECONDS,
            "ELASTIC_POLL_WINDOW_MINUTES": app_main.ELASTIC_POLL_WINDOW_MINUTES,
        }
        app_main.DB_PATH = self.root / "raptor.db"
        app_main.EVIDENCE_DIR = self.root / "evidence"
        app_main.CISA_KEV_CACHE_PATH = self.root / "intel" / "cisa_kev.json"
        app_main.CISA_KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        app_main.RAPTOR_API_KEY = ""
        app_main.ELASTIC_POLL_ENABLED = False
        app_main.ELASTIC_POLL_QUERY = "*"
        app_main.ELASTIC_POLL_INTERVAL_SECONDS = 300
        app_main.ELASTIC_POLL_WINDOW_MINUTES = 5
        app_main.init_db()

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(app_main, name, value)
        self.tmp.cleanup()

    def test_api_key_middleware_allows_docs_and_guards_api(self):
        app_main.RAPTOR_API_KEY = "test-secret"

        with TestClient(app_main.app) as client:
            docs = client.get("/docs")
            blocked = client.get("/api/v1/investigations")
            allowed = client.get("/api/v1/investigations", headers={"Authorization": "Bearer test-secret"})

        self.assertEqual(docs.status_code, 200)
        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(allowed.status_code, 200)

    def test_evidence_endpoint_lists_persisted_raw_upload_metadata(self):
        app_main.db_create("case-1", {"case_name": "Case One", "source": "file"}, input_bytes=18)
        app_main.store_evidence_file(
            "case-1",
            b'{"event":"one"}',
            {"filename": "raw.json", "content_type": "application/json", "source": "file"},
        )

        with TestClient(app_main.app) as client:
            response = client.get("/api/v1/investigate/case-1/evidence")

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["investigation_id"], "case-1")
        self.assertEqual(payload["total_count"], 1)
        self.assertEqual(payload["evidence"][0]["original_filename"], "raw.json")
        self.assertEqual(payload["evidence"][0]["source"], "file")

    def test_audit_log_endpoint_returns_structured_details(self):
        app_main.audit_log(None, "query.asked", "case-1", {"question": "Which hosts?"})

        with TestClient(app_main.app) as client:
            response = client.get("/api/v1/audit?investigation_id=case-1")

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(payload["total_count"], 1)
        self.assertEqual(payload["entries"][0]["action"], "query.asked")
        self.assertEqual(payload["entries"][0]["detail"]["question"], "Which hosts?")

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

    def test_cisa_kev_connector_uses_file_cache_and_filters(self):
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

        with TestClient(app_main.app) as client:
            response = client.get("/api/v1/threat-feeds/cisa-kev?query=gateway&limit=5")

        payload = response.json()
        self.assertEqual(response.status_code, 200)
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


if __name__ == "__main__":
    unittest.main()
