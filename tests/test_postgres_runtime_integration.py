"""
PostgreSQL runtime integration test.
Only runs when RAPTOR_DB_ENGINE=postgresql and RAPTOR_DATABASE_URL are set.
"""
import os
import sys
import unittest
import uuid
from pathlib import Path

POSTGRES_ENABLED = (
    os.getenv("RAPTOR_DB_ENGINE") == "postgresql"
    and bool(os.getenv("RAPTOR_DATABASE_URL"))
)

_BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))


@unittest.skipUnless(
    POSTGRES_ENABLED,
    "Requires RAPTOR_DB_ENGINE=postgresql and RAPTOR_DATABASE_URL",
)
class PostgresRuntimeIntegrationTest(unittest.TestCase):
    def test_postgres_runtime_metadata_contract(self):
        import database

        case_id = f"pg-{uuid.uuid4()}"
        database.init_db()
        database.db_create(
            case_id,
            {
                "case_name": "Postgres Integration",
                "source": "test",
                "owner_id": "owner-pg",
                "tenant_id": "tenant-pg",
            },
            input_bytes=5,
        )
        database.audit_log(
            "integration-test",
            "integration.created",
            case_id,
            {"backend": "postgresql"},
        )
        database.enqueue_investigation_job(case_id, "event", {"source": "test"})

        record = database.db_get(case_id)
        entries = database.list_audit_entries(investigation_id=case_id)
        claimed = database.claim_next_investigation_job()

        self.assertEqual(record["tenant_id"], "tenant-pg")
        self.assertEqual(entries[0]["detail"]["backend"], "postgresql")
        self.assertEqual(claimed["investigation_id"], case_id)
        self.assertEqual(claimed["metadata"]["source"], "test")
