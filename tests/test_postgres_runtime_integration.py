import os
import sys
import uuid
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("RAPTOR_DB_ENGINE") != "postgresql" or not os.getenv("RAPTOR_DATABASE_URL"),
    reason="PostgreSQL integration test requires RAPTOR_DB_ENGINE=postgresql and RAPTOR_DATABASE_URL",
)


def test_postgres_runtime_metadata_contract(tmp_path):
    backend_dir = Path(__file__).resolve().parents[1] / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    import main as app_main

    case_id = f"pg-{uuid.uuid4()}"
    app_main.init_db()
    app_main.db_create(
        case_id,
        {"case_name": "Postgres Integration", "source": "test", "owner_id": "owner-pg", "tenant_id": "tenant-pg"},
        input_bytes=5,
    )
    app_main.audit_log(None, "integration.created", case_id, {"backend": "postgresql"})
    app_main.enqueue_investigation_job(case_id, "event", {"source": "test"})

    record = app_main.db_get(case_id)
    entries = app_main.list_audit_entries(investigation_id=case_id)
    claimed = app_main.claim_next_investigation_job()

    assert record["tenant_id"] == "tenant-pg"
    assert entries[0]["detail"]["backend"] == "postgresql"
    assert claimed["investigation_id"] == case_id
    assert claimed["metadata"]["source"] == "test"
