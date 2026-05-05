#!/usr/bin/env python3
"""Delete evidence files whose retention_expiry has passed.

This script is intentionally conservative: it defaults to dry-run and only acts
on rows with a non-empty retention_expires_at timestamp older than now.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(conn: sqlite3.Connection, action: str, investigation_id: str, detail: dict) -> None:
    timestamp = utcnow()
    actor = "ops-retention-cleanup"
    detail_json = json.dumps(detail, sort_keys=True, default=str)
    prev = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev[0] if prev and prev[0] else ""
    material = "|".join([timestamp, actor, action, investigation_id or "", detail_json, "", prev_hash])
    entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    conn.execute(
        """
        INSERT INTO audit_log
        (timestamp, actor, action, investigation_id, detail_json, ip_address, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, '', ?, ?)
        """,
        (timestamp, actor, action, investigation_id, detail_json, prev_hash, entry_hash),
    )


def parse_ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/raptor.db", help="SQLite DB path")
    parser.add_argument("--execute", action="store_true", help="Actually delete files and evidence rows")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    now = time.time()
    deleted = 0
    candidates = conn.execute(
        """
        SELECT id, investigation_id, stored_path, sha256, retention_expires_at
        FROM evidence_files
        WHERE retention_expires_at IS NOT NULL AND retention_expires_at != ''
        ORDER BY id ASC
        """
    ).fetchall()

    try:
        for row in candidates:
            try:
                if parse_ts(row["retention_expires_at"]) > now:
                    continue
            except Exception:
                continue

            path = Path(row["stored_path"])
            print(f"expired id={row['id']} investigation={row['investigation_id']} path={path}")
            if not args.execute:
                continue

            if path.exists():
                path.unlink()
            conn.execute("DELETE FROM evidence_files WHERE id = ?", (row["id"],))
            append_audit(
                conn,
                "evidence.retention_deleted",
                row["investigation_id"],
                {"evidence_id": row["id"], "sha256": row["sha256"], "retention_expires_at": row["retention_expires_at"]},
            )
            deleted += 1
        conn.commit()
    finally:
        conn.close()

    print(f"mode={'execute' if args.execute else 'dry-run'} deleted={deleted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
