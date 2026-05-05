#!/usr/bin/env python3
"""Verify RAPTOR audit_log hash-chain integrity.

Works against the SQLite runtime database. For PostgreSQL deployments, export the
same columns to CSV/JSONL first or run this in a maintenance shell with a local
SQLite backup. The hash material intentionally matches backend.main.audit_log.
"""
from __future__ import annotations

import argparse
import hashlib
import sqlite3
import sys
from pathlib import Path


def expected_hash(row: sqlite3.Row, previous_hash: str) -> str:
    material = "|".join(
        [
            row["timestamp"] or "",
            row["actor"] or "",
            row["action"] or "",
            row["investigation_id"] or "",
            row["detail_json"] or "{}",
            row["ip_address"] or "",
            previous_hash or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, timestamp, actor, action, investigation_id, detail_json,
                   ip_address, prev_hash, entry_hash
            FROM audit_log
            ORDER BY id ASC
            """
        ).fetchall()
    finally:
        conn.close()

    previous = ""
    errors: list[str] = []
    for row in rows:
        if (row["prev_hash"] or "") != previous:
            errors.append(f"id={row['id']}: prev_hash mismatch")
        digest = expected_hash(row, previous)
        if (row["entry_hash"] or "") != digest:
            errors.append(f"id={row['id']}: entry_hash mismatch")
        previous = row["entry_hash"] or ""

    if errors:
        print("AUDIT_CHAIN_INVALID")
        for item in errors[:50]:
            print(item)
        if len(errors) > 50:
            print(f"... {len(errors) - 50} more errors")
        return 1

    print(f"AUDIT_CHAIN_OK entries={len(rows)} head={previous or 'empty'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/raptor.db", help="SQLite DB path")
    args = parser.parse_args()
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2
    return verify(db_path)


if __name__ == "__main__":
    raise SystemExit(main())
