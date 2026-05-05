#!/usr/bin/env python3
"""Export RAPTOR audit_log rows as JSONL for immutable storage."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/raptor.db", help="SQLite DB path")
    parser.add_argument("--out", required=True, help="Output JSONL path")
    parser.add_argument("--investigation-id", default="", help="Optional investigation filter")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        if args.investigation_id:
            rows = conn.execute(
                """
                SELECT id, timestamp, actor, action, investigation_id, detail_json,
                       ip_address, prev_hash, entry_hash
                FROM audit_log
                WHERE investigation_id = ?
                ORDER BY id ASC
                """,
                (args.investigation_id,),
            ).fetchall()
        else:
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

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            item = dict(row)
            try:
                item["detail"] = json.loads(item.pop("detail_json") or "{}")
            except json.JSONDecodeError:
                item["detail"] = {}
            handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")

    print(f"exported={len(rows)} out={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
