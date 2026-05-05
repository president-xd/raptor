#!/usr/bin/env python3
"""Report runtime schema migration versions from RAPTOR metadata DB."""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/raptor.db")
    args = parser.parse_args()
    path = Path(args.db)
    if not path.exists():
        print(f"Database not found: {path}", file=sys.stderr)
        return 2
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("SELECT version, applied_at FROM schema_migrations ORDER BY applied_at ASC").fetchall()
    except sqlite3.DatabaseError as exc:
        print(f"schema_migrations unavailable: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    if not rows:
        print("No schema migrations recorded")
        return 1
    for version, applied_at in rows:
        print(f"{applied_at}\t{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
