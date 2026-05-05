#!/usr/bin/env python3
"""Re-encrypt local evidence blobs from an old key to a new key.

Usage:
  OLD_EVIDENCE_ENCRYPTION_KEY=... NEW_EVIDENCE_ENCRYPTION_KEY=... \
    python scripts/ops/rotate_evidence_key.py --db data/raptor.db --execute

The script updates encrypted evidence files in place and records an audit entry.
Keep a verified backup before running with --execute.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def key_bytes(value: str) -> bytes:
    value = value.strip()
    if value.startswith("base64:"):
        raw = base64.b64decode(value.split(":", 1)[1])
        if len(raw) != 32:
            raise ValueError("base64 key must decode to 32 bytes")
        return raw
    try:
        raw = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    return hashlib.sha256(value.encode("utf-8")).digest()


def decrypt(blob: bytes, key: bytes) -> bytes:
    if not blob.startswith(b"RAPTOR-EVIDENCE-v2:"):
        return blob
    header, ciphertext = blob.split(b"\n", 1)
    _prefix, _alg, _key_id, nonce_hex = header.decode("ascii").split(":", 3)
    return AESGCM(key).decrypt(bytes.fromhex(nonce_hex), ciphertext, None)


def encrypt(content: bytes, key: bytes) -> tuple[bytes, str]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, content, None)
    key_id = hashlib.sha256(key).hexdigest()[:16]
    header = f"RAPTOR-EVIDENCE-v2:aes-256-gcm:{key_id}:{nonce.hex()}\n".encode("ascii")
    return header + ciphertext, f"aes-256-gcm:{key_id}"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(conn: sqlite3.Connection, detail: dict) -> None:
    timestamp = utcnow()
    detail_json = json.dumps(detail, sort_keys=True, default=str)
    prev = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev[0] if prev and prev[0] else ""
    material = "|".join([timestamp, "ops-key-rotation", "evidence.key_rotated", "", detail_json, "", prev_hash])
    entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    conn.execute(
        """
        INSERT INTO audit_log
        (timestamp, actor, action, investigation_id, detail_json, ip_address, prev_hash, entry_hash)
        VALUES (?, 'ops-key-rotation', 'evidence.key_rotated', NULL, ?, '', ?, ?)
        """,
        (timestamp, detail_json, prev_hash, entry_hash),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/raptor.db")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    old_key = key_bytes(os.environ["OLD_EVIDENCE_ENCRYPTION_KEY"])
    new_key = key_bytes(os.environ["NEW_EVIDENCE_ENCRYPTION_KEY"])
    if old_key == new_key:
        raise SystemExit("old and new keys resolve to the same key")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, stored_path, sha256 FROM evidence_files WHERE encrypted = 1 ORDER BY id ASC"
    ).fetchall()

    rotated = 0
    try:
        for row in rows:
            path = Path(row["stored_path"])
            if not path.exists():
                print(f"missing id={row['id']} path={path}")
                continue
            plaintext = decrypt(path.read_bytes(), old_key)
            if hashlib.sha256(plaintext).hexdigest() != row["sha256"]:
                raise RuntimeError(f"sha256 mismatch before rotation for evidence id={row['id']}")
            new_blob, key_id = encrypt(plaintext, new_key)
            print(f"rotate id={row['id']} path={path} new_key={key_id}")
            if args.execute:
                path.write_bytes(new_blob)
                conn.execute(
                    "UPDATE evidence_files SET encryption_key_id = ? WHERE id = ?",
                    (key_id, row["id"]),
                )
            rotated += 1
        if args.execute:
            append_audit(conn, {"rotated_count": rotated})
            conn.commit()
    finally:
        conn.close()

    print(f"mode={'execute' if args.execute else 'dry-run'} rotated={rotated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
