#!/usr/bin/env python3
"""Re-encrypt local evidence blobs from an old key to a new key.

Supports both the legacy v2 (direct-KEK) and current v3 (DEK/KEK envelope)
formats.  All blobs are re-encrypted as v3 on output.

Usage:
  OLD_EVIDENCE_ENCRYPTION_KEY=... NEW_EVIDENCE_ENCRYPTION_KEY=... \
    python scripts/ops/rotate_evidence_key.py --db data/raptor.db --execute

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


# ── Key helpers ───────────────────────────────────────────────────────────────

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


# ── Format-aware decrypt ──────────────────────────────────────────────────────

def _decrypt_v2(blob: bytes, kek: bytes) -> bytes:
    """v2: RAPTOR-EVIDENCE-v2:aes-256-gcm:{key_id}:{nonce_hex}\n<ct>"""
    header, ciphertext = blob.split(b"\n", 1)
    _prefix, _alg, _key_id, nonce_hex = header.decode("ascii").split(":", 3)
    return AESGCM(kek).decrypt(bytes.fromhex(nonce_hex), ciphertext, None)


def _decrypt_v3(blob: bytes, kek: bytes) -> bytes:
    """v3: RAPTOR-EVIDENCE-v3:aes-256-gcm:{kek_id}:{file_nonce_hex}:{b64_wrapped_dek}\n<ct>"""
    header, ciphertext = blob.split(b"\n", 1)
    _magic, _alg, _kek_id, file_nonce_hex, b64_wrapped = header.decode("ascii").split(":", 4)
    wrapped_raw = base64.b64decode(b64_wrapped)
    wrap_nonce, wrapped_dek_ct = wrapped_raw[:12], wrapped_raw[12:]
    dek = AESGCM(kek).decrypt(wrap_nonce, wrapped_dek_ct, None)
    return AESGCM(dek).decrypt(bytes.fromhex(file_nonce_hex), ciphertext, None)


def decrypt_blob(blob: bytes, kek: bytes) -> bytes:
    if blob.startswith(b"RAPTOR-EVIDENCE-v3:"):
        return _decrypt_v3(blob, kek)
    if blob.startswith(b"RAPTOR-EVIDENCE-v2:"):
        return _decrypt_v2(blob, kek)
    return blob  # unencrypted — pass through unchanged


# ── v3 encrypt (always write current format) ─────────────────────────────────

def encrypt_v3(content: bytes, kek: bytes) -> tuple[bytes, str]:
    """Encrypt as v3 envelope: random DEK encrypts content; DEK wrapped by KEK."""
    dek = secrets.token_bytes(32)
    file_nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(file_nonce, content, None)

    kek_id = hashlib.sha256(kek).hexdigest()[:16]
    wrap_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, None)
    b64_wrapped = base64.b64encode(wrap_nonce + wrapped_dek).decode("ascii")

    header = (
        f"RAPTOR-EVIDENCE-v3:aes-256-gcm:{kek_id}:{file_nonce.hex()}:{b64_wrapped}\n"
    ).encode("ascii")
    return header + ciphertext, f"aes-256-gcm-envelope:{kek_id}"


# ── Audit helpers ─────────────────────────────────────────────────────────────

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit(conn: sqlite3.Connection, detail: dict) -> None:
    timestamp = utcnow()
    detail_json = json.dumps(detail, sort_keys=True, default=str)
    prev = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = prev[0] if prev and prev[0] else ""
    material = "|".join(
        [timestamp, "ops-key-rotation", "evidence.key_rotated", "", detail_json, "", prev_hash]
    )
    entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    conn.execute(
        """
        INSERT INTO audit_log
        (timestamp, actor, action, investigation_id, detail_json, ip_address, prev_hash, entry_hash)
        VALUES (?, 'ops-key-rotation', 'evidence.key_rotated', NULL, ?, '', ?, ?)
        """,
        (timestamp, detail_json, prev_hash, entry_hash),
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="data/raptor.db")
    parser.add_argument("--execute", action="store_true",
                        help="Actually write changes (default: dry-run)")
    args = parser.parse_args()

    old_kek = key_bytes(os.environ["OLD_EVIDENCE_ENCRYPTION_KEY"])
    new_kek = key_bytes(os.environ["NEW_EVIDENCE_ENCRYPTION_KEY"])
    if old_kek == new_kek:
        raise SystemExit("ERROR: old and new keys resolve to the same key — aborting")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, stored_path, sha256 FROM evidence_files WHERE encrypted = 1 ORDER BY id ASC"
    ).fetchall()

    rotated = skipped = errors = 0
    try:
        for row in rows:
            path = Path(row["stored_path"])
            if not path.exists():
                print(f"MISSING  id={row['id']} path={path}")
                errors += 1
                continue

            blob = path.read_bytes()

            # Skip unrecognised blobs (already unencrypted or unknown format)
            if not (blob.startswith(b"RAPTOR-EVIDENCE-v2:") or blob.startswith(b"RAPTOR-EVIDENCE-v3:")):
                print(f"SKIP     id={row['id']} unrecognised format (not v2/v3)")
                skipped += 1
                continue

            try:
                plaintext = decrypt_blob(blob, old_kek)
            except Exception as exc:
                print(f"ERROR    id={row['id']} decrypt failed: {exc}")
                errors += 1
                continue

            actual_sha = hashlib.sha256(plaintext).hexdigest()
            if actual_sha != row["sha256"]:
                print(
                    f"ERROR    id={row['id']} sha256 mismatch "
                    f"(got {actual_sha[:16]}… expected {row['sha256'][:16]}…)"
                )
                errors += 1
                continue

            new_blob, key_id = encrypt_v3(plaintext, new_kek)
            print(f"ROTATE   id={row['id']} path={path} new_key={key_id}")

            if args.execute:
                path.write_bytes(new_blob)
                conn.execute(
                    "UPDATE evidence_files SET encryption_key_id = ? WHERE id = ?",
                    (key_id, row["id"]),
                )

            rotated += 1

        if args.execute and rotated:
            append_audit(conn, {
                "rotated_count": rotated,
                "skipped_count": skipped,
                "error_count": errors,
            })
            conn.commit()
    finally:
        conn.close()

    mode = "execute" if args.execute else "dry-run"
    print(f"\nmode={mode}  rotated={rotated}  skipped={skipped}  errors={errors}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
