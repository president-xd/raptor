"""
RAPTOR | Evidence Encryption
AES-256-GCM envelope encryption for stored evidence files (DEK/KEK pattern).

Key hierarchy:
  KEK  — static Key Encryption Key loaded from EVIDENCE_ENCRYPTION_KEY env var
  DEK  — random per-file Data Encryption Key

On write: random DEK encrypts the file; DEK is wrapped by the KEK and stored
in the file header.  Key rotation only needs to re-wrap DEKs, not re-encrypt
file content.

File format v3:
  RAPTOR-EVIDENCE-v3:aes-256-gcm:{kek_id}:{file_nonce_hex}:{b64_wrapped_dek}\n
  <ciphertext>

Legacy v2 (direct-KEK) blobs are decryptable but never written by this module.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

from config import EVIDENCE_ENCRYPTION_KEY


def _kek() -> Optional[bytes]:
    """Load and normalise the Key Encryption Key from config.

    Accepted formats:
      base64:<b64>        — explicit base64, must decode to 32 bytes
      <urlsafe-b64>       — 44-char urlsafe-base64 that decodes to 32 bytes
      <arbitrary string>  — SHA-256 digest of the string (always 32 bytes)
    """
    if not EVIDENCE_ENCRYPTION_KEY:
        return None
    key_value = EVIDENCE_ENCRYPTION_KEY.strip()

    if key_value.startswith("base64:"):
        raw = base64.b64decode(key_value.split(":", 1)[1])
        if len(raw) != 32:
            raise RuntimeError(
                "base64 EVIDENCE_ENCRYPTION_KEY must decode to exactly 32 bytes"
            )
        return raw

    try:
        padded = key_value + ("=" * (-len(key_value) % 4))
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        if len(raw) == 32:
            return raw
    except Exception:
        pass

    # Fallback: derive 32-byte key from arbitrary string via SHA-256
    return hashlib.sha256(key_value.encode("utf-8")).digest()


def encrypt_evidence(content: bytes) -> tuple[bytes, bool, str]:
    """Encrypt *content* with AES-256-GCM and return (stored_bytes, encrypted, key_id).

    If no KEK is configured, the original bytes are returned unchanged with
    encrypted=False and key_id=''.
    """
    kek = _kek()
    if not kek:
        return content, False, ""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Generate a fresh per-file DEK
    dek = secrets.token_bytes(32)
    file_nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(file_nonce, content, None)

    # Wrap the DEK with the KEK
    kek_id = hashlib.sha256(kek).hexdigest()[:16]
    wrap_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, None)
    b64_wrapped = base64.b64encode(wrap_nonce + wrapped_dek).decode("ascii")

    header = (
        f"RAPTOR-EVIDENCE-v3:aes-256-gcm:{kek_id}:{file_nonce.hex()}:{b64_wrapped}\n"
    ).encode("ascii")
    return header + ciphertext, True, f"aes-256-gcm-envelope:{kek_id}"


def decrypt_evidence(stored_content: bytes) -> bytes:
    """Decrypt evidence blobs written by :func:`encrypt_evidence`.

    Supports:
      - v3  — envelope DEK/KEK (current)
      - v2  — legacy direct-KEK (read-only support)
      - raw — unencrypted (returned as-is)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if stored_content.startswith(b"RAPTOR-EVIDENCE-v3:"):
        kek = _kek()
        if not kek:
            raise RuntimeError(
                "EVIDENCE_ENCRYPTION_KEY is required to decrypt v3 evidence blobs"
            )
        header_line, ciphertext = stored_content.split(b"\n", 1)
        _magic, _alg, _kek_id, file_nonce_hex, b64_wrapped = (
            header_line.decode("ascii").split(":", 4)
        )
        wrapped_raw = base64.b64decode(b64_wrapped)
        wrap_nonce, wrapped_dek_ct = wrapped_raw[:12], wrapped_raw[12:]
        dek = AESGCM(kek).decrypt(wrap_nonce, wrapped_dek_ct, None)
        return AESGCM(dek).decrypt(bytes.fromhex(file_nonce_hex), ciphertext, None)

    if stored_content.startswith(b"RAPTOR-EVIDENCE-v2:"):
        kek = _kek()
        if not kek:
            raise RuntimeError(
                "EVIDENCE_ENCRYPTION_KEY is required to decrypt v2 evidence blobs"
            )
        header, ciphertext = stored_content.split(b"\n", 1)
        _prefix, _alg, _key_id, nonce_hex = header.decode("ascii").split(":", 3)
        return AESGCM(kek).decrypt(bytes.fromhex(nonce_hex), ciphertext, None)

    return stored_content
