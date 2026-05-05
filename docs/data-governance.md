# RAPTOR Data Governance

## Data Classes

- **Restricted:** uploaded telemetry, raw evidence, usernames, hostnames, IP addresses, file paths, command lines, credentials accidentally present in logs.
- **Confidential:** investigation findings, attribution scores, reports, audit logs, graph exports.
- **Public:** static ATT&CK/STIX content and public CISA KEV feed data.

## LLM Policy

External LLM calls are disabled unless `RAPTOR_ALLOW_EXTERNAL_LLM=true`. Before enabling external model calls:

- Confirm telemetry export is permitted by customer policy.
- Set an approved provider endpoint.
- Validate data residency and retention terms.
- Review redaction behavior for IPs, emails, bearer tokens, API keys, passwords, and common secret fields.
- Treat all LLM outputs as analyst-supporting evidence, not authoritative truth.

## Retention

Use `EVIDENCE_RETENTION_DAYS` for evidence retention metadata. Deletion jobs should:

1. Verify case closure and legal hold status.
2. Export audit records if required.
3. Delete evidence blobs.
4. Preserve deletion audit entries.

Use `scripts/ops/cleanup_expired_evidence.py` in dry-run mode first, then run with `--execute` only after case-owner approval. The script writes `evidence.retention_deleted` audit entries for deleted evidence rows.

## Evidence Encryption

Uploaded evidence is encrypted locally when `EVIDENCE_ENCRYPTION_KEY` is configured. Production mode refuses to start without this key. Prefer a 32-byte base64 value prefixed with `base64:` and source it from a secrets manager. Regulated deployments should move evidence to object storage and use KMS-backed envelope encryption.

Key rotation must be treated as a controlled maintenance event:

1. Stop ingestion and workers.
2. Run `scripts/ops/backup.sh` and verify checksums.
3. Dry-run `scripts/ops/rotate_evidence_key.py`.
4. Run key rotation with `--execute`.
5. Run `scripts/ops/verify_audit_chain.py` and sample evidence decrypt checks.
6. Restart workers and document the new key identifier.

## Audit

Audit entries are append-only at the database level and include a hash chain. Export audit records to immutable storage for compliance programs that require independent tamper evidence.

Use `scripts/ops/verify_audit_chain.py` before export and `scripts/ops/export_audit_log.py` for JSONL export. Store JSONL output, backup checksums, and deployment release metadata together.

## Data Release Boundaries

- Do not enable external LLM calls for Restricted data unless the provider contract permits telemetry processing.
- Do not expose raw evidence downloads without an explicit entitlement review.
- Treat audit logs as Confidential because they may contain query snippets, case names, and operational metadata.
- Do not ship local SQLite databases, `.env`, evidence directories, `.venv`, or build artifacts in release archives.
