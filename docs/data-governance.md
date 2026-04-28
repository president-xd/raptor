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

## Audit

Audit entries are append-only at the database level and include a hash chain. Export audit records to immutable storage for compliance programs that require independent tamper evidence.

