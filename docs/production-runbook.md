# RAPTOR Production Runbook

## Deployment Posture

Use `docker-compose.yml` for local operation and `docker-compose.prod.yml` as the hardened overlay baseline:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Production deployments must provide:

- TLS termination at the ingress or reverse proxy.
- `RAPTOR_API_KEY`, `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD`, and `EVIDENCE_ENCRYPTION_KEY` from a secrets manager.
- `RAPTOR_ALLOW_AUTH_DISABLED=false`.
- `RAPTOR_REQUIRE_RBAC=true`.
- `RAPTOR_ALLOW_EXTERNAL_LLM=false` unless telemetry export is explicitly approved.
- Backups for `data/raptor.db`, `data/evidence/`, Neo4j, Weaviate, Elasticsearch, and Redis volumes.

## Identity And Access

RAPTOR supports server-side sessions, local bootstrap admin, roles, tenants, and case ownership metadata. Use the bootstrap admin only to create or rotate operational credentials, then manage access through a trusted identity layer or a hardened user-provisioning path.

Roles:

- `viewer`: read investigation metadata, reports, graphs, evidence metadata, audit entries, and metrics.
- `analyst`: create investigations, query intelligence, and run simulations.
- `admin` / `service`: full tenant and system access.

## Evidence Handling

Evidence is written under `data/evidence/{investigation_id}/`. Configure `EVIDENCE_ENCRYPTION_KEY` before accepting uploaded telemetry. Rotate evidence keys by draining ingestion, re-encrypting evidence blobs, and validating hashes from `evidence_files.sha256`.

Retention is configured by `EVIDENCE_RETENTION_DAYS`. Operational cleanup should remove expired evidence only after exporting required audit and case records.

## Worker Operations

Investigations are queued in `job_queue`. A backend worker claims queued jobs, recovers stale locks older than one hour, and retries failed jobs with bounded backoff. Watch:

- `/api/v1/health/detailed`
- `/api/v1/metrics`
- `job_queue.status`
- `investigations.status`
- `parser_errors`

## Backup And Restore

Back up these assets together for a consistent case snapshot:

- `data/raptor.db`
- `data/evidence/`
- `data/intel/`
- Neo4j volume
- Weaviate volume
- Elasticsearch volume
- Redis volume if connector cache continuity matters

Restore order:

1. Stop backend and frontend.
2. Restore database and evidence paths.
3. Restore infrastructure volumes.
4. Start infrastructure and verify health.
5. Start backend and confirm `/api/v1/health/detailed`.
6. Reconcile queued/running jobs in `job_queue`.

## Incident Response

If a credential or session is suspected compromised:

1. Rotate `RAPTOR_API_KEY`.
2. Revoke rows in `auth_sessions`.
3. Rotate `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD`.
4. Review `audit_log` hash chain and exported ingress logs.
5. Rotate service passwords for Neo4j, Weaviate, Elasticsearch, and Redis.
6. Re-encrypt evidence if `EVIDENCE_ENCRYPTION_KEY` is exposed.

