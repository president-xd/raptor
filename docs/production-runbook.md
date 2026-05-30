# RAPTOR Production Runbook

## Deployment Posture

Use `docker-compose.yml` for local operation and `docker-compose.prod.yml` as the hardened overlay baseline:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Production deployments must provide:

- TLS termination at the ingress or reverse proxy.
- `RAPTOR_ENV=production`.
- Separate API and worker processes: `RAPTOR_PROCESS_ROLE=api` for the backend web service and `RAPTOR_PROCESS_ROLE=worker` for the queue worker.
- PostgreSQL metadata storage: `RAPTOR_DB_ENGINE=postgresql` and `RAPTOR_DATABASE_URL` from a secrets manager. The production compose overlay provisions a `postgres` service by default.
- `RAPTOR_API_KEY`, `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD`, and `EVIDENCE_ENCRYPTION_KEY` from a secrets manager.
- `RAPTOR_ALLOW_AUTH_DISABLED=false`.
- `RAPTOR_REQUIRE_RBAC=true`.
- `RAPTOR_RATE_LIMIT_BACKEND=redis` so API rate limits work across API processes.
- `RAPTOR_SESSION_COOKIE_SECURE=true`.
- Production `CORS_ALLOW_ORIGINS` and `CSRF_TRUSTED_ORIGINS` values matching the deployed frontend origin.
- `RAPTOR_ALLOW_EXTERNAL_LLM=false` unless telemetry export is explicitly approved.
- `RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS=true` only when this is a deliberate single-node SQLite deployment. Prefer PostgreSQL for production.
- Backups for `data/raptor.db`, `data/evidence/`, Neo4j, Weaviate, Elasticsearch, and Redis volumes.
- Prometheus scraping and alerting using `observability/prometheus-rules.yml`.
- Dependency, secret, filesystem, and container scanning. These run in the committed GitHub Actions pipeline (`.github/workflows/ci.yml`) and locally via `make security-scan`.

## Identity And Access

RAPTOR supports server-side sessions, local bootstrap admin, roles, tenants, and case ownership metadata. Use the bootstrap admin only to create or rotate operational credentials, then manage access through a trusted identity layer or a hardened user-provisioning path.

For SSO/OIDC, terminate authentication at a trusted ingress or identity-aware proxy and set `RAPTOR_TRUSTED_SSO_ENABLED=true`. Only proxies in `RAPTOR_TRUSTED_PROXY_CIDRS` may assert `RAPTOR_SSO_USER_HEADER`, `RAPTOR_SSO_ROLES_HEADER`, and `RAPTOR_SSO_TENANT_HEADER`; strip those headers from all client-originated requests at the ingress.

Roles:

- `viewer`: read investigation metadata, reports, graphs, evidence metadata, audit entries, and metrics.
- `analyst`: create investigations, query intelligence, and run simulations.
- `admin` / `service`: full tenant and system access.

## Evidence Handling

Evidence is written under `data/evidence/{investigation_id}/`. Configure `EVIDENCE_ENCRYPTION_KEY` before accepting uploaded telemetry. New evidence blobs are encrypted with AES-256-GCM and record a key identifier in SQLite metadata. Rotate evidence keys by draining ingestion, re-encrypting evidence blobs, and validating hashes from `evidence_files.sha256`.

Retention is configured by `EVIDENCE_RETENTION_DAYS`. Operational cleanup should remove expired evidence only after exporting required audit and case records.

Useful operations:

```bash
# Dry-run expired evidence deletion
python scripts/ops/cleanup_expired_evidence.py --db data/raptor.db

# Execute expired evidence deletion after approval
python scripts/ops/cleanup_expired_evidence.py --db data/raptor.db --execute

# Rotate evidence encryption keys after a verified backup
OLD_EVIDENCE_ENCRYPTION_KEY=old NEW_EVIDENCE_ENCRYPTION_KEY=new \
  python scripts/ops/rotate_evidence_key.py --db data/raptor.db --execute
```

## Worker Operations

Investigations are queued in `job_queue` in the runtime metadata database. In production the API container should not process jobs; run a separate worker container with `python worker.py`. The worker claims queued jobs, recovers stale locks older than one hour, and retries failed jobs with bounded backoff. Watch:

- `/api/v1/health/detailed`
- `/api/v1/metrics`
- `job_queue.status`
- `investigations.status`
- `parser_errors`
- `schema_migrations`

## Deployment Gate

The backend refuses to start in `RAPTOR_ENV=production` when lab defaults are still configured, when PostgreSQL is selected without `RAPTOR_DATABASE_URL`, or when SQLite production limits have not been explicitly acknowledged. This is intentional. Fix the reported environment variable instead of disabling the guard.

## Backup And Restore

Back up these assets together for a consistent case snapshot:

- PostgreSQL database dump, or `data/raptor.db` only for an explicitly acknowledged SQLite deployment.
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

Baseline local backup and restore helpers:

```bash
scripts/ops/backup.sh backups/$(date -u +%Y%m%dT%H%M%SZ)
scripts/ops/restore.sh backups/<backup-id>
```

For PostgreSQL deployments, add a `pg_dump` artifact beside the filesystem backup and restore it before starting the API and worker. Run a restore drill at least monthly in an isolated environment.

## Audit Integrity

Verify the audit hash chain from a backup copy before compliance export:

```bash
python scripts/ops/verify_audit_chain.py --db data/raptor.db
python scripts/ops/export_audit_log.py --db data/raptor.db --out exports/audit-log.jsonl
```

Store audit exports and backup checksums in immutable storage when required by policy.

## Release Gate

Before tagging a production release, run:

```bash
make validate
make security-scan
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
```

The CI pipeline (`.github/workflows/ci.yml`) additionally runs the PostgreSQL integration test against a live `postgres:16` service, Gitleaks secret scanning, and Trivy filesystem and container image scanning. The release pipeline (`.github/workflows/release.yml`) publishes images to GHCR and signs each digest with Cosign keyless.

Before and after rollout, record runtime schema status and run a lightweight smoke/load probe:

```bash
python scripts/ops/schema_status.py --db data/raptor.db
python scripts/ops/smoke_load.py --base-url https://raptor.example.com/api/v1 --api-key "$RAPTOR_API_KEY"
```

## Incident Response

If a credential or session is suspected compromised:

1. Rotate `RAPTOR_API_KEY`.
2. Revoke rows in `auth_sessions`.
3. Rotate `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD`.
4. Review `audit_log` hash chain and exported ingress logs.
5. Rotate service passwords for Neo4j, Weaviate, Elasticsearch, and Redis.
6. Re-encrypt evidence if `EVIDENCE_ENCRYPTION_KEY` is exposed.
