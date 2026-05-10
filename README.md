# RAPTOR

**Retrieval-Augmented Persistent Threat Orchestration and Reasoning**

A production-grade cybersecurity investigation platform for SOC analysts. Upload raw telemetry logs, correlate them against MITRE ATT&CK, score APT attribution, predict adversary next steps, and produce analyst-ready reports — all in one workflow.

---

## Table of Contents

- [Architecture](#architecture)
- [Security Model](#security-model)
- [Quick Start (Local)](#quick-start-local)
- [Production Deployment](#production-deployment)
- [Configuration Reference](#configuration-reference)
- [API Reference](#api-reference)
- [Roles and Access Control](#roles-and-access-control)
- [Evidence Handling](#evidence-handling)
- [Audit Trail](#audit-trail)
- [Observability](#observability)
- [Operational Runbook](#operational-runbook)
- [Development](#development)
- [Security Hardening Checklist](#security-hardening-checklist)
- [CI / CD](#ci--cd)

---

## Architecture

```
+---------------------------------------------------------+
|  Browser (SOC Analyst Console)                          |
|  React · Vite · Nginx (rate-limited reverse proxy)      |
+--------------------+------------------------------------+
                     | HTTPS / TLS-terminating ingress
+--------------------v------------------------------------+
|  RAPTOR API  (FastAPI · Uvicorn · Python 3.11)          |
|  +----------+ +----------+ +----------+ +----------+   |
|  |  Auth    | | Evidence | |  Jobs    | | Metrics  |   |
|  |  RBAC    | | Encrypt  | |  Queue   | | Audit    |   |
|  +----------+ +----------+ +----------+ +----------+   |
+------+---------------+---------------+-----------------+
       |               |               |
+------v------+  +-----v------+  +-----v------------------+
|  Neo4j 5.15 |  | Weaviate   |  |  RAPTOR Worker          |
|  Attack     |  | 1.27.6     |  |  (separate process)     |
|  Graph      |  | RAG / Vec  |  |  Investigation pipeline |
+-------------+  +------------+  +----------------------+--+
                                                         |
+--------------------------------------------------------v--+
|  PostgreSQL 16  |  Elasticsearch 8.11  |  Redis 7.2       |
|  (metadata, auth|  (log search)        |  (rate-limit,    |
|   audit, jobs)  |                      |   cache)         |
+----------------------------------------------------------+
```

### Backend Module Structure

The backend is a fully modular FastAPI application. Import chain is strictly one-directional (no circular deps):

```
config
  └─ database         (all DB/Redis I/O, SQLite↔PostgreSQL adapter)
       └─ metrics_store  (Prometheus or in-memory counters)
            └─ auth_core    (sessions, RBAC, rate limiting, SSO, CSRF)
                 └─ evidence_crypto  (AES-256-GCM envelope encryption)
                      └─ pipeline_runner  (investigation worker loop)
                           └─ routers/     (FastAPI endpoint modules)
                                └─ main.py  (app factory + middleware)
```

| Module | Responsibility |
|---|---|
| `config.py` | Load and validate all environment variables; fail loudly on bad deploys |
| `database.py` | Every DB read/write; SQLite↔PostgreSQL transparent adapter; Redis helpers |
| `metrics_store.py` | Prometheus counters with in-process fallback; `get_metrics_text()` |
| `auth_core.py` | Sessions, PBKDF2 passwords, RBAC, Redis/memory rate limiting, SSO proxy trust |
| `evidence_crypto.py` | DEK/KEK envelope encryption; v2 legacy decrypt; key derivation |
| `llm_redactor.py` | Strip PII/secrets from prompts before external LLM calls |
| `pipeline_runner.py` | 6-phase investigation pipeline; Elasticsearch poller; worker process |
| `storage.py` | Pluggable evidence backend: local filesystem or S3-compatible |
| `routers/auth.py` | `POST /auth/session`, `GET /auth/me`, `POST /auth/logout` |
| `routers/investigations.py` | Upload, text ingest, list, status, report, graph, evidence |
| `routers/analysis.py` | Simulate, NLQ query, MITRE matrix, APT profiles |
| `routers/intelligence.py` | CISA KEV feed, Elasticsearch ingest + poller config |
| `routers/admin.py` | Users CRUD, audit log, Prometheus metrics, schema status |
| `routers/health.py` | Fast liveness + detailed subsystem health check |
| `worker.py` | Standalone worker entry point (`RAPTOR_PROCESS_ROLE=worker`) |
| `main.py` | FastAPI app factory, middleware stack, lifespan hooks |

### Pipelines

| Pipeline | Description |
|---|---|
| **Ingestion** | Parse raw logs (JSON, CEF, XML, plaintext), normalise to `RaptorEvent`, match Sigma-style rules |
| **RAG Analysis** | Hybrid semantic/BM25 retrieval against MITRE ATT&CK + APT reports; deterministic fallback when LLM disabled |
| **Graph Build** | Persist attack graph into Neo4j; in-memory fallback when Neo4j unavailable |
| **Attribution** | Jaccard-based TTP scoring across APT profiles; confidence gating (HIGH / MEDIUM / LOW / UNKNOWN) |
| **Simulation** | Predict next adversary steps using ATT&CK playbook context; blocked at LOW/UNKNOWN confidence |
| **Report** | Generate analyst-ready markdown report with timeline, MITRE overlay, and recommendations |

---

## Security Model

### Authentication

| Method | Header / Cookie | Use case |
|---|---|---|
| API Key | `X-RAPTOR-API-Key` or `Authorization: Bearer` | Service-to-service, CI, scripts |
| Session Cookie | `raptor_session` (HttpOnly, SameSite=Lax) | Browser sessions |
| SSO / OIDC proxy | `X-Forwarded-User` (configurable) | Enterprise IdP via trusted proxy |

Session lifetime is configurable via `RAPTOR_SESSION_TTL_SECONDS` (default 8 hours). Sessions are server-side — they can be explicitly revoked via `POST /api/v1/auth/logout`.

Password storage uses PBKDF2-SHA256 at 210 000 iterations with a per-user salt. Account lockout activates after `RAPTOR_AUTH_MAX_FAILURES` failed attempts.

### Rate Limiting

| Endpoint bucket | Limit | Window |
|---|---|---|
| `auth` | 10 req | 60 s |
| `upload` | 20 req | 300 s |
| `query` | 60 req | 300 s |
| `connector` | 30 req | 300 s |

In production, `RAPTOR_RATE_LIMIT_BACKEND=redis` coordinates limits across multiple API workers. Nginx adds a second layer with per-IP rate zones for auth (2 r/s), upload (1 r/s), and general API (20 r/s).

### Evidence Encryption

Evidence files are encrypted at rest with **AES-256-GCM envelope encryption**:

1. A random per-file **Data Encryption Key (DEK)** is generated for each upload
2. File content is encrypted with the DEK
3. The DEK is wrapped (encrypted) by the static **Key Encryption Key (KEK)** loaded from `EVIDENCE_ENCRYPTION_KEY`
4. The wrapped DEK is embedded in the file header — key rotation only needs to re-wrap DEKs, not re-encrypt file content

Legacy v2 format (direct KEK) is still fully decryptable for backward compatibility.

When `RAPTOR_STORAGE_BACKEND=s3`, the ciphertext is additionally protected by S3 server-side encryption (`AES256`), providing encryption at two independent layers.

### LLM Privacy

All prompts are scrubbed by `llm_redactor.py` before transmission to any external provider:

| Pattern | Replacement |
|---|---|
| Bearer / Authorization tokens | `Bearer [REDACTED_TOKEN]` |
| Credential key-value pairs (`password=`, `secret=`, `api_key=`, …) | `key=[REDACTED]` |
| US Social Security Numbers | `[SSN_REDACTED]` |
| Credit / debit card numbers (Luhn-plausible 13–19 digits) | `[CC_REDACTED]` |
| Email addresses | `[EMAIL_REDACTED]` |
| US phone numbers | `[PHONE_REDACTED]` |
| Private IPv4 ranges (RFC-1918, loopback, APIPA) | `[PRIVATE_IP]` |
| Sensitive Unix paths (`/etc/shadow`, `.aws/credentials`, `.ssh/id_rsa`, …) | `[SENSITIVE_PATH]` |
| Windows drive paths (`C:\…`) | `[WINDOWS_PATH]` |
| UNC network paths (`\\server\share`) | `[UNC_PATH]` |

External LLM is disabled by default (`RAPTOR_ALLOW_EXTERNAL_LLM=false`).

### CSRF Protection

Browser-session mutations (POST, PUT, PATCH, DELETE) require a trusted `Origin` or `Referer` header. API-key requests bypass this check (stateless). The `/api/v1/auth/session` login endpoint is explicitly exempt.

### Audit Trail

Every security-relevant action appends to an append-only `audit_log` table:

- Database-level trigger blocks `UPDATE` and `DELETE` on the table
- Each entry includes a SHA-256 hash of all prior content (hash chain) — tamper-evident
- Verified with `scripts/ops/verify_audit_chain.py`
- Automated daily export via `scripts/ops/export_audit_cron.sh` with optional S3 shipping

---

## Quick Start (Local)

### Prerequisites

- Docker Desktop >= 4.28 with Compose V2
- 8 GB RAM available for containers

```bash
# 1. Clone
git clone https://github.com/your-org/raptor.git
cd raptor

# 2. Copy and edit configuration
cp .env.example .env
# Replace all change_me_* values before production use

# 3. Start all services
docker compose up -d --build

# 4. Wait for health checks (~60 s)
docker compose ps

# 5. Open the SOC console
open http://localhost:3100
```

Default bootstrap admin credentials are set by `RAPTOR_BOOTSTRAP_ADMIN_USERNAME` / `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` in `.env`.

After creating permanent admin accounts, set `RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true` to disable the bootstrap account.

---

## Production Deployment

### 1. Generate Secrets

```bash
# API key (32+ bytes)
openssl rand -hex 32

# Bootstrap admin password
openssl rand -base64 24

# Evidence KEK — must decode to exactly 32 bytes
python3 -c "import secrets, base64; print('base64:' + base64.b64encode(secrets.token_bytes(32)).decode())"

# Neo4j, PostgreSQL, Elasticsearch, Weaviate passwords
openssl rand -hex 24
```

Store all secrets in a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager). Never commit them to the repository.

### 2. Required Environment Variables

| Variable | Required | Description |
|---|---|---|
| `RAPTOR_ENV` | Yes | Must be `production` |
| `RAPTOR_API_KEY` | Yes | Service API key (>=32 chars) |
| `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` | Yes | Initial admin password |
| `RAPTOR_BOOTSTRAP_ADMIN_DISABLED` | Recommended | Set `true` after first real admin created |
| `RAPTOR_DB_ENGINE` | Yes | Must be `postgresql` |
| `RAPTOR_DATABASE_URL` | Yes | `postgresql://user:pass@host:5432/raptor` |
| `RAPTOR_RATE_LIMIT_BACKEND` | Yes | Must be `redis` |
| `RAPTOR_SESSION_COOKIE_SECURE` | Yes | Must be `true` (behind TLS) |
| `RAPTOR_ALLOW_AUTH_DISABLED` | Yes | Must be `false` |
| `EVIDENCE_ENCRYPTION_KEY` | Yes | 32-byte base64 KEK |
| `NEO4J_PASSWORD` | Yes | Non-placeholder Neo4j password |
| `CORS_ALLOW_ORIGINS` | Yes | Your frontend origin (not localhost) |
| `CSRF_TRUSTED_ORIGINS` | Yes | Same as CORS origins |
| `RAPTOR_SESSION_TTL_SECONDS` | No | Default 28800 (8 h) |

### 3. Deploy

```bash
# Production overlay removes all internal port bindings and enforces required env vars
docker compose \
  -f docker-compose.yml \
  -f docker-compose.prod.yml \
  up -d --build

# Verify
curl -sf http://localhost:8000/api/v1/health/detailed | python3 -m json.tool
```

### 4. TLS

RAPTOR does not terminate TLS. Deploy behind a TLS-terminating ingress:

- **Nginx / Caddy** — single-host deployments
- **AWS ALB / GCP HTTPS LB** — cloud deployments
- **Kubernetes Ingress + cert-manager** — K8s deployments

`Strict-Transport-Security` (HSTS) is set automatically in the Nginx config and when `RAPTOR_PRODUCTION=true`.

### 5. SSO / OIDC Integration

RAPTOR supports trusted proxy header SSO (Authelia, OAuth2-Proxy, Nginx auth_request):

```bash
RAPTOR_TRUSTED_SSO_ENABLED=true
RAPTOR_TRUSTED_PROXY_CIDRS=10.0.0.5/32
RAPTOR_SSO_USER_HEADER=x-forwarded-user
RAPTOR_SSO_ROLES_HEADER=x-forwarded-roles   # comma-separated: analyst,viewer
RAPTOR_SSO_TENANT_HEADER=x-forwarded-tenant
```

Headers from non-trusted CIDRs are silently ignored at ingress.

### 6. S3 Evidence Storage

```bash
RAPTOR_STORAGE_BACKEND=s3
S3_BUCKET=my-raptor-evidence
S3_PREFIX=evidence/
S3_REGION=us-east-1
# Optional: MinIO, GCS
# S3_ENDPOINT_URL=https://minio.internal:9000
```

---

## Configuration Reference

### Core

| Variable | Default | Description |
|---|---|---|
| `RAPTOR_ENV` | `development` | `development` or `production` |
| `RAPTOR_PROCESS_ROLE` | `all` | `api`, `worker`, or `all` (dev only) |
| `API_HOST` | `0.0.0.0` | Bind address |
| `API_PORT` | `8000` | Listen port |
| `MAX_UPLOAD_BYTES` | `10485760` | Max upload size (10 MiB) |

### Auth

| Variable | Default | Description |
|---|---|---|
| `RAPTOR_API_KEY` | — | Service API key |
| `RAPTOR_ALLOW_AUTH_DISABLED` | `false` | Local dev only |
| `RAPTOR_SESSION_COOKIE_SECURE` | `false` | Set `true` behind TLS |
| `RAPTOR_SESSION_TTL_SECONDS` | `28800` | Session lifetime (seconds) |
| `RAPTOR_REQUIRE_RBAC` | `true` | Enforce role checks |
| `RAPTOR_AUTH_MAX_FAILURES` | `5` | Lockout threshold |
| `RAPTOR_AUTH_LOCK_SECONDS` | `900` | Lockout duration |
| `RAPTOR_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Bootstrap admin name |
| `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` | — | Bootstrap admin password |
| `RAPTOR_BOOTSTRAP_ADMIN_DISABLED` | `false` | Disable bootstrap account on startup |
| `RAPTOR_RATE_LIMIT_BACKEND` | `memory` | `memory` or `redis` |

### Evidence

| Variable | Default | Description |
|---|---|---|
| `EVIDENCE_ENCRYPTION_KEY` | — | 32-byte KEK for envelope encryption |
| `EVIDENCE_RETENTION_DAYS` | `180` | Retention period |
| `RAPTOR_STORAGE_BACKEND` | `local` | `local` or `s3` |
| `S3_BUCKET` | — | Required when storage is `s3` |
| `S3_PREFIX` | `evidence/` | Object key prefix |
| `S3_REGION` | `us-east-1` | AWS region |
| `S3_ENDPOINT_URL` | — | Override for MinIO / GCS |

### Database

| Variable | Default | Description |
|---|---|---|
| `RAPTOR_DB_ENGINE` | `sqlite` | `sqlite` or `postgresql` |
| `RAPTOR_DATABASE_URL` | — | PostgreSQL DSN |
| `RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS` | `false` | Required for deliberate single-node prod |

### LLM

| Variable | Default | Description |
|---|---|---|
| `RAPTOR_ALLOW_EXTERNAL_LLM` | `false` | Enable external LLM calls |
| `LLM_PROVIDER` | `nvidia` | `nvidia` or `openrouter` |
| `LLM_MODEL` | `z-ai/glm-5.1` | Model identifier |
| `LLM_TIMEOUT_SECONDS` | `30` | Per-request timeout |

---

## API Reference

All endpoints require authentication (API key or session cookie) unless noted.

### Health

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | Optional | Liveness check |
| `GET` | `/api/v1/health/detailed` | Optional | Full subsystem status |

### Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/session` | None | Create session from credentials |
| `GET` | `/api/v1/auth/me` | Required | Current principal |
| `POST` | `/api/v1/auth/logout` | Required | Revoke session |

### Investigations

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/v1/investigate` | analyst | Upload log file |
| `POST` | `/api/v1/investigate/text` | analyst | Paste logs or Elasticsearch query |
| `GET` | `/api/v1/investigations` | viewer | List (tenant-scoped) |
| `GET` | `/api/v1/investigate/{id}/status` | viewer | Poll progress |
| `GET` | `/api/v1/investigate/{id}/report` | viewer | Full report |
| `GET` | `/api/v1/investigate/{id}/graph` | viewer | Attack graph (Sigma.js) |
| `GET` | `/api/v1/investigate/{id}/evidence` | viewer | Evidence metadata |

### Analysis

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/v1/simulate` | analyst | Predict next adversary steps |
| `POST` | `/api/v1/query` | viewer | Natural language graph query |
| `GET` | `/api/v1/mitre/matrix` | viewer | ATT&CK matrix with overlay |
| `GET` | `/api/v1/apt/profiles` | viewer | APT group library |
| `GET` | `/api/v1/apt/profiles/{name}` | viewer | Single APT profile |

### Intelligence

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/v1/threat-feeds/cisa-kev` | viewer | CISA KEV catalog |
| `POST` | `/api/v1/ingest/elasticsearch` | analyst | Pull and investigate events |
| `GET` | `/api/v1/ingest/elasticsearch/status` | viewer | Poller state |
| `PUT` | `/api/v1/ingest/elasticsearch/config` | admin | Configure poller |

### Admin

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/v1/audit` | admin | Audit log entries |
| `GET` | `/api/v1/metrics` | admin | Prometheus metrics |
| `GET` | `/api/v1/admin/schema/status` | admin | Schema migration status |
| `POST` | `/api/v1/users` | admin | Create user |
| `GET` | `/api/v1/users` | admin | List users |
| `PATCH` | `/api/v1/users/{id}` | admin | Update user |
| `DELETE` | `/api/v1/users/{id}` | admin | Delete user |

---

## Roles and Access Control

| Role | Permissions |
|---|---|
| `viewer` | Read investigations, reports, graphs, audit log, threat feeds |
| `analyst` | viewer + create investigations, run simulations, query graph |
| `admin` | analyst + user management, system configuration |
| `service` | Full access (API key principal) |

RBAC is enforced at every endpoint. Investigations are scoped by `tenant_id` — analysts only see their own tenant's cases.

---

## Evidence Handling

Evidence files use AES-256-GCM envelope encryption:

1. Random 32-byte DEK generated per file
2. File content encrypted: `AES-GCM(DEK, content)`
3. DEK wrapped: `AES-GCM(KEK, DEK)` — stored in file header
4. Encrypted blob written to storage backend

Retention is tracked per file. Cleanup:

```bash
# Dry run
python3 scripts/ops/cleanup_expired_evidence.py --dry-run

# Execute
python3 scripts/ops/cleanup_expired_evidence.py
```

Key rotation (re-wraps DEKs with new KEK, no re-encryption of content):

```bash
NEW_KEY=$(python3 -c "import secrets,base64; print('base64:'+base64.b64encode(secrets.token_bytes(32)).decode())")
python3 scripts/ops/rotate_evidence_key.py --new-key "$NEW_KEY" --dry-run
python3 scripts/ops/rotate_evidence_key.py --new-key "$NEW_KEY"
```

---

## Audit Trail

```bash
# Verify chain integrity
python3 scripts/ops/verify_audit_chain.py --db data/raptor.db

# Manual export (JSONL)
python3 scripts/ops/export_audit_log.py --db data/raptor.db --out /tmp/audit.jsonl

# Scheduled daily export with optional S3 upload
# Add to cron:  0 2 * * * /app/scripts/ops/export_audit_cron.sh
AUDIT_S3_BUCKET=my-audit-bucket scripts/ops/export_audit_cron.sh
```

The cron script (`scripts/ops/export_audit_cron.sh`) exports to a timestamped JSONL file, runs chain verification, optionally uploads to S3 with SSE, and prunes local copies older than 90 days.

---

## Observability

### Health

```bash
curl http://localhost:8000/api/v1/health/detailed
```

### Prometheus Metrics

```bash
curl -H "X-RAPTOR-API-Key: $KEY" http://localhost:8000/api/v1/metrics
```

Key metrics: `raptor_requests_total`, `raptor_auth_failures_total`, `raptor_investigations_created_total`, `raptor_investigations_completed_total`, `raptor_investigations_failed_total`, `raptor_parser_errors_total`, `raptor_request_latency_seconds_avg`.

Pre-built alert rules: `observability/prometheus-rules.yml`

| Alert | Condition |
|---|---|
| `RaptorHighErrorRate` | 5xx rate > 5% for 10 min |
| `RaptorAuthFailureSpike` | > 25 auth failures in 10 min |
| `RaptorInvestigationFailure` | Any failure in 15 min |
| `RaptorParserErrorSpike` | > 50 parser errors in 15 min |
| `RaptorHighLatency` | Average latency > 2 s |

---

## Operational Runbook

### Backup and Restore

```bash
scripts/ops/backup.sh
scripts/ops/restore.sh /path/to/backup-TIMESTAMP.tar.gz
```

### Bootstrap Admin Lockdown

Once permanent admin accounts are created:

```bash
# .env or secrets manager
RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true
docker compose restart backend worker
```

### Incident Response — Credential Compromise

```bash
# 1. Revoke all sessions
sqlite3 data/raptor.db "UPDATE auth_sessions SET revoked_at = datetime('now') WHERE revoked_at = ''"

# 2. Rotate RAPTOR_API_KEY and restart
docker compose restart backend

# 3. Reset affected user passwords
curl -X PATCH -H "X-RAPTOR-API-Key: $KEY" \
  http://localhost:8000/api/v1/users/{user_id} \
  -d '{"password": "new_strong_password"}'

# 4. Export audit log for the incident window
python3 scripts/ops/export_audit_log.py --db data/raptor.db --out incident-$(date +%Y%m%d).jsonl
```

---

## Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock pytest
# Run unit + integration tests (all tests live in tests/)
pytest -q ../tests/
RAPTOR_ENV=development uvicorn main:app --reload --port 8000
```

Tests are located in `tests/` at the project root. Each test file uses `tests/helpers.py` to add `backend/` to `sys.path` — no install step required.

| Test file | What it covers |
|---|---|
| `tests/test_persistence_connectors.py` | Evidence store, audit tamper-proofing, ES poll state, API-key middleware |
| `tests/test_api_persistence_connectors.py` | Auth sessions, CSRF guard, ES pull endpoint |
| `tests/test_parser_graph_nlq.py` | Log parser, graph builder, NLQ query engine |
| `tests/test_postgres_adapter.py` | SQLite→PostgreSQL SQL translation layer |
| `tests/test_postgres_runtime_integration.py` | Full PostgreSQL integration (requires `RAPTOR_DB_ENGINE=postgresql`) |

### Frontend

```bash
cd frontend
npm ci
npm run dev          # HMR dev server
npm run build        # Production build
npm run e2e          # Playwright tests (requires running backend or mocks)
```

### Full Stack (Code-Reloading)

```bash
docker compose up -d neo4j weaviate elasticsearch redis
cd backend && uvicorn main:app --reload --port 8000 &
cd frontend && npm run dev
```

---

## Security Hardening Checklist

### Before Any Production Traffic

- [ ] All `change_me_*` values replaced with cryptographic secrets
- [ ] `.env` not committed to repository (verified with `git log`)
- [ ] `RAPTOR_ENV=production`
- [ ] `RAPTOR_DB_ENGINE=postgresql` + valid `RAPTOR_DATABASE_URL`
- [ ] `RAPTOR_RATE_LIMIT_BACKEND=redis`
- [ ] `RAPTOR_ALLOW_AUTH_DISABLED=false`
- [ ] `RAPTOR_SESSION_COOKIE_SECURE=true`
- [ ] `EVIDENCE_ENCRYPTION_KEY` set to real 32-byte base64 value
- [ ] `CORS_ALLOW_ORIGINS` and `CSRF_TRUSTED_ORIGINS` set to your domain (not localhost)
- [ ] `RAPTOR_PROCESS_ROLE=api` for web, `worker` for background
- [ ] Running behind TLS-terminating ingress

### After Initial Setup

- [ ] Create permanent admin user via API
- [ ] Set `RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true` and restart
- [ ] Schedule daily audit export: `0 2 * * * /app/scripts/ops/export_audit_cron.sh`
- [ ] Set `AUDIT_S3_BUCKET` for immutable audit storage
- [ ] Enable Prometheus scraping of `/api/v1/metrics`
- [ ] Import `observability/prometheus-rules.yml` alert rules
- [ ] Run first backup and restore drill

### Quarterly

- [ ] Rotate `EVIDENCE_ENCRYPTION_KEY` (`scripts/ops/rotate_evidence_key.py`)
- [ ] Rotate `RAPTOR_API_KEY`
- [ ] Review audit log for anomalies
- [ ] `pip-audit -r backend/requirements.lock` + `npm audit` in frontend
- [ ] Re-scan container images: `trivy image raptor-backend:latest`
- [ ] Run `scripts/ops/smoke_load.py` to verify rate limiting
- [ ] Verify audit chain: `scripts/ops/verify_audit_chain.py`

### Annual

- [ ] External penetration test
- [ ] Review CORS / CSRF trusted origins
- [ ] Audit RBAC assignments — remove stale users and roles
- [ ] Purge expired evidence: `cleanup_expired_evidence.py`

---

## CI / CD

| Job | What it verifies |
|---|---|
| `test` | Backend pytest, frontend build, Playwright e2e (functional + security tests), production compose validation |
| `security-scan` | `pip-audit`, `npm audit --audit-level=high`, Gitleaks secret scan, Trivy filesystem scan |
| `container-scan` | Build backend + frontend images, Trivy image scan, Cosign keyless signing on main branch |
| `postgres-integration` | Full backend test suite against PostgreSQL 16 |

Image signing uses Cosign keyless OIDC — no long-lived signing keys required. Signatures are published to the Sigstore transparency log on every merge to `main`.

---

## License

See `LICENSE` for details.
