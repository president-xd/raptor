<div align="center">

# 🦅 RAPTOR

**Retrieval-Augmented Persistent Threat Orchestration and Reasoning**

A self-hostable APT investigation platform for security analysts. Ingest raw
telemetry, correlate it against MITRE ATT&CK, score APT attribution, predict
likely next adversary steps, and produce an analyst-ready forensic report — in a
single workflow, running entirely on your own infrastructure.

</div>

---

## Contents

- [What RAPTOR Does](#what-raptor-does)
- [Honest Status](#honest-status)
- [Architecture](#architecture)
- [Investigation Pipeline](#investigation-pipeline)
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
- [Testing](#testing)
- [Quality Gates](#quality-gates)
- [Documentation](#documentation)
- [Project Layout](#project-layout)
- [License](#license)

---

## What RAPTOR Does

1. **Ingest** raw logs (JSON, CEF, XML, or plaintext), or pull events directly
   from Elasticsearch, and normalise them into a common event model.
2. **Detect** technique activity using Sigma-style rules and, when enabled, a
   hybrid retrieval (RAG) step over MITRE ATT&CK and APT reference material.
3. **Graph** the attack: hosts, users, processes, and techniques are persisted
   into Neo4j (with an in-memory fallback when Neo4j is unavailable).
4. **Attribute** activity to known APT groups using Jaccard TTP overlap with
   explicit confidence gating (HIGH / MEDIUM / LOW / UNKNOWN).
5. **Simulate** likely next adversary steps from ATT&CK playbook context —
   blocked automatically at LOW / UNKNOWN confidence.
6. **Report** findings as a structured forensic narrative in the browser, with
   Markdown and printable PDF export.

The analyst console also includes a natural-language graph query interface, an
APT profile library, a MITRE ATT&CK matrix overlay, and a CISA Known Exploited
Vulnerabilities feed view.

---

## Honest Status

This section states plainly what is and is not in the repository, so the rest of
the document can be read at face value.

| Area | State |
|---|---|
| Backend API, worker, pipeline, RBAC, evidence encryption, audit chain | Implemented |
| React analyst console (dashboard, investigations, reports, MITRE, APT, NLQ) | Implemented |
| Docker Compose (local) and hardened production overlay | Implemented |
| SQLite (default) and PostgreSQL runtime metadata adapter | Implemented |
| External LLM calls | Optional, **disabled by default** |
| Local quality gates (`make validate`, `make security-scan`) | Implemented via `Makefile` |
| GitHub Actions CI/CD (tests, e2e, audits, Gitleaks, Trivy, Cosign signing) | Implemented (`.github/workflows/ci.yml`, `release.yml`) |
| License file | **Not included** — see [License](#license) |
| Database migration tooling | Not included — schema is managed at startup |

By default RAPTOR runs on SQLite and keeps evidence on the local filesystem,
which is appropriate for single-node and controlled deployments. PostgreSQL,
Redis-backed rate limiting, a separate worker process, and S3-compatible
evidence storage are available for hardened production use through the
production overlay.

---

## Architecture

```
+---------------------------------------------------------+
|  Browser (Analyst Console)                              |
|  React 18 - Vite - Nginx (rate-limited reverse proxy)   |
+--------------------+------------------------------------+
                     | HTTP(S); TLS terminated upstream
+--------------------v------------------------------------+
|  RAPTOR API  (FastAPI - Uvicorn - Python 3.11)          |
|  +----------+ +----------+ +----------+ +----------+    |
|  |  Auth    | | Evidence | |  Jobs    | | Metrics  |    |
|  |  RBAC    | | Encrypt  | |  Queue   | | Audit    |    |
|  +----------+ +----------+ +----------+ +----------+    |
+------+---------------+---------------+------------------+
       |               |               |
+------v------+  +-----v------+  +-----v------------------+
|  Neo4j 5.15 |  | Weaviate   |  |  RAPTOR Worker          |
|  Attack     |  | 1.27.6     |  |  (prod: separate proc)  |
|  Graph      |  | RAG / Vec  |  |  Investigation pipeline |
+-------------+  +------------+  +-----------+------------+
                                             |
+--------------------------------------------v------------+
|  SQLite (default) / PostgreSQL 16 (prod overlay)        |
|  Elasticsearch 8.11 (log search)  Redis 7.2 (limits)    |
+---------------------------------------------------------+
```

PostgreSQL 16 and the standalone worker container are provisioned by the
production overlay (`docker-compose.prod.yml`). The base `docker-compose.yml`
runs the backend in a combined role on SQLite.

### Backend Modules

The backend is a modular FastAPI application with a one-directional import chain
(no circular dependencies):

```
config
  -> database          (all DB/Redis I/O, SQLite<->PostgreSQL adapter)
       -> metrics_store (Prometheus or in-memory counters)
            -> auth_core (sessions, RBAC, rate limiting, SSO, CSRF)
                 -> evidence_crypto (AES-256-GCM envelope encryption)
                      -> pipeline_runner (investigation worker loop)
                           -> routers/  (FastAPI endpoint modules)
                                -> main.py (app factory + middleware)
```

| Module | Responsibility |
|---|---|
| `config.py` | Load and validate environment variables; fail loudly on unsafe production config |
| `database.py` | Every DB read/write; SQLite<->PostgreSQL adapter; Redis helpers |
| `metrics_store.py` | Prometheus counters with in-process fallback |
| `auth_core.py` | Sessions, PBKDF2 passwords, RBAC, rate limiting, SSO proxy trust, CSRF |
| `evidence_crypto.py` | DEK/KEK envelope encryption; legacy decrypt; key derivation |
| `llm_redactor.py` | Strip PII/secrets from prompts before any external LLM call |
| `pipeline_runner.py` | Six-phase investigation pipeline and worker loop |
| `storage.py` | Pluggable evidence backend: local filesystem or S3-compatible |
| `worker.py` | Standalone worker entry point (`RAPTOR_PROCESS_ROLE=worker`) |
| `main.py` | FastAPI app factory, middleware stack, lifespan hooks |
| `routers/` | `auth`, `investigations`, `analysis`, `intelligence`, `admin`, `health` |
| `attribution/` | APT profiles, ATT&CK catalog, Jaccard scoring, confidence, STIX validation |
| `graph/` | Neo4j client, graph builder, provenance, queries |
| `ingestion/` | Log parser, normaliser, Sigma matcher, mock generator |
| `rag/` | Embeddings, indexer, retriever, reranker, pipeline |
| `report/` | Forensic report generator |
| `nlq/` | Natural-language graph query engine |
| `simulation/` | Next-step predictor |

---

## Investigation Pipeline

Each investigation runs six sequential phases in the worker
(`backend/pipeline_runner.py`). Progress is reported through the status endpoint.

| Phase | Description |
|---|---|
| 1. Parse | Parse and normalise raw logs into `RaptorEvent` records |
| 2. RAG analysis | Hybrid retrieval + LLM reasoning; deterministic Sigma fallback when the LLM is disabled or returns nothing |
| 3. STIX validation | Validate and normalise technique IDs against the bundled ATT&CK catalog |
| 4. Attack graph | Persist hosts/users/techniques into Neo4j; in-memory fallback when Neo4j is down |
| 5. Attribution | Jaccard TTP scoring across APT profiles with confidence gating |
| 6. Report | Generate the analyst-facing forensic narrative |

Simulation is a separate analyst action and is blocked at LOW / UNKNOWN
attribution confidence.

---

## Security Model

### Authentication

| Method | Header / Cookie | Use case |
|---|---|---|
| API Key | `X-RAPTOR-API-Key` or `Authorization: Bearer` | Service-to-service, scripts |
| Session Cookie | `raptor_session` (HttpOnly, SameSite=Lax) | Browser sessions |
| SSO / OIDC proxy | `X-Forwarded-User` (configurable) | Enterprise IdP via trusted proxy |

Sessions are server-side and revocable via `POST /api/v1/auth/logout`. Lifetime
is set by `RAPTOR_SESSION_TTL_SECONDS` (default 8 hours). Passwords use
PBKDF2-SHA256 with a per-user salt; accounts lock after
`RAPTOR_AUTH_MAX_FAILURES` failed attempts.

### Rate Limiting

| Bucket | Limit | Window |
|---|---|---|
| `auth` | 10 req | 60 s |
| `upload` | 20 req | 300 s |
| `query` | 60 req | 300 s |
| `connector` | 30 req | 300 s |

In production, `RAPTOR_RATE_LIMIT_BACKEND=redis` coordinates limits across API
workers. The Nginx frontend adds per-IP rate zones as defense in depth.

### Evidence Encryption

Evidence files are encrypted at rest with **AES-256-GCM envelope encryption**:

1. A random per-file Data Encryption Key (DEK) is generated per upload.
2. File content is encrypted with the DEK.
3. The DEK is wrapped by the static Key Encryption Key (KEK) from
   `EVIDENCE_ENCRYPTION_KEY`.
4. The wrapped DEK is stored in the file header, so key rotation only re-wraps
   DEKs rather than re-encrypting content.

A legacy direct-KEK format remains decryptable for backward compatibility. With
`RAPTOR_STORAGE_BACKEND=s3`, the ciphertext additionally sits behind S3
server-side encryption.

### LLM Privacy

External LLM calls are **disabled by default** (`RAPTOR_ALLOW_EXTERNAL_LLM=false`).
When enabled, every prompt is scrubbed by `llm_redactor.py` before transmission.

| Pattern | Replacement |
|---|---|
| Bearer / Authorization tokens | `Bearer [REDACTED_TOKEN]` |
| Credential key-value pairs (`password=`, `secret=`, `api_key=`) | `key=[REDACTED]` |
| US Social Security Numbers | `[SSN_REDACTED]` |
| Luhn-plausible card numbers | `[CC_REDACTED]` |
| Email addresses | `[EMAIL_REDACTED]` |
| US phone numbers | `[PHONE_REDACTED]` |
| Private IPv4 ranges | `[PRIVATE_IP]` |
| Sensitive Unix paths (`/etc/shadow`, `.ssh/id_rsa`) | `[SENSITIVE_PATH]` |
| Windows drive paths (`C:\...`) | `[WINDOWS_PATH]` |
| UNC network paths (`\\server\share`) | `[UNC_PATH]` |

### CSRF Protection

Browser-session mutations (POST/PUT/PATCH/DELETE) require a trusted `Origin` or
`Referer`. API-key requests are stateless and exempt; the login endpoint is
explicitly exempt.

### Audit Trail

Every security-relevant action appends to an append-only `audit_log` table:

- A database trigger blocks `UPDATE` and `DELETE` on the table.
- Each entry carries a SHA-256 hash of prior content (hash chain), making
  tampering detectable.
- Verified with `scripts/ops/verify_audit_chain.py`.
- Exportable via `scripts/ops/export_audit_log.py`, with an optional cron
  wrapper (`scripts/ops/export_audit_cron.sh`).

---

## Quick Start (Local)

### Prerequisites

- Docker Desktop >= 4.28 with Compose V2
- ~8 GB RAM available for containers

```bash
# 1. Clone
git clone <your-fork-url> raptor
cd raptor

# 2. Copy and edit configuration
cp .env.example .env
# Replace every change_me_* value before exposing the service.

# 3. Start the full stack
docker compose up -d --build

# 4. Wait for health checks (~60 s)
docker compose ps

# 5. Open the console
#    Frontend: http://localhost:3100
#    API:      http://localhost:8000/api/v1/health
```

Bootstrap admin credentials come from `RAPTOR_BOOTSTRAP_ADMIN_USERNAME` /
`RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` in `.env`. After creating a permanent admin,
set `RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true` and restart.

The base compose stack runs on SQLite. There is no separate PostgreSQL or worker
container in local mode — the backend runs the pipeline in-process.

---

## Production Deployment

### 1. Generate Secrets

```bash
openssl rand -hex 32                                   # RAPTOR_API_KEY
openssl rand -base64 24                                # bootstrap admin password
python3 -c "import secrets,base64; print('base64:'+base64.b64encode(secrets.token_bytes(32)).decode())"  # EVIDENCE_ENCRYPTION_KEY
openssl rand -hex 24                                   # service passwords
```

Store secrets in a secrets manager. Never commit them.

### 2. Required Environment Variables

| Variable | Requirement |
|---|---|
| `RAPTOR_ENV` | `production` |
| `RAPTOR_API_KEY` | Service API key (>= 32 chars) |
| `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` | Initial admin password |
| `RAPTOR_DB_ENGINE` | `postgresql` |
| `RAPTOR_DATABASE_URL` | `postgresql://user:pass@host:5432/raptor` |
| `RAPTOR_RATE_LIMIT_BACKEND` | `redis` |
| `RAPTOR_SESSION_COOKIE_SECURE` | `true` (behind TLS) |
| `RAPTOR_ALLOW_AUTH_DISABLED` | `false` |
| `EVIDENCE_ENCRYPTION_KEY` | 32-byte base64 KEK |
| `NEO4J_PASSWORD`, `WEAVIATE_API_KEY`, `ELASTIC_PASSWORD`, `REDIS_PASSWORD`, `POSTGRES_PASSWORD` | Non-placeholder values |
| `CORS_ALLOW_ORIGINS`, `CSRF_TRUSTED_ORIGINS` | Your frontend origin |

The backend refuses to start in `RAPTOR_ENV=production` when lab defaults remain,
when PostgreSQL is selected without a DSN, or when SQLite limits are not
explicitly acknowledged. Fix the reported variable rather than disabling the guard.

### 3. Deploy

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.prod.yml \
  up -d --build

curl -sf http://localhost:8000/api/v1/health/detailed | python3 -m json.tool
```

The production overlay provisions a `postgres` service and a separate `worker`
container, resets all internal port bindings, and enforces hardened service
settings.

### 4. TLS

RAPTOR does not terminate TLS. Deploy behind an Nginx/Caddy host, a cloud HTTPS
load balancer, or a Kubernetes ingress with cert-manager. HSTS is set by the
Nginx config and when `RAPTOR_PRODUCTION=true`.

### 5. SSO / OIDC

```bash
RAPTOR_TRUSTED_SSO_ENABLED=true
RAPTOR_TRUSTED_PROXY_CIDRS=10.0.0.5/32
RAPTOR_SSO_USER_HEADER=x-forwarded-user
RAPTOR_SSO_ROLES_HEADER=x-forwarded-roles   # comma-separated
RAPTOR_SSO_TENANT_HEADER=x-forwarded-tenant
```

Identity headers must be stripped from client requests at the ingress; they are
honoured only from trusted CIDRs.

### 6. S3 Evidence Storage

```bash
RAPTOR_STORAGE_BACKEND=s3
S3_BUCKET=my-raptor-evidence
S3_PREFIX=evidence/
S3_REGION=us-east-1
# S3_ENDPOINT_URL=https://minio.internal:9000   # MinIO / GCS
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
| `RAPTOR_SESSION_TTL_SECONDS` | `28800` | Session lifetime |
| `RAPTOR_REQUIRE_RBAC` | `true` | Enforce role checks |
| `RAPTOR_AUTH_MAX_FAILURES` | `5` | Lockout threshold |
| `RAPTOR_AUTH_LOCK_SECONDS` | `900` | Lockout duration |
| `RAPTOR_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Bootstrap admin name |
| `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` | — | Bootstrap admin password |
| `RAPTOR_BOOTSTRAP_ADMIN_DISABLED` | `false` | Disable bootstrap account |
| `RAPTOR_RATE_LIMIT_BACKEND` | `memory` | `memory` or `redis` |

### Evidence

| Variable | Default | Description |
|---|---|---|
| `EVIDENCE_ENCRYPTION_KEY` | — | 32-byte KEK for envelope encryption |
| `EVIDENCE_RETENTION_DAYS` | `180` | Retention period |
| `RAPTOR_STORAGE_BACKEND` | `local` | `local` or `s3` |
| `S3_BUCKET` / `S3_PREFIX` / `S3_REGION` / `S3_ENDPOINT_URL` | — | S3 storage settings |

### Database

| Variable | Default | Description |
|---|---|---|
| `RAPTOR_DB_ENGINE` | `sqlite` | `sqlite` or `postgresql` |
| `RAPTOR_DATABASE_URL` | — | PostgreSQL DSN |
| `RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS` | `false` | Required for deliberate single-node SQLite prod |

### LLM

| Variable | Default | Description |
|---|---|---|
| `RAPTOR_ALLOW_EXTERNAL_LLM` | `false` | Enable external LLM calls |
| `LLM_PROVIDER` | `nvidia` | `nvidia` or `openrouter` |
| `LLM_MODEL` | `z-ai/glm-5.1` | Model identifier |
| `LLM_TIMEOUT_SECONDS` | `30` | Per-request timeout |

See `.env.example` for the complete, annotated list.

---

## API Reference

All endpoints are under `/api/v1` and require authentication unless noted.

### Health

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | Optional | Liveness check |
| `GET` | `/health/detailed` | Optional | Full subsystem status |

### Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/session` | None | Create session from credentials |
| `GET` | `/auth/me` | Required | Current principal |
| `POST` | `/auth/logout` | Required | Revoke session |

### Investigations

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/investigate` | analyst | Upload log file |
| `POST` | `/investigate/text` | analyst | Paste logs or an Elasticsearch query |
| `GET` | `/investigations` | viewer | List (tenant-scoped) |
| `GET` | `/investigate/{id}/status` | viewer | Poll progress |
| `GET` | `/investigate/{id}/report` | viewer | Full report |
| `GET` | `/investigate/{id}/graph` | viewer | Attack graph |
| `GET` | `/investigate/{id}/evidence` | viewer | Evidence metadata |

### Analysis

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/simulate` | analyst | Predict next adversary steps |
| `POST` | `/query` | viewer | Natural-language graph query |
| `GET` | `/mitre/matrix` | viewer | ATT&CK matrix with overlay |
| `GET` | `/apt/profiles` | viewer | APT group library |
| `GET` | `/apt/profiles/{name}` | viewer | Single APT profile |

### Intelligence

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/threat-feeds/cisa-kev` | viewer | CISA KEV catalog |
| `POST` | `/ingest/elasticsearch` | analyst | Pull and investigate events |
| `GET` | `/ingest/elasticsearch/status` | viewer | Poller state |
| `PUT` | `/ingest/elasticsearch/config` | admin | Configure poller |

### Admin

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/audit` | admin | Audit log entries |
| `GET` | `/metrics` | admin | Prometheus metrics |
| `GET` | `/admin/schema/status` | admin | Schema status |
| `POST` `GET` `PATCH` `DELETE` | `/users` | admin | User management |

---

## Roles and Access Control

| Role | Permissions |
|---|---|
| `viewer` | Read investigations, reports, graphs, audit log, threat feeds |
| `analyst` | viewer + create investigations, run simulations, query graph |
| `admin` | analyst + user management, system configuration |
| `service` | Full access (API-key principal) |

RBAC is enforced at every endpoint. Investigations are scoped by `tenant_id`;
analysts see only their own tenant's cases.

---

## Evidence Handling

Evidence is written under `data/evidence/{investigation_id}/` and encrypted with
AES-256-GCM envelope encryption.

```bash
# Expired-evidence cleanup
python3 scripts/ops/cleanup_expired_evidence.py --db data/raptor.db            # dry run
python3 scripts/ops/cleanup_expired_evidence.py --db data/raptor.db --execute  # after approval

# Key rotation (re-wraps DEKs; no content re-encryption)
python3 scripts/ops/rotate_evidence_key.py --db data/raptor.db --execute
```

---

## Audit Trail

```bash
python3 scripts/ops/verify_audit_chain.py --db data/raptor.db
python3 scripts/ops/export_audit_log.py --db data/raptor.db --out exports/audit-log.jsonl

# Scheduled export with optional S3 upload
AUDIT_S3_BUCKET=my-audit-bucket scripts/ops/export_audit_cron.sh
```

The cron script writes a timestamped JSONL export, runs chain verification,
optionally uploads to S3, and prunes local copies older than 90 days.

---

## Observability

```bash
curl http://localhost:8000/api/v1/health/detailed
curl -H "X-RAPTOR-API-Key: $KEY" http://localhost:8000/api/v1/metrics
```

Key metrics: `raptor_requests_total`, `raptor_auth_failures_total`,
`raptor_investigations_created_total`, `raptor_investigations_completed_total`,
`raptor_investigations_failed_total`, `raptor_parser_errors_total`,
`raptor_request_latency_seconds_avg`.

Reference alert rules live in `observability/prometheus-rules.yml` and a starter
Grafana dashboard in `observability/grafana-dashboard.json`.

| Alert | Condition |
|---|---|
| `RaptorHighErrorRate` | 5xx rate > 5% for 10 min |
| `RaptorAuthFailureSpike` | > 25 auth failures in 10 min |
| `RaptorInvestigationFailure` | Any failure in 15 min |
| `RaptorParserErrorSpike` | > 50 parser errors in 15 min |
| `RaptorHighLatency` | Average latency > 2 s |

---

## Operational Runbook

```bash
# Backup / restore
scripts/ops/backup.sh backups/$(date -u +%Y%m%dT%H%M%SZ)
scripts/ops/restore.sh backups/<backup-id>

# Bootstrap lockdown after creating a real admin
#   set RAPTOR_BOOTSTRAP_ADMIN_DISABLED=true, then:
docker compose restart backend
```

Full procedures — deployment posture, identity, worker operations, backup order,
audit integrity, and incident response — are in
[`docs/production-runbook.md`](docs/production-runbook.md).

---

## Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock pytest
RAPTOR_ENV=development uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm ci
npm run dev          # HMR dev server
npm run build        # Production build
npm run e2e          # Playwright tests
```

### Full Stack (code-reloading)

```bash
docker compose up -d neo4j weaviate elasticsearch redis
cd backend && uvicorn main:app --reload --port 8000 &
cd frontend && npm run dev
```

Any change to frontend CSS/JSX in a containerised setup requires a rebuild:

```bash
docker compose up -d --build frontend
```

---

## Testing

Backend tests live in `tests/` at the repository root. `conftest.py` adds both
`tests/` and `backend/` to `sys.path`, so no install step is required.

```bash
pytest -q tests/
# or
python -m unittest discover -s tests
```

| Test file | Coverage |
|---|---|
| `tests/test_ingestion_pipeline.py` | Log parsing, Sigma matching, normalisation |
| `tests/test_parser_graph_nlq.py` | Parser, graph builder, NLQ query engine |
| `tests/test_graph_query.py` | Graph query construction and guards |
| `tests/test_analysis_attribution.py` | Attribution scoring and confidence |
| `tests/test_attack_catalog_matrix.py` | ATT&CK catalog / matrix |
| `tests/test_rag_fallbacks.py` | Deterministic fallbacks when the LLM is off |
| `tests/test_persistence_connectors.py` | Evidence store, audit tamper-proofing, ES poll state, API-key auth |
| `tests/test_api_persistence_connectors.py` | Auth sessions, CSRF guard, ES pull endpoint |
| `tests/test_postgres_adapter.py` | SQLite -> PostgreSQL SQL translation |
| `tests/test_postgres_runtime_integration.py` | Full PostgreSQL integration (needs `RAPTOR_DB_ENGINE=postgresql`) |
| `tests/test_repo_contracts.py` | Repository contract checks |

Frontend end-to-end tests are in `frontend/e2e/` (`dashboard.spec.js`,
`security.spec.js`) and run with Playwright via `npm run e2e`.

---

## Quality Gates

### Local

Run the gates locally through the `Makefile` before pushing:

```bash
make validate         # pytest + frontend build + prod compose config validation
make security-scan    # pip-audit (backend) + npm audit --audit-level=high (frontend)
make compose-config   # validate the production compose overlay renders
```

### Continuous Integration (`.github/workflows/ci.yml`)

Runs on every pull request and on pushes to `main`:

| Job | What it verifies |
|---|---|
| `backend-tests` | Offline regression suite (`pytest tests/`) on Python 3.11 |
| `postgres-integration` | `test_postgres_runtime_integration.py` against a live `postgres:16` service |
| `frontend-build` | Production Vite build |
| `frontend-e2e` | Playwright functional + security e2e (API-mocked, Vite dev server) |
| `compose-validate` | Production compose overlay renders with all required variables |
| `dependency-audit` | `pip-audit` (backend) and `npm audit --audit-level=high` (frontend) |
| `secret-scan` | Gitleaks secret scan over full history |
| `filesystem-scan` | Trivy filesystem scan (fails on fixable CRITICALs) |
| `container-scan` | Builds backend and frontend images and scans them with Trivy |

### Release and Signing (`.github/workflows/release.yml`)

Runs on pushes to `main` and on `v*.*.*` tags:

- Builds the backend and frontend images and pushes them to the GitHub
  Container Registry (`ghcr.io`).
- Scans the published image digests with Trivy.
- Signs each pushed digest with **Cosign keyless** (Sigstore / OIDC) — no
  long-lived signing keys. Verify a published image with:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/<owner>/<repo>/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/<owner>/<repo>/backend:<tag>
```

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/production-runbook.md`](docs/production-runbook.md) | Deployment posture, identity, worker ops, backup/restore, incident response |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, trust boundaries, threats and controls, residual risk |
| [`docs/data-governance.md`](docs/data-governance.md) | Data classes, LLM policy, retention, evidence encryption, audit |
| [`docs/observability.md`](docs/observability.md) | Metrics, logs, operational checks |
| [`docs/scaling-limits.md`](docs/scaling-limits.md) | Operating envelope, bottlenecks, expansion path |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |

---

## Project Layout

```
backend/        FastAPI app, pipeline, attribution, graph, rag, ingestion, report
frontend/       React 18 + Vite analyst console (Nginx-served container)
data/           Mock telemetry, bundled STIX/ATT&CK, runtime evidence (gitignored)
docs/           Operational and governance documentation
observability/  Prometheus alert rules and Grafana dashboard
scripts/        Docker installers, hybrid installers, ops tooling
tests/          Backend test suite (run from repo root)
docker-compose.yml          Local stack (SQLite)
docker-compose.prod.yml     Hardened production overlay (PostgreSQL + worker)
Makefile                    Local quality gates and ops shortcuts
```

---

## License

This repository is under Apache License.