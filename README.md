# 🦅 RAPTOR

Retrieval-Augmented Persistent Threat Orchestration and Reasoning

RAPTOR is a cybersecurity investigation platform for turning security telemetry into ATT&CK-mapped findings, attack graphs, attribution candidates, analyst reports, and next-step adversary predictions. It combines a FastAPI backend, local Sigma-style detections, MITRE ATT&CK STIX data, optional RAG over Weaviate, Neo4j graph persistence, OpenRouter-compatible LLM calls, and a React/Vite SOC console.

This repository is now wired as one live application:

- The backend investigation API ingests logs, runs the analysis pipeline through a durable SQLite-backed job queue, persists job state, and exposes reports, graphs, attribution, simulation, APT profiles, health, metrics, and natural-language query endpoints.
- The React console calls the backend through `frontend/src/api/raptorApi.js`. The investigation queue, new-ingestion workflow, report preview/download, graph view, attribution view, simulation, intelligence query, APT library, MITRE view, and subsystem health screens are API-backed rather than fabricated local data.

## Current Status

Implemented today:

- Multi-format log ingestion for JSON, newline JSON, XML Windows events, CEF, and generic text logs.
- File-upload investigations through `POST /api/v1/investigate`.
- Pasted-log and Elasticsearch-query investigations through `POST /api/v1/investigate/text`.
- Normalized event schema with timestamps, hosts, IPs, event type, raw evidence, Sigma matches, and preliminary IoC score.
- Local Sigma-style detection signatures mapped to MITRE ATT&CK technique IDs.
- RAG-oriented analysis pipeline that retrieves ATT&CK and threat-report context from Weaviate when available.
- OpenAI-compatible LLM analysis with NVIDIA NIM/GLM defaults and fallback model support.
- Deterministic local fallback analysis when the LLM, embeddings, retrieval, or report generation path cannot complete.
- MITRE ATT&CK STIX validation for technique IDs.
- APT profile loading from the cached Enterprise ATT&CK STIX bundle.
- APT attribution using Jaccard overlap plus confidence penalties and bonuses.
- Neo4j attack graph writing when Neo4j is reachable.
- In-memory graph export fallback when Neo4j is unavailable.
- Investigation-scoped graph data and guarded read-only natural-language graph queries.
- Predictive simulation endpoint gated by attribution confidence.
- Natural-language query endpoint that routes questions to graph, RAG, or simulation-style handlers.
- Markdown analyst report generation with deterministic fallback.
- Detailed health endpoint for API, SQLite, Neo4j, Weaviate, Elasticsearch, Redis, evidence encryption, and LLM configuration.
- Prometheus-compatible operational counters at `/api/v1/metrics`.
- React SOC console backed by the API for investigation creation, polling, reports, graphs, raw evidence metadata, audit log review, manual Elasticsearch polling, attribution, simulation, natural-language query, APT profiles, MITRE findings, report download, and subsystem health.
- Investigation metadata in the backend list API, including case name, source, upload size, host count, top candidate, confidence score, and confidence label.
- Persistent raw evidence storage under `data/evidence/{investigation_id}/` with SQLite metadata for path, hash, size, source, content type, AES-256-GCM encryption state, and retention expiry.
- Append-only SQLite audit logging with a database-level update/delete guard and per-entry hash chain for investigation creation, report/graph/evidence viewing, natural-language queries, simulations, threat-feed access, and Elasticsearch poller actions.
- Server-side browser sessions, API-key service access, local bootstrap admin credentials, role checks, tenant scoping, and case ownership enforcement.
- SQLite-backed investigation job queue with retry tracking, stale-claim recovery, and separate API/worker process roles for hardened single-node deployments.
- CISA Known Exploited Vulnerabilities connector with file cache and Redis JSON cache when Redis is reachable.
- Optional interval-based Elasticsearch poller that queues matching events as investigations.
- Redis health plus lightweight CISA KEV cache usage.
- Docker Compose stack for backend, frontend, Neo4j, Weaviate, Elasticsearch, and Redis.
- Docker Compose ports bind to `127.0.0.1` by default through `LOCAL_BIND_ADDRESS`.
- Windows and Linux helper scripts for Docker and hybrid local runs.
- Regression tests for parser behavior, persistence helpers, graph scoping/export, connector state, and natural-language query safety guards.
- Production security hardening for bounded request models, CSP headers, feed URL allowlists, redacted health details, and safer evidence metadata exposure.
- CI security gates for Python dependencies, frontend dependencies, secret scanning, filesystem scanning, and backend/frontend container image scanning.
- Operational tooling for backup/restore, audit hash-chain verification, audit export, expired evidence cleanup, and evidence encryption key rotation.
- Prometheus alert rules, a starter Grafana dashboard, and an observability runbook for production monitoring.
- Redis-backed production rate limiting, trusted ingress SSO/OIDC header support, schema migration version tracking, and smoke/load drill tooling.

Operational boundaries:

- MISP and OpenCTI are not active backend connectors.
- Elasticsearch ingest is a simple interval poller, not a streaming pipeline with checkpoints and deduplication.
- Redis is used as a lightweight cache, not a lock service.
- SQLite is used for local single-node job, audit, identity, session, and investigation metadata. Use PostgreSQL or equivalent through the documented deployment path for multi-node, high-concurrency case management.
- The sample credentials in `.env.example` must be changed before use outside a private local workstation.

## Architecture

```text
Analyst / API client
        |
        | upload logs, paste logs, or submit Elasticsearch query
        v
FastAPI backend
        |
        | parse and normalize
        v
RaptorEvent schema
        |
        | Sigma-style ATT&CK matching
        v
Analysis pipeline
        |
        | optional retrieval from Weaviate
        | optional OpenRouter LLM reasoning
        | deterministic fallback when unavailable
        v
Validated findings
        |
        | STIX validation, attribution scoring, graph building, report generation
        v
SQLite job state + optional Neo4j graph
        |
        v
API responses for status, report, graph, simulation, and query
```

The React console is served separately and calls the backend API:

```text
React/Vite frontend
        |
        | /api/v1 via Vite proxy or Nginx proxy
        v
FastAPI backend
```

## Tech Stack

| Area | Technology |
|---|---|
| Backend API | FastAPI, Pydantic, Uvicorn |
| Job state | SQLite |
| Graph database | Neo4j 5 community |
| Vector database | Weaviate 1.27 |
| Search source | Elasticsearch 8 single-node |
| Runtime service | Redis 7, lightweight JSON cache plus health checks |
| LLM client | OpenAI SDK against OpenRouter-compatible API |
| Embeddings | `BAAI/bge-large-en-v1.5` through `sentence-transformers` |
| Reranking | Configured BGE cross-encoder reranker with lexical fallback |
| Threat framework | MITRE Enterprise ATT&CK STIX |
| Frontend | React 18, Vite 5, Tailwind CSS, lucide-react |
| Frontend serving | Vite in development, Nginx in Docker |
| Deployment | Docker Compose plus optional local hybrid scripts |
| Security scanning | pip-audit, npm audit, Gitleaks, Trivy |
| Observability | Prometheus-compatible metrics, Grafana dashboard seed, alert rules |

## Repository Layout

```text
.
|-- backend/
|   |-- main.py                    # FastAPI app and investigation orchestration
|   |-- config.py                  # Environment configuration and LLM prompts
|   |-- models.py                  # API request/response models
|   |-- schema.py                  # Core RAPTOR data models
|   |-- ingestion/                 # Log parsing, normalization, Sigma matching
|   |-- rag/                       # Retrieval, indexing, embeddings, reranking, LLM analysis
|   |-- attribution/               # STIX profile loading, Jaccard scoring, confidence logic
|   |-- graph/                     # Neo4j client, graph builder, provenance helpers
|   |-- nlq/                       # Natural-language query routing and Cypher safeguards
|   |-- simulation/                # Next-step prediction
|   |-- report/                    # Analyst report generation
|   `-- tests/                     # Regression tests
|-- data/
|   |-- mock/                      # Example investigation logs
|   `-- stix/                      # Cached MITRE Enterprise ATT&CK bundle
|-- frontend/
|   |-- src/api/raptorApi.js       # Frontend API client
|   |-- src/components/Dashboard.jsx
|   |-- src/index.css              # Dark SOC console design system
|   |-- vite.config.js
|   |-- nginx.conf
|   `-- Dockerfile
|-- docs/
|   |-- production-runbook.md      # Deployment, backup, operations, and incident procedures
|   |-- observability.md           # Metrics, alerts, logs, and operational review cadence
|   |-- threat-model.md            # Trust boundaries, abuse paths, and required controls
|   |-- data-governance.md         # Evidence, telemetry, LLM, retention, and audit policy
|   `-- scaling-limits.md          # Scale limits and migration path
|-- observability/
|   |-- prometheus-rules.yml       # Starter production alert rules
|   `-- grafana-dashboard.json     # Starter Grafana dashboard JSON
|-- scripts/
|   |-- docker/                    # Full Docker launch helpers
|   |-- hybrid/                    # Docker infrastructure plus local app helpers
|   `-- ops/                       # Backup, restore, audit, retention, and key-rotation tools
|-- tests/                         # Top-level offline regression suite
|-- Makefile                       # Local validation and production readiness targets
|-- docker-compose.yml
|-- docker-compose.prod.yml
|-- .env.example
`-- README.md
```

## Runtime Services

| Service | Default URL | Purpose |
|---|---|---|
| Frontend console | `http://localhost:3100` | React SOC dashboard |
| Backend API docs | `http://localhost:8000/docs` | Interactive OpenAPI documentation |
| Backend health | `http://localhost:8000/api/v1/health` | High-level service health |
| Detailed health | `http://localhost:8000/api/v1/health/detailed` | Subsystem health |
| Neo4j browser | `http://localhost:7474` | Graph database UI |
| Neo4j Bolt | `bolt://localhost:7687` | Backend graph connection |
| Weaviate HTTP | `http://localhost:8080` | Vector database |
| Weaviate gRPC | `localhost:50051` | Weaviate v4 client transport |
| Elasticsearch | `http://localhost:9200` | Optional investigation source |
| Redis | `localhost:6379` | Lightweight connector cache and health check |

Production deployments should set `RAPTOR_RATE_LIMIT_BACKEND=redis` so API rate limits are shared across API processes. Local development defaults to the in-memory limiter.

## Quick Start With Docker

Prerequisites:

- Docker Desktop or Docker Engine with Compose support.
- Enough disk and memory for Neo4j, Weaviate, Elasticsearch, Redis, backend, and frontend containers.
- Optional OpenRouter API key for LLM-powered reasoning. Without a key, investigations can still complete through deterministic fallback logic.

1. Copy the environment template.

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

2. Edit `.env`, replace the `NEO4J_PASSWORD`, `RAPTOR_API_KEY`, and bootstrap admin placeholders. Set `NVIDIA_API_KEY` and `RAPTOR_ALLOW_EXTERNAL_LLM=true` only when your data policy permits live LLM calls.

3. Start the stack.

```bash
docker compose up -d --build
```

For a hardened deployment profile, apply the production overlay after setting real secrets. The overlay runs separate API and worker containers, switches runtime metadata to PostgreSQL, and enables production startup validation:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

4. Open the frontend and API docs.

```text
Frontend: http://localhost:3100
API docs: http://localhost:8000/docs
```

5. Check backend health.

```bash
curl http://localhost:8000/api/v1/health/detailed
```

Helper scripts are also available:

```powershell
.\scripts\docker\install_windows.ps1
```

```bash
bash scripts/docker/install_linux.sh
```

## Hybrid Local Development

Hybrid mode runs the infrastructure in Docker while running backend and frontend directly on the host.

1. Start infrastructure.

```bash
docker compose up -d neo4j weaviate elasticsearch redis
```

2. Start the backend.

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

On Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

3. Start the frontend.

```bash
cd frontend
npm install
npm run dev
```

The browser frontend no longer embeds the API key at build time. When backend API-key auth is enabled, use the in-app authentication prompt to exchange the operator-provided key for an HttpOnly session cookie.

4. Open `http://localhost:3100`.

Hybrid helper scripts are available:

```powershell
.\scripts\hybrid\install_windows.ps1
```

```bash
bash scripts/hybrid/install_linux.sh
```

The Linux hybrid helper validates Docker access, dependency presence, service health, and the backend/frontend HTTP ports before reporting success. If Docker infrastructure is already running and you only need to restart the local backend/frontend, run `RAPTOR_SKIP_INFRA=true bash scripts/hybrid/install_linux.sh`. If the helper reports Docker daemon access errors, start Docker and either run `sudo -v` before the script or add your user to the Docker group for non-root Docker access.

## Backend Pipeline

The main orchestration lives in `backend/main.py`.

1. The API receives uploaded logs, pasted logs, or Elasticsearch results.
2. `LogParser` parses JSON, XML Windows events, CEF, or generic text into raw dictionaries.
3. `LogNormalizer` converts parsed dictionaries into `RaptorEvent` models.
4. `SigmaMatcher` enriches events with local ATT&CK technique matches and IoC scores.
5. The RAG pipeline builds retrieval queries from events and Sigma matches.
6. `HybridRetriever` searches Weaviate `Technique` and `ThreatReport` collections when available, then falls back to local ATT&CK STIX/report-corpus search when Weaviate or embeddings are unavailable.
7. Reranking reduces retrieved context before the LLM prompt is assembled; if the cross-encoder cannot load, a deterministic lexical reranker is used.
8. OpenRouter LLM analysis produces structured findings when configured and reachable.
9. If the LLM path fails, deterministic Sigma fallback findings are generated.
10. Findings are validated against MITRE ATT&CK STIX.
11. `GraphBuilder` writes investigation-scoped nodes and edges to Neo4j when available.
12. If Neo4j is down, the backend still returns an in-memory graph export.
13. APT attribution is scored from observed TTP overlap against STIX-derived APT profiles.
14. The report generator creates a markdown analyst report, with deterministic fallback.
15. SQLite stores status, durable job claims, findings, attack sequence, attribution, graph JSON, report markdown, evidence metadata, server-side sessions, tenants, users, and hash-chained audit entries.

## Backend API

Base URL:

```text
http://localhost:8000/api/v1
```

When `RAPTOR_API_KEY` is set, service clients can include `X-RAPTOR-API-Key: <key>` or `Authorization: Bearer <key>`. Browser sessions should call `POST /api/v1/auth/session` with either an API key or username/password credentials; the backend creates a server-side session record and sets an HttpOnly `raptor_session` cookie. If no valid API key or session is supplied and `RAPTOR_ALLOW_AUTH_DISABLED=false`, protected API routes return `401` instead of silently disabling auth. `/api/v1/health` can remain unauthenticated when `RAPTOR_AUTH_EXEMPT_HEALTH=true`.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/auth/session` | Establish an HttpOnly browser session from an API key or username/password credentials. |
| `GET` | `/auth/me` | Return the authenticated actor, roles, and tenant. |
| `POST` | `/auth/logout` | Revoke the current server-side browser session. |
| `POST` | `/investigate` | Upload a log file and queue an investigation job. |
| `POST` | `/investigate/text` | Queue an investigation from pasted logs or an Elasticsearch query. |
| `GET` | `/investigations` | List recent investigation jobs from SQLite. |
| `GET` | `/investigate/{id}/status` | Poll job progress and current phase. |
| `GET` | `/investigate/{id}/report` | Fetch findings, sequence, anomalies, attribution, and report markdown. |
| `GET` | `/investigate/{id}/graph` | Fetch graph JSON suitable for graph renderers. |
| `GET` | `/investigate/{id}/evidence` | List persisted raw evidence metadata for an investigation. |
| `POST` | `/simulate` | Predict likely next steps for the selected or top attributed APT. |
| `POST` | `/query` | Ask a natural-language question for a completed investigation. |
| `GET` | `/apt/profiles` | List STIX-derived APT profiles and mapped technique counts. |
| `GET` | `/audit` | List recent append-only audit entries, optionally filtered by investigation. |
| `GET` | `/threat-feeds/cisa-kev` | Fetch/search the cached CISA KEV catalog. |
| `POST` | `/threat-feeds/cisa-kev/sync` | Force-refresh the CISA KEV cache. |
| `POST` | `/ingest/elasticsearch/poll` | Poll Elasticsearch once and queue matched events as an investigation. |
| `GET` | `/ingest/elasticsearch/status` | Return the interval poller state. |
| `GET` | `/health` | High-level service health. |
| `GET` | `/health/detailed` | Detailed subsystem health. |
| `GET` | `/metrics` | Prometheus-compatible request, auth, queue, and investigation counters. |

### Upload A Log File

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -F "file=@data/mock/apt29_campaign.json"
```

Example response:

```json
{
  "investigation_id": "2f6d4a6b-bc9f-49e7-9c61-5d6d5e4a44d8",
  "status": "queued",
  "message": "Investigation started. 12345 bytes of logs received."
}
```

### Start From Pasted Logs

```bash
curl -X POST http://localhost:8000/api/v1/investigate/text \
  -H "Content-Type: application/json" \
  -d '{
    "source": "paste",
    "log_content": "[{\"timestamp\":\"2026-04-25T10:00:00Z\",\"host\":\"WKSTN-01\",\"event_type\":\"process\",\"raw\":\"powershell.exe -enc SQBFAFgA\"}]"
  }'
```

### Start From Elasticsearch

```bash
curl -X POST http://localhost:8000/api/v1/investigate/text \
  -H "Content-Type: application/json" \
  -d '{
    "source": "elasticsearch",
    "elastic_query": "powershell OR mimikatz",
    "time_range_start": "now-24h",
    "time_range_end": "now"
  }'
```

The backend searches indices matching `raptor-events*` by default through `ELASTIC_INDEX_PREFIX`.

### Poll Status

```bash
curl http://localhost:8000/api/v1/investigate/<investigation_id>/status
```

### Fetch Report

```bash
curl http://localhost:8000/api/v1/investigate/<investigation_id>/report
```

### Fetch Graph

```bash
curl http://localhost:8000/api/v1/investigate/<investigation_id>/graph
```

### Run Simulation

```bash
curl -X POST http://localhost:8000/api/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{"investigation_id":"<investigation_id>"}'
```

Simulation is intentionally blocked when attribution confidence is `LOW` or `UNKNOWN`.

### Ask A Natural-Language Question

```bash
curl -X POST http://localhost:8000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "<investigation_id>",
    "question": "Which compromised hosts laterally moved toward the domain controller?"
  }'
```

Graph questions are restricted to read-only, investigation-scoped Cypher. RAG and simulation-style questions use retrieval context when available.

## Frontend Console

The frontend lives in `frontend/src/components/Dashboard.jsx`, calls the API through `frontend/src/api/raptorApi.js`, and uses styling from `frontend/src/index.css`.

Current frontend capabilities:

- Fixed full-viewport analyst shell with sidebar, top header, global search, status indicators, and toast messages.
- Mission dashboard with KPI cards, recent backend investigations, operational feed, kill-chain coverage, and live graph preview.
- Investigation list with filters and a real new-investigation composer for file upload, pasted logs, and Elasticsearch queries.
- Investigation detail workspace with tabs for attack graph, APT attribution, simulation, intelligence query, and forensic report.
- Interactive backend attack graph with selectable nodes and side-panel metadata.
- APT attribution view rendered from `GET /api/v1/investigate/{id}/report`.
- Simulation view that calls `POST /api/v1/simulate` and displays API errors when attribution confidence is too low.
- Intelligence query chat that calls `POST /api/v1/query`; there are no canned assistant responses.
- Forensic report view rendered from backend findings and narrative report markdown.
- APT library cards loaded from `GET /api/v1/apt/profiles`.
- MITRE ATT&CK matrix populated from selected investigation findings.
- Subsystem health page rendered from `GET /api/v1/health/detailed`, with CISA KEV catalog and Elasticsearch poller status panels.
- Report archive based on completed backend investigations with markdown download from the report API response.
- Settings page showing runtime API base and backend subsystem status.

The UI intentionally shows empty, loading, degraded, and error states when backend data or connectors are unavailable. It no longer imports or renders fabricated investigation data.

## Configuration

Copy `.env.example` to `.env` before running Docker or the backend locally.

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `nvidia` | Main OpenAI-compatible provider profile. Use `openrouter` to keep the legacy route. |
| `NVIDIA_API_KEY` | empty | NVIDIA NIM API key for live LLM calls. Fallback analysis works without it. |
| `NVIDIA_BASE_URL` | `https://integrate.api.nvidia.com/v1` | NVIDIA OpenAI-compatible API base URL. |
| `OPENROUTER_API_KEY` | empty | Legacy OpenRouter API key used when `LLM_PROVIDER=openrouter`. |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | OpenRouter-compatible API base URL. |
| `LLM_MODEL` | `z-ai/glm-5.1` | Primary model for analysis and generation. |
| `LLM_FALLBACK_MODEL` | `z-ai/glm-5.1` | Secondary model if the primary call fails. |
| `LLM_MAX_TOKENS` | `32768` | Maximum generated tokens for LLM requests. |
| `LLM_TEMPERATURE` | `1` | Sampling temperature for LLM requests. |
| `LLM_TOP_P` | `1` | Nucleus sampling value for LLM requests. |
| `LLM_TIMEOUT_SECONDS` | `30` | Timeout for LLM requests. |
| `LLM_STREAM_RESPONSES` | `true` | Streams chat completions and collects content while discarding reasoning chunks. |
| `LLM_ENABLE_THINKING` | `true` | Sends GLM chat-template thinking options for `z-ai/*` models. |
| `LLM_CLEAR_THINKING` | `false` | Controls the provider `clear_thinking` chat-template option. |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt connection string. |
| `NEO4J_USER` | `neo4j` | Neo4j username. |
| `NEO4J_PASSWORD` | `change_me_neo4j_password` | Local Neo4j password placeholder. Change before running shared environments. |
| `WEAVIATE_URL` | `http://localhost:8080` | Weaviate HTTP endpoint. |
| `WEAVIATE_GRPC_URL` | `localhost:50051` | Weaviate gRPC endpoint. |
| `WEAVIATE_API_KEY` | `change_me_weaviate_api_key` | API key used by the production overlay when Weaviate anonymous access is disabled. |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch endpoint for optional query-based investigations. |
| `ELASTIC_PASSWORD` | `change_me_elasticsearch_password` | Password for the production overlay Elasticsearch `elastic` user. |
| `ELASTIC_INDEX_PREFIX` | `raptor-events` | Elasticsearch index prefix searched by query and poller ingestion. |
| `ELASTIC_POLL_ENABLED` | `false` | Enables the interval poller when set to `true`. |
| `ELASTIC_POLL_QUERY` | `*` | Query string used by the interval poller. |
| `ELASTIC_POLL_INTERVAL_SECONDS` | `300` | Poller interval, with a 30 second minimum in the loop. |
| `ELASTIC_POLL_WINDOW_MINUTES` | `5` | Relative lookback window used by the poller. |
| `REDIS_URL` | `redis://localhost:6379` | Redis endpoint for health and lightweight JSON cache. |
| `REDIS_CACHE_TTL_SECONDS` | `3600` | TTL for Redis-cached connector payloads. |
| `CISA_KEV_URL` | CISA public JSON feed | CISA Known Exploited Vulnerabilities source URL. |
| `API_HOST` | `0.0.0.0` | Backend bind host. |
| `API_PORT` | `8000` | Backend port. |
| `FRONTEND_PORT` | `3100` | Frontend port. |
| `LOCAL_BIND_ADDRESS` | `127.0.0.1` | Host address Docker Compose publishes service ports on. |
| `RAPTOR_ENV` | `development` | Set to `production` to enable fail-fast startup validation for unsafe lab defaults. |
| `RAPTOR_PROCESS_ROLE` | `all` | Use `api` for the web process and `worker` for the background job process in production. |
| `RAPTOR_API_KEY` | `change_me_raptor_api_key` in `.env.example` | Enables service API-key authentication when non-empty. |
| `RAPTOR_AUTH_EXEMPT_HEALTH` | `true` | Leaves `/api/v1/health` public when API-key auth is enabled. |
| `RAPTOR_ALLOW_AUTH_DISABLED` | `false` | Allows protected API routes without auth only when explicitly set to `true` for local development. |
| `RAPTOR_REQUIRE_RBAC` | `true` | Enforces endpoint role checks, tenant scoping, and case ownership. |
| `RAPTOR_RATE_LIMIT_BACKEND` | `memory` | Rate-limit backend: `memory` for local development, `redis` for production multi-process deployments. |
| `RAPTOR_TRUSTED_SSO_ENABLED` | `false` | Trust identity headers from an authenticated ingress or identity-aware proxy. |
| `RAPTOR_TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | CIDR allowlist for proxies permitted to assert SSO headers. |
| `RAPTOR_SSO_USER_HEADER` | `x-forwarded-user` | Header containing the authenticated user from trusted ingress. |
| `RAPTOR_SSO_ROLES_HEADER` | `x-forwarded-roles` | Header containing comma/space-separated `viewer`, `analyst`, or `admin` roles. |
| `RAPTOR_SSO_TENANT_HEADER` | `x-forwarded-tenant` | Header containing the tenant identifier from trusted ingress. |
| `RAPTOR_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Local bootstrap admin username created during database initialization when a password is set. |
| `RAPTOR_BOOTSTRAP_ADMIN_PASSWORD` | empty | Bootstrap admin password. Set a strong value before creating the runtime database. |
| `RAPTOR_AUTH_MAX_FAILURES` | `5` | Failed login count before temporary lockout. |
| `RAPTOR_AUTH_LOCK_SECONDS` | `300` | Login lockout duration in seconds. |
| `RAPTOR_SESSION_COOKIE_SECURE` | `false` | Set to `true` behind HTTPS so browser session cookies require TLS. |
| `RAPTOR_ALLOW_EXTERNAL_LLM` | `false` | Allows telemetry to leave the deployment for OpenRouter-compatible LLM calls only when explicitly enabled. |
| `VITE_API_BASE_URL` | `/api/v1` | Optional frontend API base override for local or remote deployments. |
| `MAX_UPLOAD_BYTES` | `10485760` | Maximum upload or pasted input size. |
| `CORS_ALLOW_ORIGINS` | localhost frontend origins | Browser origins allowed by FastAPI CORS. |
| `CORS_ALLOW_CREDENTIALS` | `true` | CORS credential behavior. |
| `CSRF_TRUSTED_ORIGINS` | localhost frontend origins | Origins/Referers trusted for browser-session mutating API requests. |
| `RAPTOR_DB_ENGINE` | `sqlite` | Runtime metadata database backend: `sqlite` for local development, `postgresql` for production. |
| `RAPTOR_DATABASE_URL` | empty | PostgreSQL connection URL used when `RAPTOR_DB_ENGINE=postgresql`. |
| `RAPTOR_DB_PATH` | `data/raptor.db` | SQLite runtime database path for local job state and investigation results. |
| `RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS` | `false` | Must be set to `true` only when deliberately running SQLite in production. The production compose overlay uses PostgreSQL instead. |
| `EVIDENCE_ENCRYPTION_KEY` | empty | Base64 or raw key used for AES-256-GCM evidence encryption. Must be set for production. |
| `EVIDENCE_RETENTION_DAYS` | `90` | Retention window recorded for evidence metadata and operational cleanup. |
| `RAG_AUTO_INDEX` | `false` | When explicitly enabled, attempts one-time Weaviate indexing if required collections are missing. Leave disabled on request-serving deployments and run indexing as an operational setup task. |
| `RAG_LOCAL_FALLBACK_ENABLED` | `true` | Uses cached ATT&CK STIX and local report files when Weaviate or embeddings are unavailable. |
| `EMBEDDING_MODEL` | `BAAI/bge-large-en-v1.5` | Sentence-transformers embedding model for Weaviate vector search and indexing. |
| `RERANKER_MODEL` | `BAAI/bge-reranker-large` | Sentence-transformers cross-encoder reranker model. |
| `APT_REPORTS_DIR` | `data/intel/apt_reports` | Optional local threat-report corpus directory (`.txt`, `.md`, `.json`, `.jsonl`) used for RAG report context. |
| `RAPTOR_ALLOW_TEST_EMBEDDINGS` | `false` | Enables deterministic non-semantic embeddings for test-only fallback. |

Docker Compose overrides service URLs inside the backend container so it can reach `neo4j`, `weaviate`, `elasticsearch`, and `redis` by service name.

Backend containers install from `backend/requirements.lock` for reproducible builds, pin the CPU Torch wheel path to avoid accidental CUDA payloads, and run `pip check` during image/CI dependency installation. CI also runs a PostgreSQL-backed runtime metadata integration test. Review and refresh that lock file deliberately after dependency scanning.

## Data

Included mock investigations:

- `data/mock/apt29_campaign.json`
- `data/mock/hafnium_exchange.json`

Included or generated knowledge data:

- `data/stix/enterprise-attack.json`

If the STIX bundle is missing, the backend can download the MITRE Enterprise ATT&CK bundle during profile loading or indexing.

Runtime state:

- `data/raptor.db` is created locally by the backend and stores investigation job state, queued jobs, users, sessions, audit entries, and results.
- `data/evidence/{investigation_id}/` stores uploaded or ingested evidence bytes. When `EVIDENCE_ENCRYPTION_KEY` is set, the backend stores encrypted evidence blobs and records retention metadata.
- `data/intel/cisa_kev.json` stores the file-cache copy of the CISA KEV catalog.
- Docker named volumes store Neo4j, Weaviate, Elasticsearch, and Redis data.

Treat runtime databases, cached intelligence, and uploaded logs as sensitive investigation artifacts.

## Production Operations

RAPTOR includes baseline operational artifacts for teams running beyond a private workstation:

| Area | Artifact |
|---|---|
| Release validation | `Makefile` targets: `make validate`, `make security-scan`, `make compose-config` |
| Metrics and alerts | `observability/prometheus-rules.yml` and `/api/v1/metrics` |
| Dashboard seed | `observability/grafana-dashboard.json` |
| Observability runbook | `docs/observability.md` |
| Backup and restore | `scripts/ops/backup.sh`, `scripts/ops/restore.sh` |
| Audit integrity | `scripts/ops/verify_audit_chain.py` |
| Audit export | `scripts/ops/export_audit_log.py` |
| Evidence retention | `scripts/ops/cleanup_expired_evidence.py` |
| Evidence key rotation | `scripts/ops/rotate_evidence_key.py` |
| Schema status | `scripts/ops/schema_status.py` |
| Smoke/load drill | `scripts/ops/smoke_load.py` |

Recommended release gate:

```bash
make validate
make security-scan
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
```

Recommended recurring drills:

```bash
# Verify a backup copy of the audit chain
python scripts/ops/verify_audit_chain.py --db data/raptor.db

# Export audit records to JSONL for immutable storage
python scripts/ops/export_audit_log.py --db data/raptor.db --out exports/audit-log.jsonl

# Preview expired evidence cleanup before approval
python scripts/ops/cleanup_expired_evidence.py --db data/raptor.db

# Check recorded runtime schema migrations
python scripts/ops/schema_status.py --db data/raptor.db

# Run a lightweight health smoke/load probe against a running backend
python scripts/ops/smoke_load.py --base-url http://127.0.0.1:8000/api/v1

# Back up local runtime artifacts
scripts/ops/backup.sh backups/$(date -u +%Y%m%dT%H%M%SZ)
```

For production PostgreSQL deployments, pair these filesystem helpers with a `pg_dump`/restore workflow and run restore drills in an isolated environment before relying on backups.

## Testing And Verification

Convenience targets:

```bash
make setup
make validate
make security-scan
```

`make validate` runs backend tests, the frontend production build, and production Compose config validation. `make security-scan` runs local dependency audits when `pip-audit` and npm dependencies are installed.

Top-level offline regression suite:

```bash
python -m unittest discover -s tests
```

Backend-local regression tests:

```bash
python -m unittest discover -s backend/tests
```

Backend syntax check:

```bash
python -m compileall -q backend
```

Frontend build:

```bash
cd frontend
npm install
npm run build
```

Docker Compose validation:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
```

Health check after startup:

```bash
curl http://localhost:8000/api/v1/health/detailed
```

## Security Notes

- Do not commit `.env`; it may contain API keys.
- Replace the `.env.example` placeholder values before using the stack beyond local development.
- Docker Compose publishes service ports on `127.0.0.1` by default. Keep that binding for local work, or run with `docker-compose.prod.yml` behind a TLS-terminating ingress.
- Tighten `CORS_ALLOW_ORIGINS` for any non-local deployment.
- Production mode disables public OpenAPI docs, requires non-placeholder secrets, requires secure cookies, and refuses unsafe lab defaults.
- The backend emits a Content Security Policy and redacts detailed subsystem health for non-admin/service users.
- CI includes dependency scanning, secret scanning, filesystem scanning, and container scanning. Treat failures as release blockers unless explicitly risk-accepted.
- In-process rate limiting is a defensive guardrail. Put ingress-level or Redis-backed rate limiting in front of multi-node deployments.
- Set `RAPTOR_RATE_LIMIT_BACKEND=redis` in production so limits are shared across API processes; keep ingress-level limits as defense in depth.
- Trusted SSO headers are accepted only when `RAPTOR_TRUSTED_SSO_ENABLED=true` and the request source matches `RAPTOR_TRUSTED_PROXY_CIDRS`; never expose those headers directly to clients.
- Evidence API responses expose metadata, not internal filesystem paths. Do not add raw evidence download endpoints without explicit entitlement and audit requirements.
- Use bootstrap credentials only to create the first administrator, then rotate secrets and issue named operator accounts through the database-backed identity model.
- Do not embed API keys into frontend builds. The React console uses an HttpOnly session cookie created at runtime.
- Audit logging is append-only at the SQLite table level and hash-chained per entry. Export audit records to immutable external storage when regulatory retention requires out-of-process custody.
- The graph natural-language query path uses deterministic allowlisted handlers for Neo4j access and investigation scoping.
- External LLM calls are disabled unless `RAPTOR_ALLOW_EXTERNAL_LLM=true`; prompts redact common secrets before provider submission.
- LLM output is validated and has fallbacks, but attribution and simulation should be treated as analyst-supporting evidence, not automatic truth.
- Uploaded telemetry can contain credentials, hostnames, usernames, IP addresses, file paths, and other sensitive data.
- Read `docs/production-runbook.md`, `docs/observability.md`, `docs/threat-model.md`, `docs/data-governance.md`, and `docs/scaling-limits.md` before operating the stack outside a private workstation.

## Roadmap

Likely next engineering steps:

- Add end-to-end browser tests for the live API-backed console.
- Add identity-provider federation for SSO environments that already standardize on OIDC or SAML.
- Add a PostgreSQL-backed metadata store and object-storage evidence backend for multi-node deployments.
- Add MISP, OpenCTI, and additional threat-feed connectors.
- Add streaming Elasticsearch checkpoints, deduplication, and replay controls.
- Add report export to PDF or DOCX.
- Add frontend component, accessibility, and API integration tests.
- Add Helm or Kubernetes manifests for teams that do not deploy with Compose.
- Refactor `backend/main.py` into routers/services/repositories and split `Dashboard.jsx` into feature components/hooks.
- Replace local filesystem evidence storage with object storage and KMS for regulated multi-node deployments.

## License

No license file is currently included in this repository. Treat the code as private unless a license is added.
