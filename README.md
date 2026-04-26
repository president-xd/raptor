# 🦅 RAPTOR

Retrieval-Augmented Persistent Threat Orchestration and Reasoning

RAPTOR is an MVP cybersecurity investigation platform for turning security telemetry into ATT&CK-mapped findings, attack graphs, attribution candidates, analyst reports, and next-step adversary predictions. It combines a FastAPI backend, local Sigma-style detections, MITRE ATT&CK STIX data, optional RAG over Weaviate, Neo4j graph persistence, OpenRouter-compatible LLM calls, and a React/Vite SOC console.

This repository is now wired as one live application:

- The backend investigation API ingests logs, runs the analysis pipeline, persists job state in SQLite, and exposes reports, graphs, attribution, simulation, APT profiles, health, and natural-language query endpoints.
- The React console calls the backend through `frontend/src/api/raptorApi.js`. The investigation queue, new-ingestion workflow, report preview/download, graph view, attribution view, simulation, intelligence query, APT library, MITRE view, and subsystem health screens are API-backed rather than fabricated local data.

## Current Status

RAPTOR is a functional MVP, not a production SIEM, case-management system, or fully integrated enterprise product.

Implemented today:

- Multi-format log ingestion for JSON, newline JSON, XML Windows events, CEF, and generic text logs.
- File-upload investigations through `POST /api/v1/investigate`.
- Pasted-log and Elasticsearch-query investigations through `POST /api/v1/investigate/text`.
- Normalized event schema with timestamps, hosts, IPs, event type, raw evidence, Sigma matches, and preliminary IoC score.
- Local Sigma-style detection signatures mapped to MITRE ATT&CK technique IDs.
- RAG-oriented analysis pipeline that retrieves ATT&CK and threat-report context from Weaviate when available.
- OpenRouter-compatible LLM analysis with fallback model support.
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
- Detailed health endpoint for API, SQLite, Neo4j, Weaviate, Elasticsearch, Redis, and LLM configuration.
- React SOC console backed by the API for investigation creation, polling, reports, graphs, attribution, simulation, natural-language query, APT profiles, MITRE findings, report download, and subsystem health.
- Investigation metadata in the backend list API, including case name, source, upload size, host count, top candidate, confidence score, and confidence label.
- Docker Compose stack for backend, frontend, Neo4j, Weaviate, Elasticsearch, and Redis.
- Windows and Linux helper scripts for Docker and hybrid local runs.
- Regression tests for parser behavior, graph scoping/export, and natural-language query safety guards.

Not implemented or only partially implemented:

- MISP, OpenCTI, CISA KEV, and threat-feed syncing are not active backend connectors. The former feed mockup was replaced with real subsystem health.
- Elasticsearch can be queried as an investigation source, but RAPTOR does not continuously ingest from Elasticsearch.
- Redis is provisioned and health-checked, but it is not currently used as a queue, cache, or pub/sub layer.
- There is no authentication, authorization, RBAC, audit logging, or multi-user case workflow.
- SQLite is used for MVP job state. It is not a production-grade shared case database.
- There is no persistent uploaded-file evidence store beyond the normalized results saved in SQLite.
- The Docker credentials and open service defaults are suitable for local development only.

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
| Runtime service | Redis 7, currently health/provisioning only |
| LLM client | OpenAI SDK against OpenRouter-compatible API |
| Embeddings | `BAAI/bge-large-en-v1.5` through `sentence-transformers` |
| Reranking | BGE cross-encoder reranker with score fallback |
| Threat framework | MITRE Enterprise ATT&CK STIX |
| Frontend | React 18, Vite 5, Tailwind CSS, lucide-react |
| Frontend serving | Vite in development, Nginx in Docker |
| Deployment | Docker Compose plus optional local hybrid scripts |

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
|-- scripts/
|   |-- docker/                    # Full Docker launch helpers
|   `-- hybrid/                    # Docker infrastructure plus local app helpers
|-- docker-compose.yml
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
| Redis | `localhost:6379` | Provisioned service, health checked |

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

2. Edit `.env` and set `OPENROUTER_API_KEY` if you want live LLM calls.

3. Start the stack.

```bash
docker compose up -d --build
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

4. Open `http://localhost:3100`.

Hybrid helper scripts are available:

```powershell
.\scripts\hybrid\install_windows.ps1
```

```bash
bash scripts/hybrid/install_linux.sh
```

## Backend Pipeline

The main orchestration lives in `backend/main.py`.

1. The API receives uploaded logs, pasted logs, or Elasticsearch results.
2. `LogParser` parses JSON, XML Windows events, CEF, or generic text into raw dictionaries.
3. `LogNormalizer` converts parsed dictionaries into `RaptorEvent` models.
4. `SigmaMatcher` enriches events with local ATT&CK technique matches and IoC scores.
5. The RAG pipeline builds retrieval queries from events and Sigma matches.
6. `HybridRetriever` searches Weaviate `Technique` and `ThreatReport` collections when available.
7. Reranking reduces retrieved context before the LLM prompt is assembled.
8. OpenRouter LLM analysis produces structured findings when configured and reachable.
9. If the LLM path fails, deterministic Sigma fallback findings are generated.
10. Findings are validated against MITRE ATT&CK STIX.
11. `GraphBuilder` writes investigation-scoped nodes and edges to Neo4j when available.
12. If Neo4j is down, the backend still returns an in-memory graph export.
13. APT attribution is scored from observed TTP overlap against STIX-derived APT profiles.
14. The report generator creates a markdown analyst report, with deterministic fallback.
15. SQLite stores status, findings, attack sequence, attribution, graph JSON, and report markdown.

## Backend API

Base URL:

```text
http://localhost:8000/api/v1
```

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/investigate` | Upload a log file and start a background investigation. |
| `POST` | `/investigate/text` | Start an investigation from pasted logs or an Elasticsearch query. |
| `GET` | `/investigations` | List recent investigation jobs from SQLite. |
| `GET` | `/investigate/{id}/status` | Poll job progress and current phase. |
| `GET` | `/investigate/{id}/report` | Fetch findings, sequence, anomalies, attribution, and report markdown. |
| `GET` | `/investigate/{id}/graph` | Fetch graph JSON suitable for graph renderers. |
| `POST` | `/simulate` | Predict likely next steps for the selected or top attributed APT. |
| `POST` | `/query` | Ask a natural-language question for a completed investigation. |
| `GET` | `/apt/profiles` | List STIX-derived APT profiles and mapped technique counts. |
| `GET` | `/health` | High-level service health. |
| `GET` | `/health/detailed` | Detailed subsystem health. |

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

The backend searches indices matching `raptor-*` by default.

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
- Subsystem health page rendered from `GET /api/v1/health/detailed`.
- Report archive based on completed backend investigations with markdown download from the report API response.
- Settings page showing runtime API base and backend subsystem status.

The UI intentionally shows empty, loading, degraded, and error states when backend data or connectors are unavailable. It no longer imports or renders fabricated investigation data.

## Configuration

Copy `.env.example` to `.env` before running Docker or the backend locally.

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | empty | Enables live LLM calls. Fallback analysis works without it. |
| `OPENROUTER_BASE_URL` | configured in `backend/config.py` | OpenRouter-compatible API base URL. |
| `LLM_MODEL` | `nvidia/nemotron-3-super-120b-a12b:free` | Primary model for analysis and generation. |
| `LLM_FALLBACK_MODEL` | `qwen/qwen3-coder:free` | Secondary model if the primary call fails. |
| `LLM_TIMEOUT_SECONDS` | `30` | Timeout for LLM requests. |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt connection string. |
| `NEO4J_USER` | `neo4j` | Neo4j username. |
| `NEO4J_PASSWORD` | `raptor_secret_2024` | Local development password. Change for real deployments. |
| `WEAVIATE_URL` | `http://localhost:8080` | Weaviate HTTP endpoint. |
| `WEAVIATE_GRPC_URL` | `localhost:50051` | Weaviate gRPC endpoint. |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch endpoint for optional query-based investigations. |
| `REDIS_URL` | `redis://localhost:6379` | Redis health-check endpoint. |
| `API_HOST` | `0.0.0.0` | Backend bind host. |
| `API_PORT` | `8000` | Backend port. |
| `FRONTEND_PORT` | `3100` | Frontend port. |
| `VITE_API_BASE_URL` | `/api/v1` | Optional frontend API base override for local or remote deployments. |
| `MAX_UPLOAD_BYTES` | `10485760` | Maximum upload or pasted input size. |
| `CORS_ALLOW_ORIGINS` | localhost frontend origins | Browser origins allowed by FastAPI CORS. |
| `CORS_ALLOW_CREDENTIALS` | `true` | CORS credential behavior. |
| `RAG_AUTO_INDEX` | `true` | Attempts one-time Weaviate indexing if required collections are missing. |
| `RAPTOR_ALLOW_TEST_EMBEDDINGS` | `false` | Enables deterministic non-semantic embeddings for test-only fallback. |

Docker Compose overrides service URLs inside the backend container so it can reach `neo4j`, `weaviate`, `elasticsearch`, and `redis` by service name.

## Data

Included mock investigations:

- `data/mock/apt29_campaign.json`
- `data/mock/hafnium_exchange.json`

Included or generated knowledge data:

- `data/stix/enterprise-attack.json`

If the STIX bundle is missing, the backend can download the MITRE Enterprise ATT&CK bundle during profile loading or indexing.

Runtime state:

- `backend/raptor.db` is created locally by the backend and stores investigation job state and results.
- Docker named volumes store Neo4j, Weaviate, Elasticsearch, and Redis data.

Treat runtime databases and uploaded logs as sensitive investigation artifacts.

## Testing And Verification

Backend regression tests:

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
docker compose config --quiet
```

Health check after startup:

```bash
curl http://localhost:8000/api/v1/health/detailed
```

## Security Notes

- Do not commit `.env`; it may contain API keys.
- Replace default Neo4j credentials before using the stack beyond local development.
- Restrict exposed Docker ports in shared environments.
- Tighten `CORS_ALLOW_ORIGINS` for any non-local deployment.
- The backend does not currently provide authentication or authorization.
- The graph natural-language query path enforces read-only patterns and investigation scoping, but production deployments should still monitor and restrict generated-query behavior.
- LLM output is validated and has fallbacks, but attribution and simulation should be treated as analyst-supporting evidence, not automatic truth.
- Uploaded telemetry can contain credentials, hostnames, usernames, IP addresses, file paths, and other sensitive data.

## Roadmap

Likely next engineering steps:

- Add end-to-end browser tests for the live API-backed console.
- Add authentication, user roles, audit logging, and case ownership.
- Replace SQLite job state with a production database for multi-user deployments.
- Add real threat-feed connectors for MISP, OpenCTI, CISA KEV, or other sources.
- Add a durable evidence store for uploaded files and extracted artifacts.
- Add queued background workers instead of FastAPI in-process background tasks.
- Add report export to PDF or DOCX.
- Add frontend tests and API integration tests.
- Add deployment hardening for credentials, TLS, CORS, and service exposure.

## License

No license file is currently included in this repository. Treat the code as private unless a license is added.
