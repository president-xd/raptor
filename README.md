# RAPTOR

Retrieval-Augmented Persistent Threat Orchestration and Reasoning.

RAPTOR is a forensic and predictive APT analysis system. It accepts security logs, normalizes events, maps suspicious activity to MITRE ATT&CK techniques, builds an attack graph, scores likely APT attribution, generates an analyst report, and predicts likely next attacker steps.

## Current Status

This repository is an MVP implementation with a fully wired FastAPI backend and React/Vite analyst console.

Implemented:

- Multi-format log parsing for JSON, XML Windows events, CEF, and generic logs.
- Local Sigma-style ATT&CK technique matching.
- OpenRouter-backed LLM analysis with deterministic Sigma fallback when the LLM provider is unavailable.
- STIX validation against the cached MITRE Enterprise ATT&CK bundle.
- APT attribution using Jaccard similarity plus confidence penalties and bonuses.
- Neo4j graph writing when Neo4j is available, with in-memory graph export fallback.
- Investigation-scoped graph persistence and investigation-safe graph query execution.
- Detailed subsystem health telemetry (`/api/v1/health/detailed`) for API/UI degraded-mode visibility.
- Simulation confidence gate (simulation blocked for LOW/UNKNOWN attribution confidence).
- Upload guardrails (empty-file rejection and maximum upload size enforcement).
- React analyst console styled as a dense SOC workspace.
- Docker Compose for Neo4j, Weaviate, Elasticsearch, Redis, backend, and frontend.

Partially implemented / future work:

- Elasticsearch and Redis are provisioned but not yet central to the runtime pipeline.
- MISP/OpenCTI enrichment is represented in the UI/docs as planned work, not active ingestion.
- Full case management workflows (compare/reopen/delete/rerun) are still evolving.

## Ports

| Service | URL |
|---|---|
| Frontend console | http://localhost:3100 |
| API docs | http://localhost:8000/docs |
| API health | http://localhost:8000/api/v1/health |
| Neo4j browser | http://localhost:7474 |
| Weaviate | http://localhost:8080 |
| Elasticsearch | http://localhost:9200 |

## Quick Start: Docker

1. Copy the environment template.

```bash
cp .env.example .env
```

2. Edit `.env` and add `OPENROUTER_API_KEY` if you want LLM-powered reports and reasoning. Without a working key, RAPTOR still completes investigations using local Sigma fallback analysis.

3. Start the stack.

```bash
docker compose up -d --build
```

4. Open the console.

```text
http://localhost:3100
```

The Docker frontend uses Nginx and proxies `/api/*` to the backend service, so the React app can keep using relative API paths.

## Quick Start: Hybrid Local

Run infrastructure in Docker, backend and frontend locally.

```bash
docker compose up -d neo4j weaviate elasticsearch redis
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3100`.

## API

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/investigate` | Upload a log file and start analysis. |
| `GET` | `/investigations` | List recent investigations and statuses. |
| `GET` | `/investigate/{id}/status` | Poll job status and progress. |
| `GET` | `/investigate/{id}/report` | Fetch findings, attribution, sequence, and report markdown. |
| `GET` | `/investigate/{id}/graph` | Fetch Sigma.js-compatible graph JSON. |
| `POST` | `/simulate` | Predict likely next steps for the top attributed actor (requires MEDIUM/HIGH confidence). |
| `POST` | `/query` | Ask natural language questions for a completed investigation (read-only scoped Cypher). |
| `GET` | `/apt/profiles` | List APT profiles loaded from the cached STIX bundle. |
| `GET` | `/health` | Health check. |
| `GET` | `/health/detailed` | Detailed subsystem health (API, SQLite, Neo4j, Weaviate, LLM config). |

Example:

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -F "file=@data/mock/apt29_campaign.json"
```

## Frontend

The React console is implemented in `frontend/src/components/Dashboard.jsx` and follows the standalone UI reference as a normal Vite application. Static analyst-demo intelligence lives in `frontend/src/data/raptorDemo.js` so the UI can render fully without requiring backend seed data:

- Persistent left navigation.
- Top operations bar with subsystem status.
- Dense stat cards and investigation summary panels.
- Investigation tabs for attack graph, attribution, simulation, query, and forensic report.
- APT profile library.
- MITRE ATT&CK matrix view based on observed findings.
- Threat-feed/status workspace.

For local Vite development, `/api` is proxied to `http://127.0.0.1:8000`. For Docker, Nginx proxies `/api` to the backend container.

## Backend Pipeline

The main orchestration is in `backend/main.py`.

Pipeline stages:

1. Parse and normalize uploaded logs.
2. Match local Sigma-style detection signatures.
3. Retrieve RAG context when Weaviate is available.
4. Call the LLM through OpenRouter.
5. Fall back to local Sigma findings if the LLM fails or returns empty findings.
6. Validate technique IDs against MITRE ATT&CK STIX.
7. Build Neo4j graph or in-memory graph export.
8. Score APT attribution.
9. Generate LLM report or deterministic fallback report.

## Configuration

Copy `.env.example` to `.env`.

Important variables:

| Variable | Default | Notes |
|---|---|---|
| `OPENROUTER_API_KEY` | empty | Required for LLM calls. Fallback analysis works without it. |
| `LLM_MODEL` | `nvidia/nemotron-3-super-120b-a12b:free` | Primary OpenRouter model. |
| `LLM_FALLBACK_MODEL` | `qwen/qwen3-coder:free` | Fallback OpenRouter model. |
| `LLM_TIMEOUT_SECONDS` | `30` | Hard timeout for OpenRouter requests. |
| `NEO4J_URI` | `bolt://localhost:7687` | Use `bolt://neo4j:7687` inside Docker. |
| `WEAVIATE_URL` | `http://localhost:8080` | Use `http://weaviate:8080` inside Docker. |
| `RAG_AUTO_INDEX` | `true` | Runs one-time Weaviate bootstrap indexing when required collections are missing. |
| `RAPTOR_ALLOW_TEST_EMBEDDINGS` | `false` | Enables deterministic test embeddings when `sentence-transformers` is unavailable (non-production only). |
| `API_PORT` | `8000` | Backend API port. |
| `FRONTEND_PORT` | `3100` | Frontend console port. |
| `MAX_UPLOAD_BYTES` | `10485760` | Upload size limit enforced by `/investigate`. |
| `CORS_ALLOW_ORIGINS` | `http://localhost:3100,http://127.0.0.1:3100` | Allowed browser origins. |

## Data

Mock logs:

- `data/mock/apt29_campaign.json`
- `data/mock/hafnium_exchange.json`

Cached STIX bundle:

- `data/stix/enterprise-attack.json`

The number of APT profiles depends on the cached STIX bundle. The current local bundle loads 164 intrusion-set profiles with at least two mapped techniques.

## Verification

Useful checks:

```bash
cd frontend
npm run build
```

```bash
python -m compileall -q backend
```

```bash
docker compose config --quiet
```

## Security Notes

- Do not commit `.env`; it may contain API keys.
- Restrict `CORS_ALLOW_ORIGINS` and credentials policy appropriately before production deployment.
- Neo4j and Weaviate use development-friendly defaults in `docker-compose.yml`.
- Uploaded logs can contain sensitive data. Treat `backend/raptor.db` and generated logs as sensitive artifacts.
- The graph NLQ path enforces read-only query patterns and investigation scoping, but should still be monitored in production.
