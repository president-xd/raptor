# RAPTOR Changelog

## [1.4.0] - 2026-04-29

### Added
- Added production startup guardrails for unsafe defaults, process roles, database engine selection, and SQLite production acknowledgement.
- Added PostgreSQL runtime metadata support with adapter translation, worker entrypoint, and a production compose overlay that provisions postgres and a worker service.
- Added CSRF trusted origin checks for session-authenticated mutations, security headers, and request ID tracing.
- Added AES-256-GCM evidence encryption with key identifiers and a decrypt helper.
- Added CI workflow with backend tests, frontend build plus Playwright e2e, compose validation, and a PostgreSQL integration test.
- Added Playwright configuration and dashboard e2e coverage.

### Changed
- Updated metrics to emit request latency and status counters; health now reports a database subsystem with backend type.
- Updated evidence metadata and access controls for audit log, threat feeds, and Elasticsearch poll endpoints.
- Updated README and operational docs for production hardening, worker separation, CSRF safeguards, and PostgreSQL runtime metadata.
- Updated frontend subsystem display to show Database instead of SQLite.
- Updated backend dependency locks, including CPU Torch wheels, PostgreSQL driver, and cryptography.

### Fixed
- Fixed Elasticsearch poll de-duplication to avoid duplicate inserts while tracking last-seen timestamps.

## [1.3.0] - 2026-04-25

### Added
- Added `/api/v1/investigations` endpoint for recent case listing.
- Added `/api/v1/health/detailed` endpoint with subsystem-level health for API, SQLite, Neo4j, Weaviate, and LLM config readiness.
- Added upload guardrails for `/api/v1/investigate` (empty file rejection and max file size enforcement).
- Added environment controls: `LLM_TIMEOUT_SECONDS`, `MAX_UPLOAD_BYTES`, `CORS_ALLOW_ORIGINS`, `CORS_ALLOW_CREDENTIALS`, `RAG_AUTO_INDEX`, and `RAPTOR_ALLOW_TEST_EMBEDDINGS`.
- Added simulation confidence gating: simulation is blocked for LOW/UNKNOWN attribution confidence.

### Changed
- Hardened graph persistence to scope Host/User/Technique merges by `investigation_id`.
- Hardened NLQ graph query execution with read-only query sanitization and investigation scoping enforcement.
- Updated Weaviate container to `semitechnologies/weaviate:1.27.6` for compatibility with `weaviate-client>=4.4.0`.
- Enabled `sentence-transformers` as a required backend dependency for embeddings/reranking.
- Improved frontend operations UX with detailed subsystem status pills and recent investigation list loading.

### Fixed
- Fixed JSON parsing where `null` destination values could become string values and create fake graph hosts.
- Fixed parser behavior to preserve producer-provided `event_type` when present.
- Fixed stale host compromise state in graph export by refreshing host state from Neo4j before frontend graph serialization.
- Fixed compromised-host metric rendering to show `0` when hosts exist but none are compromised.
- Fixed attack graph instability by using deterministic backend coordinates and preserving provided layout on the frontend.
- Fixed attack graph hover highlighting behavior by removing stale state closure from Sigma reducers.
- Fixed long LLM stall behavior by adding explicit request timeout controls.
- Fixed unsafe embedding fallback behavior by removing random vectors in production mode.

## [1.2.0] - 2026-04-25

### Added
- Converted the frontend into a SOC-style analyst console inspired by the provided standalone UI reference.
- Added left navigation, top operations bar, dashboard metrics, investigation tabs, APT library, threat-feed view, MITRE matrix view, settings page, and persistent last-investigation loading.
- Added Nginx frontend container config so Docker deployments proxy `/api/*` to the backend service.
- Added `.env.example` and `.gitignore`.
- Added deterministic Sigma fallback analysis when LLM analysis fails or returns no findings.
- Added deterministic report and simulation fallbacks when LLM calls fail.

### Changed
- Updated frontend palette, typography, spacing, and component styling to match the standalone UI direction.
- Updated frontend API client to support `VITE_API_BASE_URL` while defaulting to `/api/v1`.
- Replaced Node static serving in the frontend image with Nginx.
- Removed `.env` from backend Docker image build context usage.
- Updated README to reflect the actual ports, Docker behavior, fallbacks, and implemented features.

### Fixed
- Fixed the Docker frontend API path problem by proxying `/api`.
- Fixed graph node details by reading `node_type` from Sigma.js node attributes.
- Fixed simulation host context extraction from stored graph JSON.
- Split frontend production bundles into React, graph, reporting, and chart chunks.

## [1.1.0] - 2026-04-23

### Added
- Dockerfiles for backend and frontend.
- Docker Compose deployment with infrastructure and app services.
- Service health checks for infrastructure and backend.
- README, Docker startup scripts, and runtime configuration.

### Changed
- Standardized frontend port on `3100`.
- Added `WEAVIATE_GRPC_URL` and `FRONTEND_PORT` environment variables.

## [1.0.0] - 2026-04-23

### Added
- Initial FastAPI backend and React dashboard.
- Log ingestion, Sigma matching, RAG pipeline, graph builder, attribution scoring, simulation, NLQ, and report generation modules.
