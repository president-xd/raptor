# RAPTOR Changelog

## [Unreleased]

### Added
- Added a GitHub Actions CI pipeline (`.github/workflows/ci.yml`): backend tests, a PostgreSQL integration job against a live `postgres:16` service, frontend build, Playwright e2e, production compose validation, dependency audit (pip-audit + npm audit), Gitleaks secret scanning, and Trivy filesystem and container image scans.
- Added a release pipeline (`.github/workflows/release.yml`) that builds and publishes backend and frontend images to GHCR, scans the published digests with Trivy, and signs them with Cosign keyless (Sigstore / OIDC).

### Changed
- Rewrote `README.md` for accuracy, including an explicit project-status table, and aligned the operational docs with what the repository actually ships.
- CI now runs `pip check` to verify installed dependency consistency.
- Documentation now describes simulation as confidence-aware (predictions de-prioritised at LOW/UNKNOWN attribution) instead of hard-blocked, matching actual behaviour.

### Security
- Tenant-scoped user management: ordinary `admin` accounts can now only create, read, update, or delete users within their own tenant; only the `service` principal manages users across all tenants. Closes a cross-tenant account-takeover gap.
- Password resets and account disables now revoke the target user's active sessions.
- Audit-chain appends are serialised across processes (SQLite `BEGIN IMMEDIATE` / PostgreSQL transaction-scoped advisory lock), preventing a forked hash chain when separate API and worker processes write concurrently.
- `/api/v1/metrics` now requires the `admin` role (was `viewer`), matching the documented contract.
- Constant-time authentication: the unknown/disabled-user path now performs a dummy PBKDF2 to remove a username-enumeration timing oracle.
- Production startup now rejects a `CORS_ALLOW_ORIGINS=*` + credentials combination and a weak `EVIDENCE_ENCRYPTION_KEY`.
- `LocalStorage.write` now rejects keys that escape the evidence base directory (defense in depth).
- Redis rate-limit keys always assert a TTL with `EXPIRE ... NX`, so a lost `EXPIRE` after a crash can no longer wedge a client indefinitely.

### Fixed
- Fixed a failing report test that still asserted the pre-redesign report header, which left the offline suite red.
- The report-view upgrade path again populates affected hosts/users/processes (derived from persisted graph nodes) after evidence summaries stopped carrying raw JSON.
- Stopped embedding raw log content in deterministic evidence summaries, which previously leaked raw JSON into on-screen reports and Markdown/PDF exports.
- Report scope (affected hosts, observed users, observed processes) is now derived from structured event data instead of fragile regex scraping of evidence text, so those fields populate reliably.
- Wired the previously inert temporal-sequence signal into attribution confidence scoring (the `+0.10` bonus now applies when the observed technique order progresses through the ATT&CK kill chain).
- Removed emoji from the attribution summary helper output.

### Removed
- Removed stale build artifacts: a leftover test database, an empty `backend/tests` directory, and stray `__pycache__` directories.
- Removed the unused `backend/ingestion/mock_generator.py` module (no importers).

## [1.4.0] - 2026-04-29

### Added
- Added production startup guardrails for unsafe defaults, process roles, database engine selection, and SQLite production acknowledgement.
- Added PostgreSQL runtime metadata support with adapter translation, worker entrypoint, and a production compose overlay that provisions postgres and a worker service.
- Added CSRF trusted origin checks for session-authenticated mutations, security headers, and request ID tracing.
- Added AES-256-GCM evidence encryption with key identifiers and a decrypt helper.
- Added `Makefile` quality gates (`make validate`, `make security-scan`, `make compose-config`) covering backend tests, frontend build, dependency audit, and production compose validation, plus a PostgreSQL integration test.
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
