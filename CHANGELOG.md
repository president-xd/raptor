# RAPTOR Changelog

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
