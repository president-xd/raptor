# RAPTOR Threat Model

## Assets

- Uploaded telemetry and raw evidence.
- Investigation results, reports, attribution, and graph data.
- API/session credentials.
- LLM prompts and retrieved context.
- Audit log and parser dead-letter records.

## Trust Boundaries

- Browser to frontend.
- Frontend proxy to backend API.
- Backend to SQLite runtime database and evidence filesystem.
- Backend to Neo4j, Weaviate, Elasticsearch, Redis, CISA KEV, and OpenRouter-compatible LLM providers.
- Local Docker host to container network.

## Main Threats And Controls

| Threat | Control |
|---|---|
| Unauthorized case access | RBAC, tenant metadata, case ownership metadata, API/session enforcement |
| Session theft | HttpOnly cookies, server-side session store, revocation, secure-cookie production setting |
| Browser CSRF against session-authenticated users | Trusted Origin/Referer enforcement on mutating API routes |
| Evidence disclosure | AES-256-GCM evidence encryption, retention metadata, runtime artifact ignores, production backup controls |
| Prompt or telemetry leakage | External LLM disabled by default, telemetry redaction before prompts |
| Generated graph-query abuse | Allowlisted deterministic graph queries, regex sanitizer retained only as defense-in-depth utility |
| Audit tampering | Append-only triggers plus hash chaining |
| Worker loss | Durable `job_queue`, retry state, stale-lock recovery |
| Infrastructure exposure | Localhost-bound compose defaults, production overlay removes infrastructure ports |
| Vulnerable dependencies or images | CI dependency audit, npm audit, Trivy filesystem/container scans |
| Secret leakage in repository | Gitleaks secret scan in CI and local artifact ignores |
| Retention overrun | Evidence retention metadata plus `scripts/ops/cleanup_expired_evidence.py` |
| Backup tampering | Backup checksums plus audit-chain verification before export |

## Residual Risks

- SQLite is still a single-node embedded database. Use a managed relational database adapter before horizontally scaling backend workers.
- Evidence encryption is application-managed. Use KMS-backed object storage for regulated environments and centralized key rotation.
- Local bootstrap users are suitable for controlled deployments; large enterprises should integrate SSO/OIDC at the ingress or API layer.
- In-memory API rate limits are a single-process guardrail. Put production ingress or Redis-backed rate limiting in front of horizontally scaled deployments.
- Local filesystem evidence storage is acceptable for controlled single-node or mounted-volume deployments. Regulated multi-node deployments should use object storage and KMS.
