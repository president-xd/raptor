# RAPTOR Scaling Limits

## Current Safe Operating Envelope

- Separate backend API and worker processes are supported by `RAPTOR_PROCESS_ROLE`.
- SQLite-backed runtime metadata for local development; PostgreSQL-backed runtime metadata for production.
- Local or mounted evidence filesystem.
- Docker Compose infrastructure.

This supports controlled production deployments with cleaner process isolation. Before multi-node use, keep PostgreSQL as the metadata layer and move evidence to object storage.

## Known Bottlenecks

- LLM/RAG analysis is CPU/network intensive and processed by worker threads in the worker process.
- Embedding and reranking model loading can consume significant memory.
- SQLite write concurrency is bounded even with WAL. Do not run multiple API/worker hosts against the same SQLite file.
- PostgreSQL removes the embedded database concurrency limit, but evidence still defaults to a local or mounted filesystem.
- Large evidence files are loaded into memory up to `MAX_UPLOAD_BYTES`.

## Production Expansion Path

1. Replace local evidence paths with S3-compatible object storage and KMS.
2. Run multiple worker containers against PostgreSQL after sizing queue throughput.
3. Add database migration tooling for future schema changes.
4. Add Prometheus scraping of `/api/v1/metrics`.
5. Add ingress-level rate limiting, WAF rules, and SSO.
6. Add queue-depth, worker-latency, parser-error, and investigation-failure alerts.
