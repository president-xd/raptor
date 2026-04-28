# RAPTOR Scaling Limits

## Current Safe Operating Envelope

- Single backend API process with one durable worker loop.
- SQLite-backed runtime metadata.
- Local or mounted evidence filesystem.
- Docker Compose infrastructure.

This supports controlled single-node deployments. Before multi-node use, replace the metadata layer with PostgreSQL or another transactional database and move evidence to object storage.

## Known Bottlenecks

- LLM/RAG analysis is CPU/network intensive and currently processed by backend worker threads.
- Embedding and reranking model loading can consume significant memory.
- SQLite write concurrency is bounded even with WAL.
- Large evidence files are loaded into memory up to `MAX_UPLOAD_BYTES`.

## Production Expansion Path

1. Externalize metadata to PostgreSQL.
2. Replace local evidence paths with S3-compatible object storage and KMS.
3. Run worker containers separately from API containers.
4. Add Prometheus scraping of `/api/v1/metrics`.
5. Add ingress-level rate limiting, WAF rules, and SSO.
6. Add queue-depth, worker-latency, parser-error, and investigation-failure alerts.
