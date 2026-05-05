# RAPTOR Observability

## Metrics

The backend exposes Prometheus text metrics at `/api/v1/metrics`. Scrape it through the authenticated ingress or through an internal service account path. At minimum, alert on:

- API 5xx rate above 5% for 10 minutes.
- Authentication failure spikes.
- Any investigation failures in a 15 minute window.
- Parser error spikes.
- Average request latency above 2 seconds.

Reference alert rules live in `observability/prometheus-rules.yml` and a starter Grafana dashboard lives in `observability/grafana-dashboard.json`.

## Logs

RAPTOR writes structured request logs from the backend middleware. Production deployments should ship backend, worker, frontend, PostgreSQL, Neo4j, Weaviate, Elasticsearch, and Redis logs to centralized storage with retention aligned to the evidence data classification.

Recommended log retention:

- API/worker security logs: 180 days minimum.
- Investigation processing logs: match evidence retention.
- Infrastructure debug logs: 30 to 90 days.

## Operational Checks

Daily:

1. Review alert state and API error rate.
2. Confirm investigation queue is draining.
3. Confirm `parser_errors_total` is not spiking.
4. Confirm backups completed and checksums were generated.

Weekly:

1. Run `scripts/ops/verify_audit_chain.py` on a backup copy.
2. Restore the latest backup into an isolated environment.
3. Review dependency/container scan results.

Monthly:

1. Exercise credential rotation.
2. Review CORS/CSRF trusted origins.
3. Review evidence retention exceptions and legal holds.
