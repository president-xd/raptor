# RAPTOR Tests

Run the top-level offline regression suite from the repository root:

```bash
python -m unittest discover -s tests
```

The suite covers ingestion, Sigma matching, attribution confidence, STIX validation, report fallback, graph export, NLQ guards, API-key auth, evidence/audit persistence, CISA KEV cache behavior, Elasticsearch poller state, frontend API wiring, and Docker/env defaults.

You can also run it with pytest from the repository root:

```bash
pytest -q tests/
```
