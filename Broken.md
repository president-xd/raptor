**Broken**
- JSON parsing turns `null` into string `"None"` for `dest_host` and `dest_ip`, creating a fake host called `None` in the graph. See [log_parser.py](D:/raptor/backend/ingestion/log_parser.py:61).
- JSON parser ignores the provided `event_type` and re-detects it from raw text, so known mock event types can be misclassified. See [log_parser.py](D:/raptor/backend/ingestion/log_parser.py:64).
- Host compromise state is wrong in frontend graph JSON. The graph API returned 5 host nodes, all `compromised: false`, while Neo4j query reported 2 compromised hosts. The dashboard therefore showed `--` for “Hosts Compromised.” Root cause is first-seen host state plus later Neo4j updates not reflected in exported graph. See [graph_builder.py](D:/raptor/backend/graph/graph_builder.py:44), [graph_builder.py](D:/raptor/backend/graph/graph_builder.py:168), and [Dashboard.jsx](D:/raptor/frontend/src/components/Dashboard.jsx:874).
- Graph data can bleed across investigations. Neo4j nodes are merged only by hostname or technique id, not by investigation id, then `investigation_id` is overwritten. See [graph_builder.py](D:/raptor/backend/graph/graph_builder.py:109).
- Natural-language graph queries are not forced to scope by `investigation_id`. The generated query I saw was `MATCH (h:Host) WHERE h.compromised = true ...`, so it can count hosts across cases. See [query_engine.py](D:/raptor/backend/nlq/query_engine.py:89).
- Weaviate is effectively broken in the provided stack: Docker uses `semitechnologies/weaviate:1.23.0`, but the installed client rejects it and requires `1.27.0+`. RAG retrieval returns empty results. See [docker-compose.yml](D:/raptor/docker-compose.yml:25) and [retriever.py](D:/raptor/backend/rag/retriever.py:69).
- LLM fallback works, but only after long waits. The mock investigation sat at RAG/report phases for minutes because `client.chat.completions.create` has no explicit timeout. See [pipeline.py](D:/raptor/backend/rag/pipeline.py:231).
- If embedding dependencies are missing, embeddings become random vectors. That makes retrieval nondeterministic and semantically invalid. See [embeddings.py](D:/raptor/backend/rag/embeddings.py:48).
- Attack graph layout is randomized on every render, so node positions jump and screenshots are unstable. See [AttackGraph.jsx](D:/raptor/frontend/src/components/AttackGraph.jsx:67).
- Attack graph hover highlighting is likely ineffective because reducers close over the initial `hoveredNode` value while the renderer effect only depends on `graphData`. See [AttackGraph.jsx](D:/raptor/frontend/src/components/AttackGraph.jsx:100).

**Incomplete Or Missing**
- No true investigation history UI/API. The frontend only stores one last investigation id in `localStorage`; the reference has recent investigations and statuses. See [Dashboard.jsx](D:/raptor/frontend/src/components/Dashboard.jsx:97).
- New investigation wizard is missing. Reference has file upload, Elastic query, paste logs, time range, sensitivity, APT group filters, review/submit. Current app only uploads one file. See [FileUpload.jsx](D:/raptor/frontend/src/components/FileUpload.jsx:49).
- Threat feeds are static labels. MISP/OpenCTI is explicitly “planned,” Elasticsearch is not used for runtime event storage, Redis is unused. See [Dashboard.jsx](D:/raptor/frontend/src/components/Dashboard.jsx:645).
- Settings page is read-only status text, not a real configuration surface. Reference has LLM, RAG, data source, attribution, thresholds, toggles.
- Reports page only shows the current report. No report archive, case list, saved exports, or generated report metadata.
- APT library loads profiles but only displays the first 12, with no search/filter/detail modal like the reference.
- MITRE Navigator is a simplified grid from current findings, not a Navigator-style layer/export or coverage view.
- Query is much thinner than the reference. It has suggestions and answers, but not rich chat context, source cards, Cypher display, or reliable grounding. One “block right now” answer came back generic with no sources.
- Simulation runs even when attribution confidence is `UNKNOWN`. In the mock run the top actor was `FIN8` at `13.8%`, yet simulation produced confident next-step predictions. That needs stronger UX warnings.

**Can Be Enhanced**
- Fix ingestion and graph correctness first: preserve `null`, respect source `event_type`, update host compromise state over all events, remove fake `None` nodes, and scope graph nodes/edges by investigation id.
- Make RAG real: upgrade Weaviate, run indexing automatically or provide a clear setup command, avoid random embeddings outside test mode, and surface “RAG unavailable” in the UI.
- Add LLM timeouts and a “local-only mode” when no reliable key/provider exists, so analysts are not waiting minutes for fallback.
- Improve attribution: Jaccard-only scoring is too weak. The mock `apt29_campaign.json` attributed to FIN8 because no infrastructure, malware, temporal, alias, or campaign-specific signals are actually applied. See [confidence.py](D:/raptor/backend/attribution/confidence.py:31).
- Add case management: list investigations, reopen, delete, rerun, compare, and show status/progress history.
- Make UI honest about degraded modes: show Sigma fallback, empty RAG, rate limits, report fallback, and unknown attribution prominently.
- Add tests around parser normalization, graph export, query scoping, attribution ranking, and frontend metric rendering. Right now the build passes, but there is no meaningful regression safety net.