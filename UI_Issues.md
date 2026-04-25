**Broken Or Misleading**
- **Hosts Compromised is wrong on the dashboard.** It renders `--` even though the backend/graph state knows compromised hosts exist. The UI depends on `graphData.nodes[].metadata.compromised`, but that exported graph metadata is stale. See [Dashboard.jsx](</d:/raptor/frontend/src/components/Dashboard.jsx:857>) and [Dashboard.jsx](</d:/raptor/frontend/src/components/Dashboard.jsx:874>).
- **Attribution confidence is dangerously over-presented.** The dashboard shows `14% FIN8` as “Top Confidence,” and the attribution panel can label a weak result as `TOP MATCH`. That should be treated as `UNKNOWN / low confidence`, not as a useful answer. See [Dashboard.jsx](</d:/raptor/frontend/src/components/Dashboard.jsx:887>) and [Attribution.jsx](</d:/raptor/frontend/src/components/Attribution.jsx:38>).
- **API health is too optimistic.** The top bar says `API healthy`, but degraded subsystems like vector/RAG/LLM fallback are not surfaced. The UI gives a false operational green light.
- **Threat Feed looks live but is mostly static/demo content.** It appears like an integrated feed panel, but there is no meaningful connector status, timestamp, source confidence, or “last pulled” state.
- **Reports expose raw evidence too directly.** The rendered report shows long JSON-like snippets and detection text. It is technically useful, but not analyst-friendly.

**Incomplete UI Areas**
- **APT Library:** only shows the first 12 profiles with a search-looking box, but no real search/filter/detail workflow. See [Dashboard.jsx](</d:/raptor/frontend/src/components/Dashboard.jsx:609>).
- **Settings:** mostly read-only status rows. No actual controls for API endpoint, model/provider, graph renderer, report format, connector config, or health checks.
- **Simulation:** looks like a feature, but it does not warn when attribution confidence is weak. Predicting next attacker steps from `UNKNOWN` attribution should be visually gated.
- **Query:** basic ask/answer UI works, but it needs source citations, graph-backed evidence, previous query history, and clearer “no answer / low confidence” states.
- **Reports:** current report rendering exists, but there is no report archive, generation state, export error UI, template selection, or analyst notes.
- **Investigations:** the detail view renders, but there is no strong investigation list/history workflow, no severity sorting, no case owner, no status transitions, and no triage actions.

**Graph UI Issues**
- The attack graph is one of the strongest-looking pieces, but it needs work before it feels reliable.
- Layout is random on each render because positions use `Math.random()`, so the same investigation can look different every time. See [AttackGraph.jsx](</d:/raptor/frontend/src/components/AttackGraph.jsx:67>).
- Labels overlap and become hard to scan.
- There is no useful filtering by host, technique, tactic, severity, timestamp, or confidence.
- Selection/hover behavior is visually helpful, but not enough for dense investigations.

**Responsive UI**
- Mobile renders without crashing, but it is not pleasant yet.
- Navigation becomes icon-only, which makes sections hard to understand.
- The top action bar stacks vertically and consumes too much screen height.
- Cards are large, so the real investigation data starts too far down the page.

**Highest Priority Fixes**
1. Fix compromised host count and graph metadata consistency.
2. Change attribution UI so weak matches are clearly labeled `UNKNOWN / LOW CONFIDENCE`.
3. Replace single `API healthy` with real subsystem health: API, graph DB, vector DB, LLM, report export.
4. Make APT Library search/filter/detail real.
5. Make the graph deterministic and filterable.
6. Add true investigation history/case management.
7. Improve mobile navigation and compact the dashboard for analyst use.

So: the UI is implemented enough to demo the concept, but not completely implemented as a trustworthy operational interface yet. It needs less “command center polish” and more honest state, source-backed evidence, filtering, and failure visibility.