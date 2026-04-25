# GOD LEVEL PROMPT — RAG-Based APT Attack Map System
## Build Specification for AI Coding Agent / Senior Engineer

---

## ⚠️ HOW TO USE THIS PROMPT

This is a **fully self-contained build specification**. Feed the entire document to your AI coding agent (Claude Code, Cursor, Aider) as the system-level context. When the agent loses context mid-session, **re-feed this entire document** — do not summarize it. Every design decision herein is load-bearing.

This prompt is structured in layers matching the actual build order. Work **top-down**. Do not jump to Layer 4 (APT correlation) before Layer 2 (RAG pipeline) is tested.

---

## SECTION 0 — PROJECT IDENTITY

**Name**: RAPTOR | Retrieval-Augmented Persistent Threat Orchestration and Reasoning  
**Type**: Forensic + Predictive APT analysis system  
**Core Value Proposition**: Given raw security logs, produce a natural-language investigation report that reconstructs the attack timeline, maps each step to MITRE ATT&CK TTPs, attributes the campaign to a known APT group with a confidence score, visualizes lateral movement as an interactive graph, and simulates what the attacker would do next.

**What makes this different from existing tools**:
- BloodHound maps AD paths but doesn't reason about *who* is attacking or *why*
- MITRE ATT&CK Navigator is a knowledge base, not an analyst
- CALDERA emulates attacks but doesn't detect them
- SIEMs produce alerts but not narratives
- **RAPTOR closes all four gaps in one pipeline**

**Research grounding** (cite these if writing a paper):
- March 2026 arXiv: RAG + ATT&CK query library → 100% recall on malware scenarios, 100% precision / 82% recall on AD attack steps
- November 2025: GNN tripartite graph (APT groups × TTPs × Kill Chain) → 85% attribution accuracy, Macro-F1 = 0.84
- ESORICS 2024: APT scenarios modeled as CVE exploitation chains through ATT&CK technique sequences
- AURA (2025/2026): multi-agent, knowledge-enhanced, attribution-focused — closest existing parallel

---

## SECTION 1 — ARCHITECTURE OVERVIEW

Five data layers, one analyst interface. Data flows strictly downward; queries flow upward.

```
[Layer 1] Data Ingestion & Log Sources
         ↓
[Layer 2] RAG Pipeline & LLM Reasoning  ←→  [Vector Store: ATT&CK + APTNotes + CVEs]
         ↓
[Layer 3] Attack Graph & Lateral Movement  ←→  [Neo4j Graph DB]
         ↓
[Layer 4] APT Correlation & Attribution  ←→  [MITRE ATT&CK STIX API]
         ↓
[Layer 5] Simulation & Emulation  ←→  [MITRE CALDERA]
         ↓
[Layer 6] Frontend, API & Infrastructure  ←→  [React + FastAPI + Sigma.js]
```

**Critical architectural constraint**: RAG is not optional. Research proves LLM baselines without RAG miss *all* attack infrastructure — malicious domains, C2 servers, lateral movement artifacts. Every LLM call in this system must go through the retrieval layer. No naked LLM calls against raw logs.

---

## SECTION 2 — LAYER 1: DATA INGESTION & LOG SOURCES

### 2.1 Purpose
Normalize heterogeneous log formats into a unified event schema that downstream components can reason over. The system is only as good as what it ingests.

### 2.2 Core Components (must-have)

**Apache Kafka** — Real-time log streaming  
- Topics: `logs.windows`, `logs.network`, `logs.edr`, `logs.syslog`  
- Retention: 7 days (sufficient for APT campaign replay)  
- Consumer group: `raptor-ingestion`

**Logstash / Fluentd** — Log normalization  
- Input parsers: Windows Event Log (XML), Zeek/Suricata JSON, Syslog CEF, EDR telemetry (CrowdStrike/SentinelOne schemas)  
- Output: Normalized event objects in the RAPTOR Event Schema (see below)  
- Apply Sigma rules at this layer for pre-detection signal

**Elastic / OpenSearch** — Full-text log storage  
- Index: `raptor-events-YYYY-MM-DD`  
- Retention policy: 90 days warm, 1 year cold  
- Used for: log search, timeline reconstruction, evidence retrieval during RAG augmentation

**Sigma Rules** — Pre-detection signal layer  
- Source: SigmaHQ official repo (clone, do not modify)  
- Purpose: lightweight first-pass matching before LLM reasoning; reduces LLM token cost by 60-80%  
- Convert Sigma → Elasticsearch queries using `sigma-cli`

### 2.3 Threat Data Feeds (must-have)

**MISP / OpenCTI** — Threat intelligence platform  
- Pull IoC feeds: IP blacklists, domain reputation, file hash databases  
- Enrich every ingested event with IoC match scores before writing to Elastic  
- MISP correlation engine runs async (do not block ingestion pipeline)

**APTNotes + ATT&CK STIX** — APT knowledge corpus  
- APTNotes: https://github.com/aptnotes/data — 2018–2024 CTI reports  
- ATT&CK STIX: https://github.com/mitre/cti — pull `enterprise-attack` bundle  
- These are the **source documents** for the RAG vector store (Layer 2)

### 2.4 RAPTOR Event Schema (unified format)

```json
{
  "event_id": "uuid4",
  "timestamp": "ISO8601",
  "source_host": "hostname",
  "source_ip": "IPv4/6",
  "dest_host": "hostname | null",
  "dest_ip": "IPv4/6 | null",
  "event_type": "process | network | file | registry | auth | lateral",
  "raw": "original log line",
  "sigma_matches": ["T1059.001", "T1078"],
  "ioc_score": 0.0,
  "enriched": true
}
```

### 2.5 Implementation Notes

- Use Python for the Kafka consumer: `confluent-kafka` library
- Logstash pipeline configs go in `/config/logstash/pipelines/`
- Index template for Elastic goes in `/config/elastic/index_template.json`
- All Sigma rule matches are stored as ATT&CK technique IDs (e.g., `T1059.001`), not rule names
- **Dependency explosion mitigation**: For provenance graph construction, limit causal edge retention to 1M edges per 24h window. Older edges are archived, not discarded — archive to S3/MinIO with a retrieval API.

---

## SECTION 3 — LAYER 2: RAG PIPELINE & LLM REASONING

### 3.1 Purpose
This is the intelligence core. It transforms raw log events + Sigma matches into structured forensic findings by grounding every LLM inference in retrieved ATT&CK documentation, APTNotes threat reports, and CVE-to-TTP mappings.

### 3.2 The Non-Negotiable Four

These four components are the absolute minimum for the system to function. Cut anything else before you cut these.

1. **Weaviate** (vector database) — use Weaviate over Chroma/Pinecone because it supports hybrid BM25 + semantic search natively. This matters: security log events are short and keyword-heavy ("mimikatz", "lsass.exe", "T1003"). Semantic-only search misses keyword matches. BM25-only misses conceptual matches. Weaviate's hybrid mode handles both.

2. **BGE-large-en-v1.5 or Sentence-BERT fine-tuned on CTI text** — do NOT use a generic embedding model. Security language is a domain. "Lateral movement" in an ATT&CK document means something specific that a model trained on Wikipedia will not embed correctly. If fine-tuning is out of scope for MVP, use `BAAI/bge-large-en-v1.5` — it has the best zero-shot performance on security text.

3. **Neo4j** (graph database) — attack paths are a graph traversal problem. Relational DBs cannot efficiently answer "what is the shortest path from this compromised workstation to the domain controller?" Neo4j + Cypher can answer this in milliseconds.

4. **MITRE ATT&CK STIX API** — every TTP your system identifies must be anchored to a canonical ATT&CK technique object. Never fabricate technique descriptions. Always retrieve them.

### 3.3 RAG Orchestration

**LangChain** (primary) or **LlamaIndex** (alternative) — use LangChain if you need custom chain logic; LlamaIndex if you want faster indexing.

**Embedding pipeline**:
```
ATT&CK STIX objects → chunk by technique → embed → store in Weaviate (class: "Technique")
APTNotes PDFs → chunk 512 tokens / 64 overlap → embed → store in Weaviate (class: "ThreatReport")
CVE descriptions + ATT&CK mappings (CISA KEV) → embed → store in Weaviate (class: "Vulnerability")
```

**Query pipeline**:
```
Input: RAPTOR Event batch (50-200 events, 15-min window)
  ↓
Step 1: Extract candidate TTP signatures (regex + Sigma matches)
  ↓
Step 2: Hybrid search in Weaviate for each candidate
         query = event_description + sigma_match_ids
         alpha = 0.6 (60% semantic, 40% BM25)
  ↓
Step 3: Rerank results (Cohere Rerank API or BGE-reranker-large locally)
         Keep top-5 per event
  ↓
Step 4: Construct augmented prompt (see prompt template below)
  ↓
Step 5: LLM inference → structured JSON output
  ↓
Step 6: Validate output against ATT&CK STIX (reject hallucinated technique IDs)
```

### 3.4 LLM Configuration

**Primary**: Claude Sonnet (best recall on security tasks per March 2026 paper)  
**Fallback**: GPT-4o  
**Local / air-gapped**: Mistral-7B-Instruct fine-tuned on CTI (requires labeled data)

**System prompt for log analysis**:
```
You are a senior threat analyst at a tier-1 SOC. You have access to retrieved 
MITRE ATT&CK documentation and APT threat reports. Your job is to analyze the 
provided security events and produce ONLY a JSON object matching the schema below. 
Do not include any text outside the JSON. Do not fabricate technique IDs — use only 
the IDs present in the retrieved context. If you are unsure, set confidence to "low".

Output schema:
{
  "findings": [
    {
      "event_ids": ["uuid", ...],
      "technique_id": "T1XXX.YYY",
      "technique_name": "string",
      "kill_chain_phase": "recon|resource-dev|initial-access|execution|persistence|privilege-esc|defense-evasion|credential-access|discovery|lateral-movement|collection|c2|exfiltration|impact",
      "confidence": "high|medium|low",
      "evidence_summary": "string (max 100 words)",
      "apt_indicators": ["string", ...]
    }
  ],
  "attack_sequence": ["T1XXX", "T1YYY", ...],
  "anomalies": ["string", ...]
}
```

### 3.5 Context Window Management

- Each RAG call: max 4,096 input tokens (events + retrieved context)
- Batch events into 15-minute windows to stay under limit
- For long campaigns (24h+): use map-reduce — analyze each window independently, then synthesize with a second "consolidation" LLM call that takes all window summaries as input
- **Temporal context problem**: APTs operate over 18+ month campaigns. Neo4j handles this, not the LLM. The LLM sees event windows; Neo4j maintains the full campaign graph. Do not attempt to fit an entire campaign into one LLM context window.

### 3.6 Supporting Components

**Haystack** (deepset) — production RAG framework; use if you want a managed pipeline with monitoring built in. Good for deployment; LangChain is better for development velocity.

**Reranker** — Cohere Rerank API (cloud) or `BAAI/bge-reranker-large` (local). Do not skip this. Without reranking, top-k retrieval at k=20 returns too much noise. Rerank to k=5 before LLM injection.

---

## SECTION 4 — LAYER 3: ATTACK GRAPH & LATERAL MOVEMENT

### 4.1 Purpose
Construct a directed graph of the attack: who went where, via what mechanism, in what order. This is the "spatial map" of the campaign. It answers questions like: "How did the attacker get from the phishing victim's laptop to the domain controller in 4 hops?"

### 4.2 Graph Data Model (Neo4j)

**Node types**:
```cypher
(:Host {hostname, ip, os, domain, compromised: bool, compromise_time})
(:User  {username, domain, privilege_level, compromised: bool})
(:Process {pid, name, command_line, host, timestamp})
(:File  {path, hash_sha256, host, timestamp})
(:Network {dest_ip, dest_port, protocol, c2: bool})
(:Technique {id, name, tactic, kill_chain_phase})
(:APTGroup {name, aliases, nation_state})
```

**Relationship types**:
```cypher
(Host)-[:EXECUTED]->(Process)
(Process)-[:CREATED]->(File)
(Process)-[:CONNECTED_TO]->(Network)
(User)-[:LOGGED_INTO]->(Host)
(Host)-[:LATERAL_MOVED_TO {technique, timestamp}]->(Host)
(Technique)-[:OBSERVED_IN]->(Host)
(APTGroup)-[:USES]->(Technique)
```

**Critical indexes**:
```cypher
CREATE INDEX FOR (h:Host) ON (h.hostname);
CREATE INDEX FOR (u:User) ON (u.username);
CREATE INDEX FOR (t:Technique) ON (t.id);
CREATE CONSTRAINT FOR (a:APTGroup) REQUIRE a.name IS UNIQUE;
```

### 4.3 BloodHound Integration (do NOT rebuild from scratch)

BloodHound CE already: ingests AD data via SharpHound, builds a Neo4j graph, runs shortest-path queries. Your job is to **extend** it, not replace it.

**Integration approach**:
1. Deploy BloodHound CE (Docker Compose provided in their repo)
2. Point RAPTOR at the same Neo4j instance BloodHound uses
3. Add RAPTOR node/edge types to the existing schema (they don't conflict)
4. Use BloodHound's Cypher queries as templates for RAPTOR's lateral movement analysis
5. Wrap BloodHound's UI with RAPTOR's React frontend OR iframe BloodHound's graph view

**Key BloodHound queries to reuse**:
```cypher
-- Shortest path from compromised user to Domain Admin
MATCH p=shortestPath((u:User {name: $username})-[*]->(g:Group {name: "Domain Admins@*"}))
RETURN p

-- All hosts reachable from a compromised host
MATCH (h:Computer {name: $hostname})-[:HasSession|AdminTo|CanRDP*1..5]->(target:Computer)
RETURN DISTINCT target
```

### 4.4 Provenance Graph as DAG

For process-level forensics (OCR-APT style), build a provenance DAG:

```
Process A
  └─ spawned: Process B (T1059.001 - PowerShell)
       ├─ read: File C (credential store)
       └─ connected: Network D (C2: 185.x.x.x:443)
            └─ downloaded: File E (T1105 - Ingress Tool Transfer)
```

**Implementation**: Each event from Layer 1 becomes a node. Causal edges connect events where one event directly caused another (parent-child process, process-file write, file-network upload).

**Scale constraint**: Limit in-memory provenance graph to 1M edges. Archive older edges to Neo4j cold storage. Provide retrieval API for historical path queries.

### 4.5 GNN for Attribution (optional, MVP-bypass)

**For MVP**: Skip PyG/DGL. Use Jaccard similarity between observed TTP sets and known APT TTP profiles. Gets you to 60-70% attribution accuracy with zero training data.

```python
def jaccard_attribution(observed_ttps: set, apt_profiles: dict) -> list:
    scores = []
    for apt_name, apt_ttps in apt_profiles.items():
        intersection = len(observed_ttps & apt_ttps)
        union = len(observed_ttps | apt_ttps)
        score = intersection / union if union > 0 else 0
        scores.append({"apt": apt_name, "jaccard": score, "overlap": list(observed_ttps & apt_ttps)})
    return sorted(scores, key=lambda x: x["jaccard"], reverse=True)
```

**For v2 (GNN)**: Use PyG with a Relational Graph Convolutional Network (RGCN). Train on the APTNotes corpus labeled by APT group. Target: 85% attribution accuracy (matching the November 2025 paper).

---

## SECTION 5 — LAYER 4: APT CORRELATION & ATTRIBUTION

### 5.1 Purpose
Answer the question every analyst asks: "Who is doing this?" Map the observed TTP sequence to a known APT group with a confidence score and a ranked list of supporting evidence.

### 5.2 The False Flag Problem (critical — most systems ignore this)

Adversaries deliberately mimic other APT groups to poison attribution. APT41 has been observed using APT29 TTPs. Attribution confidence must factor this in.

**Confidence scoring formula**:
```
Base score: Jaccard similarity (TTPs observed vs APT profile)
Penalty 1: -0.15 if observed TTPs overlap with ≥2 other APT groups at >0.4 Jaccard
Penalty 2: -0.10 if campaign duration < 72h (APTs operate long; fast campaigns suggest mimicry or FIN group)
Bonus 1:   +0.10 if infrastructure (C2 IPs, domains) matches known APT infrastructure in MISP
Bonus 2:   +0.05 if malware families match (via file hash enrichment)
Bonus 3:   +0.10 if temporal TTP sequence matches known APT playbook order

Final confidence:
  > 0.75: HIGH — attribute with high confidence
  0.50–0.75: MEDIUM — likely attribution, note alternatives
  0.30–0.50: LOW — possible attribution, do not report without caveat
  < 0.30: UNKNOWN — insufficient evidence
```

### 5.3 Knowledge Alignment (must-have)

**MITRE ATT&CK API** — ground truth TTP database  
- Endpoint: https://attack.mitre.org/api/ (or use the STIX bundle locally)
- Every attributed TTP must have a canonical STIX object retrieved from here
- Do not use ATT&CK Navigator web UI programmatically — use the STIX bundle directly

**TRAM (MITRE)** — automated TTP extraction from free-text  
- GitHub: https://github.com/center-for-threat-informed-defense/tram  
- Use TRAM to extract TTPs from APTNotes reports for building the APT profile corpus
- Run TRAM offline on the APTNotes dataset → output: `{apt_name: [T1xxx, ...]}` profiles

**Cybersecurity Knowledge Graph (CSKG)** — optional but valuable  
- Connects CVEs, software vendors, malware families, APT groups  
- Use for cross-referencing: "APT29 exploits CVE-2021-26855 (ProxyLogon) → Exchange Server"

### 5.4 APT Profile Store

Store APT profiles in Neo4j as `APTGroup` nodes with `USES` edges to `Technique` nodes. Load from MITRE CTI:

```python
import requests, json
from stix2 import MemoryStore, Filter

def load_apt_profiles():
    bundle = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json").json()
    store = MemoryStore(stix_data=bundle["objects"])
    
    groups = store.query([Filter("type", "=", "intrusion-set")])
    for group in groups:
        # Get techniques used by this group
        rels = store.query([
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "uses"),
            Filter("source_ref", "=", group.id)
        ])
        techniques = [r.target_ref for r in rels]
        # Write to Neo4j
        write_apt_profile(group.name, group.aliases, techniques)
```

### 5.5 TTP Overlap Scoring

Use pandas + scikit-learn for the scoring pipeline:

```python
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import MultiLabelBinarizer

def build_ttp_matrix(apt_profiles: dict, observed_ttps: list):
    mlb = MultiLabelBinarizer()
    all_ttps = list(apt_profiles.values()) + [observed_ttps]
    matrix = mlb.fit_transform(all_ttps)
    
    apt_vectors = matrix[:-1]
    observed_vector = matrix[-1].reshape(1, -1)
    
    similarities = cosine_similarity(observed_vector, apt_vectors)[0]
    apt_names = list(apt_profiles.keys())
    
    return sorted(zip(apt_names, similarities), key=lambda x: x[1], reverse=True)[:10]
```

---

## SECTION 6 — LAYER 5: SIMULATION & EMULATION

### 6.1 Purpose
Given the attributed APT and the current foothold, simulate what they would likely do next. This transforms RAPTOR from a forensic tool (looking backward) into a proactive tool (looking forward).

### 6.2 MITRE CALDERA Integration

**CALDERA** is an automated adversary emulation platform. Do not reimplement it. Wrap it.

**Setup**:
```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && pip install -r requirements.txt
python server.py --insecure  # dev only; use TLS in prod
```

**RAPTOR → CALDERA workflow**:
1. RAPTOR identifies APT group (e.g., APT29) with HIGH confidence
2. RAPTOR queries CALDERA's API for APT29's adversary profile
3. CALDERA returns the ability chain (sequence of ATT&CK techniques)
4. RAPTOR filters the chain to only include techniques that are feasible given the current network state (from Layer 3 graph)
5. RAPTOR asks LLM: "Given this foothold and this APT's known playbook, what are the 3 most likely next steps?"
6. Output: ordered list of predicted next techniques with MITRE IDs, descriptions, and detection recommendations

**LLM prompt for simulation**:
```
You are a red team operator simulating APT {apt_name}. 

Current foothold:
- Compromised hosts: {host_list}
- Current privileges: {privilege_level}
- Observed TTPs so far: {observed_ttps}
- Network segment: {network_info}

Known APT {apt_name} playbook (from ATT&CK):
{retrieved_caldera_abilities}

Retrieved ATT&CK documentation for likely next techniques:
{rag_context}

Predict the 3 most likely next techniques this APT would execute. For each:
1. Technique ID and name
2. Why this APT would choose this technique at this stage
3. What specific commands or tools they would likely use
4. How to detect it NOW, before they execute it

Output as JSON only.
```

### 6.3 Atomic Red Team

Use Atomic Red Team for unit-testing individual technique detections:
- When RAPTOR attributes a technique, run the corresponding Atomic test in the lab environment
- Verify that the detection fires
- This creates a feedback loop: simulation → detection → verification

### 6.4 Lab Environment

**DetectionLab / GOAD** — pre-built vulnerable AD environments for testing  
- DetectionLab: Windows domain with logging enabled  
- GOAD (Game of Active Directory): more complex, Kali-based red team scenarios  
- Both export to Vagrant/VMware/VirtualBox

---

## SECTION 7 — LAYER 6: FRONTEND, API & INFRASTRUCTURE

### 7.1 API Layer (FastAPI)

**Core endpoints**:
```
POST /api/v1/investigate
  body: { log_file: base64, time_range: {start, end} }
  returns: { investigation_id: uuid }

GET  /api/v1/investigate/{id}/status
  returns: { status: "queued|processing|complete|failed", progress: 0-100 }

GET  /api/v1/investigate/{id}/report
  returns: full InvestigationReport object

GET  /api/v1/investigate/{id}/graph
  returns: Sigma.js compatible graph JSON

POST /api/v1/simulate
  body: { investigation_id: uuid, apt_group: string | null }
  returns: SimulationResult object

GET  /api/v1/apt/profiles
  returns: list of all APT profiles with TTP counts

POST /api/v1/query
  body: { question: string, investigation_id: uuid }
  returns: { answer: string, sources: [...], confidence: string }
```

**Async tasks**: Use Celery + Redis for all long-running operations (log analysis, graph construction, simulation). Never block the API thread.

### 7.2 Visualization (Sigma.js / Cytoscape.js)

**Sigma.js** for attack graph rendering (better performance on large graphs vs D3)

Graph node colors encode meaning:
- Gray: uncompromised host
- Amber: potentially compromised (medium confidence)  
- Red: confirmed compromised  
- Purple: domain controller  
- Blue: user account
- Orange edges: lateral movement paths
- Red edges: confirmed attack path (critical path)

**Interactive features (must-have)**:
- Click node → sidebar panel with host details, observed TTPs, timeline
- Click edge → shows the lateral movement technique used and timestamp
- Timeline scrubber → replay attack progression chronologically
- Filter panel → filter by technique, host type, confidence level
- Natural language query bar → "show me all paths to the domain controller"

### 7.3 The Natural Language Query Layer (killer differentiator)

This is what separates RAPTOR from every existing tool. Analysts can ask in plain English:

- "What would APT29 do next given this foothold?"
- "How many hops from the initial compromise to domain admin?"
- "Which techniques were used that overlap with Cozy Bear's known playbook?"
- "What should I block right now to contain this attack?"

Implementation: dedicated `/api/v1/query` endpoint that:
1. Receives free-text question + investigation context
2. Routes to appropriate sub-pipeline (graph query → Cypher translation, ATT&CK lookup → RAG retrieval, simulation → CALDERA query)
3. Synthesizes response with citations
4. Returns answer + source documents + confidence

**Cypher translation via LLM**:
```python
def natural_language_to_cypher(question: str, schema: str) -> str:
    prompt = f"""
    Neo4j schema: {schema}
    User question: {question}
    Write a Cypher query that answers this question. Return ONLY the Cypher query.
    """
    return llm.invoke(prompt)
```

### 7.4 Infrastructure

**Docker Compose** (development):
```yaml
services:
  kafka:        confluentinc/cp-kafka:7.5
  zookeeper:    confluentinc/cp-zookeeper:7.5
  elasticsearch: elasticsearch:8.11.0
  neo4j:        neo4j:5.15-enterprise
  weaviate:     semitechnologies/weaviate:1.23
  redis:        redis:7.2-alpine
  caldera:      (build from source)
  api:          (RAPTOR FastAPI)
  worker:       (Celery workers)
  frontend:     (React + Nginx)
```

**Kubernetes** (production):
- Use Helm charts for Kafka (Bitnami), Elastic (official), Neo4j (official), Weaviate (official)
- RAPTOR API + workers deploy as separate Deployments with HPA
- Secrets: Kubernetes Secrets (or Vault for enterprise)

**MLflow / W&B** — model tracking:
- Track embedding model versions, reranker configurations, LLM prompt versions
- Log attribution accuracy on the validation set after each model update

---

## SECTION 8 — MVP SCOPING (build this first)

Build **exactly** this, nothing more, for the MVP. Resist scope creep.

### MVP Deliverable
A forensic/retrospective tool that:
1. Accepts a `.log` file or Elastic query as input
2. Produces an attack timeline with each event mapped to an ATT&CK technique
3. Outputs a ranked attribution list: "This attack most resembles APT29 (62% confidence) because of 7 technique overlaps: T1078, T1021.002, T1059.001..."
4. Renders an interactive graph showing which hosts were touched and in what order
5. Generates a 1-page analyst report in natural language

### MVP Stack (minimal viable)
```
Weaviate (local, single-node)       ← vector store
BGE-large-en-v1.5                   ← embeddings
LangChain                           ← RAG orchestration
Claude Sonnet (API)                 ← LLM reasoning
Neo4j (local, community edition)    ← graph store
FastAPI                             ← API
React + Sigma.js                    ← frontend
Jaccard similarity                  ← attribution (skip GNN)
SQLite                              ← job state tracking (skip Redis/Celery for MVP)
```

### MVP Exclusions (build later)
- Real-time streaming (Kafka) — MVP accepts batch files
- MISP/OpenCTI integration — MVP uses static IoC list
- CALDERA simulation — MVP does prediction only, no emulation
- GNN attribution — MVP uses Jaccard
- Kubernetes — MVP runs on Docker Compose
- Multi-user authentication — MVP is single-user

### MVP Build Order
1. Vector store setup: index ATT&CK STIX + APTNotes into Weaviate
2. RAG pipeline: LangChain chain that takes log events → retrieves ATT&CK context → LLM → structured JSON
3. Neo4j schema: create node/edge types, write ingestion functions
4. Attribution engine: Jaccard similarity against ATT&CK group profiles
5. FastAPI: 4 endpoints (upload, status, report, graph)
6. React frontend: file upload, loading state, report view, Sigma.js graph
7. End-to-end test: feed the DARPA Transparent Computing dataset through the pipeline

---

## SECTION 9 — KNOWN HARD PROBLEMS & HOW TO HANDLE THEM

### 9.1 Temporal Dynamics (most underestimated problem)
APTs like APT41 operate across 18+ month campaigns. No LLM has a context window for this.

**Solution**: Neo4j is your long-term memory. The LLM only sees 15-minute event windows. Neo4j holds the full campaign graph indefinitely. Build a "campaign state" object that summarizes the current graph state in <500 tokens, and include it as context in every LLM call.

### 9.2 False Flag Attacks
Adversaries mimic other APT groups. See Section 5.2 for the confidence scoring formula. Additionally: always present the top-3 attributions, never just the top-1. "This most resembles APT29 (62%), but APT41 is also plausible (48%). Note that APT41 has been observed mimicking APT29 TTPs."

### 9.3 Dependency Explosion in Provenance Graphs
Modern systems generate millions of causal edges per hour.

**Solution**: Apply "backward slicing" — start from the suspicious event (e.g., data exfiltration) and trace backward through the causal graph only as far as needed to reach the initial access point. Don't build the full forward graph from every process start.

### 9.4 Hallucinated ATT&CK Technique IDs
LLMs fabricate technique IDs when not grounded.

**Solution**: After every LLM call, validate all technique IDs in the output against the STIX bundle. Reject any ID not found in the bundle. Log rejections. This is a required post-processing step, not optional.

```python
def validate_technique_ids(findings: list, stix_store: MemoryStore) -> list:
    valid = []
    for finding in findings:
        tid = finding["technique_id"]
        result = stix_store.query([Filter("external_references.external_id", "=", tid)])
        if result:
            valid.append(finding)
        else:
            log.warning(f"Rejected hallucinated technique ID: {tid}")
    return valid
```

### 9.5 Data Scarcity for GNN Training
APT attack data is classified and scarce.

**Solution for MVP**: Use the APTNotes corpus + ATT&CK groups as labeled data. 142 APT groups × avg. 20 techniques = ~2,840 labeled samples. Augment with MITRE CALDERA adversary profiles. This is sufficient to train a basic GNN. For production: consider synthetic APT scenario generation using CALDERA's automated red team.

---

## SECTION 10 — EVALUATION & VALIDATION

### 10.1 Datasets for Testing
- **DARPA Transparent Computing** — provenance graph datasets with ground truth labels
- **APTNotes corpus** — 2018–2024 CTI reports, labeled by APT group
- **MITRE ATT&CK Evaluations** — AV/EDR vendor data, usable as red team ground truth
- **BROP/BlueSky datasets** (academic, request access)

### 10.2 Metrics to Track

| Component | Metric | Target |
|---|---|---|
| TTP extraction recall | % of ground-truth TTPs identified | >80% |
| TTP extraction precision | % of identified TTPs that are correct | >85% |
| Attribution top-1 accuracy | Correct APT group as first result | >65% |
| Attribution top-3 accuracy | Correct APT group in top-3 | >85% |
| Hallucination rate | % of technique IDs that fail STIX validation | <5% |
| Lateral movement path accuracy | % of attack paths correctly reconstructed | >75% |
| Response latency (MVP) | Time from log upload to report complete | <60s |

### 10.3 Ablation Studies (publish these)
- RAG vs no-RAG: run both on the same dataset, compare recall
- Jaccard vs cosine vs GNN attribution: compare accuracy at each stage
- BGE-large vs generic embeddings: compare retrieval MRR@5

---

## SECTION 11 — SECURITY & OPERATIONAL NOTES

- **Never log raw log events to stdout in production** — they contain PII and sensitive infrastructure data
- **API authentication**: JWT tokens, short-lived (1h), with RBAC (analyst / admin roles)
- **Neo4j authentication**: mandatory, separate credentials from API service account
- **Weaviate**: enable API key authentication in production
- **CALDERA**: never expose CALDERA's API externally — proxy through RAPTOR API only
- **Log the LLM inputs/outputs** to MLflow for audit trail — every attribution decision must be reproducible
- **Air-gapped deployment**: replace Claude/GPT-4 with local Mistral-7B; replace Weaviate cloud with local instance; replace Cohere Rerank with BGE-reranker-large. All components support local deployment.

---

## SECTION 12 — BACKTRACKING IN CONVERSATIONS (agent instruction)

When an AI coding agent is building this system and must revisit a previous decision:

**Backtrack protocol**:
1. State explicitly what you are backtracking on: "Reverting the embedding pipeline design from Section 3.3 because [specific reason]."
2. Before changing any shared schema (Neo4j node types, RAPTOR Event Schema, API contracts), check all downstream consumers in Sections 4–6 and list what breaks.
3. When changing a Layer N component, re-read all Layers N+1 through 6 to identify cascading impacts.
4. Never silently change a shared interface. Document the change in a `CHANGELOG.md` at the project root.
5. If the backtrack invalidates a design decision in this prompt, the prompt wins unless there is a concrete technical reason it cannot. State the reason explicitly before overriding.

**Common valid backtracks**:
- Weaviate → Qdrant (valid if Weaviate has deployment issues; Qdrant also supports hybrid search)
- LangChain → LlamaIndex (valid if orchestration complexity is too high)
- Jaccard attribution → cosine similarity (valid; cosine handles TTP frequency better for APTs with large technique libraries)
- FastAPI → Flask (valid for MVP; FastAPI preferred for async task handling)

**Invalid backtracks** (require explicit justification):
- Removing the STIX validation step (hallucination prevention is non-negotiable)
- Replacing Neo4j with a relational DB (graph traversal performance is load-bearing)
- Removing the reranking step (retrieval precision drops unacceptably without it)
- Using a generic embedding model (security domain language requires domain embeddings)

---

## SECTION 13 — QUICK REFERENCE

### Recommended Libraries (Python)
```
confluent-kafka==2.3.0
logstash-formatter==0.5.17
elasticsearch==8.11.0
weaviate-client==4.4.0
sentence-transformers==2.6.1
langchain==0.2.0
langchain-anthropic==0.1.0
cohere==4.57.0
neo4j==5.18.0
networkx==3.2
torch-geometric==2.5.0  (v2 only)
fastapi==0.111.0
celery==5.3.6
redis==5.0.3
stix2==3.0.1
pandas==2.2.0
scikit-learn==1.4.0
mlflow==2.12.0
```

### Recommended Libraries (Frontend)
```
react==18.2.0
typescript==5.4.0
sigma==3.0.0-beta.4
graphology==0.25.4
@tanstack/react-query==5.32.0
tailwindcss==3.4.0
recharts==2.12.0
```

### Operating System Instructions
If you want to use kali, follow the instructions
- 1. Execute: wsl -d kali-linux 
- 2. Wait: for the kali to load
- 3. Then You will able do whatever you want
- 4. Sudo Password for kali-linux is "kali"

### Key External Resources
- ATT&CK STIX bundle: https://github.com/mitre/cti
- APTNotes corpus: https://github.com/aptnotes/data
- BloodHound CE: https://github.com/SpecterOps/BloodHound
- MITRE CALDERA: https://github.com/mitre/caldera
- TRAM: https://github.com/center-for-threat-informed-defense/tram
- DetectionLab: https://github.com/clong/DetectionLab
- DARPA TC datasets: https://github.com/darpa-i2o/Transparent-Computing
- Sigma rules: https://github.com/SigmaHQ/sigma

---

*End of specification. Build RAPTOR.*