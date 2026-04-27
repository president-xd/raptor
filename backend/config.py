"""
RAPTOR | Centralized Configuration
Loads all settings from environment variables / .env file.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# ─── LLM Configuration ───────────────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
LLM_MODEL = os.getenv("LLM_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
LLM_FALLBACK_MODEL = os.getenv("LLM_FALLBACK_MODEL", "qwen/qwen3-coder:free")
LLM_MAX_TOKENS = 4096  # Increased — new models support much larger context windows
LLM_TEMPERATURE = 0.1  # Low temp for deterministic security analysis
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))

# Context window capabilities for model-aware batching
MODEL_CONTEXT_WINDOWS = {
    "qwen/qwen3-coder:free": 131072,           # 128K context
    "nvidia/nemotron-3-super-120b-a12b:free": 131072,  # 128K context
    "google/gemini-flash-1.5": 1048576,        # 1M context
    "anthropic/claude-3-haiku-20240307": 200000,
    "anthropic/claude-3-sonnet-20240229": 200000,
}

# ─── Neo4j ────────────────────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "change_me_neo4j_password")

# ─── Weaviate ─────────────────────────────────────────────────────────
WEAVIATE_URL = os.getenv("WEAVIATE_URL", "http://localhost:8080")
WEAVIATE_GRPC_URL = os.getenv("WEAVIATE_GRPC_URL", "localhost:50051")

# ─── Elasticsearch ────────────────────────────────────────────────────
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTIC_INDEX_PREFIX = os.getenv("ELASTIC_INDEX_PREFIX", "raptor-events")
ELASTIC_POLL_ENABLED = os.getenv("ELASTIC_POLL_ENABLED", "false").lower() == "true"
ELASTIC_POLL_QUERY = os.getenv("ELASTIC_POLL_QUERY", "*")
ELASTIC_POLL_INTERVAL_SECONDS = int(os.getenv("ELASTIC_POLL_INTERVAL_SECONDS", "300"))
ELASTIC_POLL_WINDOW_MINUTES = int(os.getenv("ELASTIC_POLL_WINDOW_MINUTES", "5"))

# ─── Redis ────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_CACHE_TTL_SECONDS = int(os.getenv("REDIS_CACHE_TTL_SECONDS", "3600"))

# ─── API ──────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
RAPTOR_API_KEY = os.getenv("RAPTOR_API_KEY", "")
RAPTOR_AUTH_EXEMPT_HEALTH = os.getenv("RAPTOR_AUTH_EXEMPT_HEALTH", "true").lower() == "true"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "10485760"))  # 10 MiB default
CORS_ALLOW_ORIGINS = [
  origin.strip()
  for origin in os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:3100,http://127.0.0.1:3100"
  ).split(",")
  if origin.strip()
]
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"

# ─── RAG Configuration ───────────────────────────────────────────────
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "BAAI/bge-large-en-v1.5")
RERANKER_MODEL = os.getenv("RERANKER_MODEL", "BAAI/bge-reranker-large")
RAG_LOCAL_FALLBACK_ENABLED = os.getenv("RAG_LOCAL_FALLBACK_ENABLED", "true").lower() == "true"
RAG_CHUNK_SIZE = 512
RAG_CHUNK_OVERLAP = 64
RAG_HYBRID_ALPHA = 0.6  # 60% semantic, 40% BM25
RAG_RETRIEVAL_K = 20    # Initial retrieval
RAG_RERANK_K = 5        # After reranking
EVENT_BATCH_WINDOW_MINUTES = 15
MAX_INPUT_TOKENS = 16384  # Increased from 4096 — new models support 128K+ context

# ─── Paths ────────────────────────────────────────────────────────────
DATA_DIR = PROJECT_ROOT / "data"
STIX_DIR = DATA_DIR / "stix"
MOCK_DIR = DATA_DIR / "mock"
EVIDENCE_DIR = DATA_DIR / "evidence"
INTEL_DIR = DATA_DIR / "intel"
APT_REPORTS_DIR = Path(os.getenv("APT_REPORTS_DIR", str(INTEL_DIR / "apt_reports")))
DB_PATH = PROJECT_ROOT / "backend" / "raptor.db"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
STIX_DIR.mkdir(exist_ok=True)
MOCK_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)
INTEL_DIR.mkdir(exist_ok=True)

# ─── ATT&CK STIX Source ──────────────────────────────────────────────
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CISA_KEV_URL = os.getenv(
    "CISA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
CISA_KEV_CACHE_PATH = INTEL_DIR / "cisa_kev.json"

# ─── System Prompts ──────────────────────────────────────────────────

LOG_ANALYSIS_SYSTEM_PROMPT = """You are a senior threat analyst at a tier-1 SOC. You have access to retrieved 
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
}"""

SIMULATION_PROMPT_TEMPLATE = """You are a red team operator simulating APT {apt_name}. 

Current foothold:
- Compromised hosts: {host_list}
- Current privileges: {privilege_level}
- Observed TTPs so far: {observed_ttps}
- Network segment: {network_info}

Known APT {apt_name} playbook (from ATT&CK):
{retrieved_abilities}

Retrieved ATT&CK documentation for likely next techniques:
{rag_context}

Predict the 3 most likely next techniques this APT would execute. For each:
1. Technique ID and name
2. Why this APT would choose this technique at this stage
3. What specific commands or tools they would likely use
4. How to detect it NOW, before they execute it

Output as JSON only with schema:
{{
  "predictions": [
    {{
      "technique_id": "T1XXX",
      "technique_name": "string",
      "rationale": "string",
      "likely_tools": ["string"],
      "detection_guidance": "string",
      "urgency": "critical|high|medium"
    }}
  ]
}}"""

NLQ_CYPHER_PROMPT = """You are a Neo4j Cypher query expert. Given the following graph schema and a user's natural language question, write a Cypher query that answers the question.

Neo4j Schema:
Node types:
  (:Host {{hostname, ip, os, domain, compromised: bool, compromise_time}})
  (:User {{username, domain, privilege_level, compromised: bool}})
  (:Process {{pid, name, command_line, host, timestamp}})
  (:File {{path, hash_sha256, host, timestamp}})
  (:Network {{dest_ip, dest_port, protocol, c2: bool}})
  (:Technique {{id, name, tactic, kill_chain_phase}})
  (:APTGroup {{name, aliases, nation_state}})

Relationship types:
  (Host)-[:EXECUTED]->(Process)
  (Process)-[:CREATED]->(File)
  (Process)-[:CONNECTED_TO]->(Network)
  (User)-[:LOGGED_INTO]->(Host)
  (Host)-[:LATERAL_MOVED_TO {{technique, timestamp}}]->(Host)
  (Technique)-[:OBSERVED_IN]->(Host)
  (APTGroup)-[:USES]->(Technique)

User question: {question}

Critical requirement:
- Scope every relevant node pattern by investigation_id using `$investigation_id`.
- Return read-only Cypher only.

Return ONLY the Cypher query, no explanation."""

REPORT_GENERATION_PROMPT = """You are a senior cybersecurity analyst writing an investigation report. 
Based on the following forensic findings, write a clear, concise, 1-page analyst report.

The report should include:
1. **Executive Summary** — 2-3 sentence overview of the attack
2. **Attack Timeline** — Chronological sequence of events with timestamps
3. **Techniques Observed** — Each ATT&CK technique with evidence
4. **Attribution Assessment** — Who is likely responsible and confidence level
5. **Impact Assessment** — What was compromised
6. **Recommendations** — Immediate containment and remediation steps

Findings:
{findings_json}

Attribution:
{attribution_json}

Graph Summary:
{graph_summary}

Write the report in markdown format. Be specific and cite evidence."""
