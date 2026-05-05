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
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "nvidia").lower()
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
LLM_BASE_URL = os.getenv(
    "LLM_BASE_URL",
    OPENROUTER_BASE_URL if LLM_PROVIDER == "openrouter" else NVIDIA_BASE_URL,
)
LLM_API_KEY = os.getenv(
    "LLM_API_KEY",
    OPENROUTER_API_KEY if LLM_PROVIDER == "openrouter" else NVIDIA_API_KEY,
)
RAPTOR_ALLOW_EXTERNAL_LLM = os.getenv("RAPTOR_ALLOW_EXTERNAL_LLM", "false").lower() == "true"
LLM_MODEL = os.getenv("LLM_MODEL", "z-ai/glm-5.1")
LLM_FALLBACK_MODEL = os.getenv("LLM_FALLBACK_MODEL", "z-ai/glm-5.1")
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "32768"))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "1"))
LLM_TOP_P = float(os.getenv("LLM_TOP_P", "1"))
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
LLM_STREAM_RESPONSES = os.getenv("LLM_STREAM_RESPONSES", "true").lower() == "true"
LLM_ENABLE_THINKING = os.getenv("LLM_ENABLE_THINKING", "true").lower() == "true"
LLM_CLEAR_THINKING = os.getenv("LLM_CLEAR_THINKING", "false").lower() == "true"

# Context window capabilities for model-aware batching
MODEL_CONTEXT_WINDOWS = {
    "qwen/qwen3-coder:free": 131072,           # 128K context
    "nvidia/nemotron-3-super-120b-a12b:free": 131072,  # 128K context
    "z-ai/glm-5.1": 131072,
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
WEAVIATE_API_KEY = os.getenv("WEAVIATE_API_KEY", "")

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
RAPTOR_ENV = os.getenv("RAPTOR_ENV", "development").lower()
RAPTOR_PRODUCTION = RAPTOR_ENV in {"production", "prod"}
RAPTOR_PROCESS_ROLE = os.getenv("RAPTOR_PROCESS_ROLE", "all").lower()
RAPTOR_DB_ENGINE = os.getenv("RAPTOR_DB_ENGINE", "sqlite").lower()
RAPTOR_DATABASE_URL = os.getenv("RAPTOR_DATABASE_URL", "")
RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS = os.getenv("RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS", "false").lower() == "true"
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
RAPTOR_API_KEY = os.getenv("RAPTOR_API_KEY", "")
RAPTOR_AUTH_EXEMPT_HEALTH = os.getenv("RAPTOR_AUTH_EXEMPT_HEALTH", "true").lower() == "true"
RAPTOR_ALLOW_AUTH_DISABLED = os.getenv("RAPTOR_ALLOW_AUTH_DISABLED", "false").lower() == "true"
RAPTOR_SESSION_COOKIE_SECURE = os.getenv("RAPTOR_SESSION_COOKIE_SECURE", "false").lower() == "true"
RAPTOR_REQUIRE_RBAC = os.getenv("RAPTOR_REQUIRE_RBAC", "true").lower() == "true"
RAPTOR_RATE_LIMIT_BACKEND = os.getenv("RAPTOR_RATE_LIMIT_BACKEND", "memory").lower()
RAPTOR_TRUSTED_SSO_ENABLED = os.getenv("RAPTOR_TRUSTED_SSO_ENABLED", "false").lower() == "true"
RAPTOR_TRUSTED_PROXY_CIDRS = [
  item.strip()
  for item in os.getenv("RAPTOR_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128").split(",")
  if item.strip()
]
RAPTOR_SSO_USER_HEADER = os.getenv("RAPTOR_SSO_USER_HEADER", "x-forwarded-user").lower()
RAPTOR_SSO_ROLES_HEADER = os.getenv("RAPTOR_SSO_ROLES_HEADER", "x-forwarded-roles").lower()
RAPTOR_SSO_TENANT_HEADER = os.getenv("RAPTOR_SSO_TENANT_HEADER", "x-forwarded-tenant").lower()
RAPTOR_BOOTSTRAP_ADMIN_USERNAME = os.getenv("RAPTOR_BOOTSTRAP_ADMIN_USERNAME", "admin")
RAPTOR_BOOTSTRAP_ADMIN_PASSWORD = os.getenv("RAPTOR_BOOTSTRAP_ADMIN_PASSWORD", "")
RAPTOR_AUTH_MAX_FAILURES = int(os.getenv("RAPTOR_AUTH_MAX_FAILURES", "5"))
RAPTOR_AUTH_LOCK_SECONDS = int(os.getenv("RAPTOR_AUTH_LOCK_SECONDS", "900"))
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
CSRF_TRUSTED_ORIGINS = [
  origin.strip()
  for origin in os.getenv("CSRF_TRUSTED_ORIGINS", ",".join(CORS_ALLOW_ORIGINS)).split(",")
  if origin.strip()
]

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
def _project_path_from_env(name: str, default: str) -> Path:
    candidate = Path(os.getenv(name, default))
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


DATA_DIR = PROJECT_ROOT / "data"
STIX_DIR = DATA_DIR / "stix"
MOCK_DIR = DATA_DIR / "mock"
EVIDENCE_DIR = DATA_DIR / "evidence"
INTEL_DIR = DATA_DIR / "intel"
APT_REPORTS_DIR = _project_path_from_env("APT_REPORTS_DIR", str(INTEL_DIR / "apt_reports"))
DB_PATH = _project_path_from_env("RAPTOR_DB_PATH", str(DATA_DIR / "raptor.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
EVIDENCE_ENCRYPTION_KEY = os.getenv("EVIDENCE_ENCRYPTION_KEY", "")
EVIDENCE_RETENTION_DAYS = int(os.getenv("EVIDENCE_RETENTION_DAYS", "180"))

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
STIX_DIR.mkdir(exist_ok=True)
MOCK_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)
INTEL_DIR.mkdir(exist_ok=True)

# ─── ATT&CK STIX Source ──────────────────────────────────────────────
ATTACK_STIX_URL = os.getenv(
    "ATTACK_STIX_URL",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
)
ATTACK_STIX_SHA256 = os.getenv("ATTACK_STIX_SHA256", "")
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
      "tactics": ["reconnaissance|resource-development|initial-access|execution|persistence|privilege-escalation|defense-evasion|credential-access|discovery|lateral-movement|collection|command-and-control|exfiltration|impact"],
      "kill_chain_phase": "primary tactic from tactics",
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


def _is_placeholder(value: str) -> bool:
    lowered = str(value or "").lower()
    return not lowered or lowered.startswith("change_me") or "placeholder" in lowered


def validate_startup_config() -> None:
    """Fail fast when production mode is requested with unsafe lab defaults."""
    if RAPTOR_PROCESS_ROLE not in {"api", "worker", "all"}:
        raise RuntimeError("RAPTOR_PROCESS_ROLE must be one of: api, worker, all")
    if RAPTOR_DB_ENGINE not in {"sqlite", "postgresql"}:
        raise RuntimeError("RAPTOR_DB_ENGINE must be one of: sqlite, postgresql")
    if RAPTOR_RATE_LIMIT_BACKEND not in {"memory", "redis"}:
        raise RuntimeError("RAPTOR_RATE_LIMIT_BACKEND must be one of: memory, redis")

    if not RAPTOR_PRODUCTION:
        return

    failures = []
    if RAPTOR_DB_ENGINE == "postgresql" and _is_placeholder(RAPTOR_DATABASE_URL):
        failures.append("RAPTOR_DATABASE_URL must be set when RAPTOR_DB_ENGINE=postgresql")
    if RAPTOR_DB_ENGINE == "sqlite" and not RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS:
        failures.append(
            "SQLite is a single-node runtime store; set RAPTOR_ACKNOWLEDGE_SQLITE_LIMITS=true "
            "only for a deliberately single-node production deployment"
        )
    if _is_placeholder(RAPTOR_API_KEY):
        failures.append("RAPTOR_API_KEY must be set to a non-placeholder secret")
    if RAPTOR_ALLOW_AUTH_DISABLED:
        failures.append("RAPTOR_ALLOW_AUTH_DISABLED must be false")
    if not RAPTOR_REQUIRE_RBAC:
        failures.append("RAPTOR_REQUIRE_RBAC must be true")
    if not RAPTOR_SESSION_COOKIE_SECURE:
        failures.append("RAPTOR_SESSION_COOKIE_SECURE must be true behind TLS")
    if _is_placeholder(RAPTOR_BOOTSTRAP_ADMIN_PASSWORD):
        failures.append("RAPTOR_BOOTSTRAP_ADMIN_PASSWORD must be set to a non-placeholder secret")
    if _is_placeholder(EVIDENCE_ENCRYPTION_KEY):
        failures.append("EVIDENCE_ENCRYPTION_KEY must be set to a non-placeholder 32-byte/base64 key")
    if _is_placeholder(NEO4J_PASSWORD):
        failures.append("NEO4J_PASSWORD must be set to a non-placeholder secret")
    if "localhost" in ",".join(CORS_ALLOW_ORIGINS) or "127.0.0.1" in ",".join(CORS_ALLOW_ORIGINS):
        failures.append("CORS_ALLOW_ORIGINS must be set to production frontend origins")
    if RAPTOR_PROCESS_ROLE == "all":
        failures.append("RAPTOR_PROCESS_ROLE=all is for local development; use separate api and worker processes")
    if RAPTOR_RATE_LIMIT_BACKEND != "redis":
        failures.append("RAPTOR_RATE_LIMIT_BACKEND=redis is required for production multi-process rate limiting")
    if RAPTOR_TRUSTED_SSO_ENABLED and not RAPTOR_TRUSTED_PROXY_CIDRS:
        failures.append("RAPTOR_TRUSTED_PROXY_CIDRS must be set when trusted SSO headers are enabled")

    if failures:
        joined = "; ".join(failures)
        raise RuntimeError(f"Unsafe RAPTOR production configuration: {joined}")
