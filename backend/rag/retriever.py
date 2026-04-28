"""
RAPTOR | Hybrid Retriever
Implements hybrid BM25 + semantic search in Weaviate.
Alpha = 0.6 (60% semantic, 40% BM25) per spec Section 3.3.
"""
import json
import os
import re
from typing import List, Dict, Any
from loguru import logger

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    APT_REPORTS_DIR,
    ATTACK_STIX_URL,
    RAG_HYBRID_ALPHA,
    RAG_LOCAL_FALLBACK_ENABLED,
    RAG_RETRIEVAL_K,
    STIX_DIR,
    WEAVIATE_API_KEY,
    WEAVIATE_GRPC_URL,
    WEAVIATE_URL,
)
from rag.embeddings import embed_query


_INDEX_BOOTSTRAP_ATTEMPTED = False
_LOCAL_CORPUS = None
_TOKEN_RE = re.compile(r"[a-z0-9_.-]+")


def _split_host_port(endpoint: str, default_port: int) -> tuple[str, int]:
    cleaned = endpoint.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in cleaned:
        host, port = cleaned.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    return cleaned, default_port


def get_weaviate_client():
    """Get Weaviate client."""
    import weaviate
    http_host, http_port = _split_host_port(WEAVIATE_URL, 8080)
    grpc_host, grpc_port = _split_host_port(WEAVIATE_GRPC_URL, 50051)
    auth_credentials = weaviate.auth.AuthApiKey(WEAVIATE_API_KEY) if WEAVIATE_API_KEY else None

    try:
        return weaviate.connect_to_custom(
            http_host=http_host,
            http_port=http_port,
            http_secure=False,
            grpc_host=grpc_host,
            grpc_port=grpc_port,
            grpc_secure=False,
            auth_credentials=auth_credentials,
        )
    except Exception:
        # Compatibility fallback for client variants
        return weaviate.connect_to_local(
            host=http_host,
            port=http_port,
            grpc_port=grpc_port,
            auth_credentials=auth_credentials,
        )


def _tokenize(text: str) -> set[str]:
    return {token for token in _TOKEN_RE.findall(str(text).lower()) if len(token) > 1}


def _load_stix_bundle() -> dict:
    cache_path = STIX_DIR / "enterprise-attack.json"
    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    import requests
    response = requests.get(ATTACK_STIX_URL, timeout=120)
    response.raise_for_status()
    bundle = response.json()
    STIX_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(bundle), encoding="utf-8")
    return bundle


def _load_local_threat_reports(groups: list[dict]) -> list[dict]:
    """Load local report corpus files, with STIX group profiles as a fallback corpus."""
    reports: list[dict] = []
    if APT_REPORTS_DIR.exists():
        for path in sorted(APT_REPORTS_DIR.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".txt", ".md", ".json", ".jsonl"}:
                continue
            try:
                if path.suffix.lower() == ".jsonl":
                    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        if not line.strip():
                            continue
                        item = json.loads(line)
                        reports.append({
                            "title": item.get("title") or path.stem,
                            "content": item.get("content") or item.get("text") or "",
                            "apt_group": item.get("apt_group") or item.get("actor") or "Unknown",
                            "source": item.get("source") or str(path.relative_to(APT_REPORTS_DIR)),
                        })
                elif path.suffix.lower() == ".json":
                    payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                    items = payload if isinstance(payload, list) else payload.get("reports", [payload])
                    for item in items:
                        reports.append({
                            "title": item.get("title") or path.stem,
                            "content": item.get("content") or item.get("text") or "",
                            "apt_group": item.get("apt_group") or item.get("actor") or "Unknown",
                            "source": item.get("source") or str(path.relative_to(APT_REPORTS_DIR)),
                        })
                else:
                    reports.append({
                        "title": path.stem.replace("_", " ").replace("-", " ").title(),
                        "content": path.read_text(encoding="utf-8", errors="ignore"),
                        "apt_group": "Unknown",
                        "source": str(path.relative_to(APT_REPORTS_DIR)),
                    })
            except Exception as e:
                logger.debug(f"Skipping local report {path}: {e}")

    reports = [report for report in reports if report.get("content")]
    if reports:
        return reports

    fallback = []
    for group in groups:
        description = group.get("description", "")
        if not description:
            continue
        fallback.append({
            "title": f"ATT&CK Threat Profile: {group.get('name', 'Unknown')}",
            "content": description,
            "apt_group": group.get("name", "Unknown"),
            "source": "MITRE ATT&CK STIX intrusion-set profile",
        })
    return fallback


def _build_local_corpus() -> dict[str, list[dict]]:
    global _LOCAL_CORPUS
    if _LOCAL_CORPUS is not None:
        return _LOCAL_CORPUS

    try:
        bundle = _load_stix_bundle()
    except Exception as e:
        logger.warning(f"Local RAG fallback corpus unavailable: {e}")
        _LOCAL_CORPUS = {"Technique": [], "ThreatReport": [], "Vulnerability": []}
        return _LOCAL_CORPUS

    techniques = []
    groups = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "intrusion-set":
            groups.append(obj)
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break
        if not technique_id:
            continue
        phase = ""
        kill_chain = obj.get("kill_chain_phases", [])
        if kill_chain:
            phase = kill_chain[0].get("phase_name", "")
        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactic": phase.replace("-", " ").title() if phase else "",
            "kill_chain_phase": phase,
            "detection": "",
            "_collection": "Technique",
        })

    reports = _load_local_threat_reports(groups)
    for report in reports:
        report["_collection"] = "ThreatReport"

    _LOCAL_CORPUS = {"Technique": techniques, "ThreatReport": reports, "Vulnerability": []}
    logger.info(
        f"Local RAG fallback ready: {len(techniques)} ATT&CK techniques, "
        f"{len(reports)} threat profile/report records"
    )
    return _LOCAL_CORPUS


def _local_search(collection_name: str, query: str, limit: int, properties: list[str]) -> list[dict[str, Any]]:
    corpus = _build_local_corpus().get(collection_name, [])
    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    scored = []
    for doc in corpus:
        text = " ".join(str(doc.get(prop, "")) for prop in properties)
        doc_tokens = _tokenize(text)
        exact_id_bonus = 5 if doc.get("technique_id", "").lower() in query.lower() else 0
        overlap = len(query_tokens & doc_tokens)
        if overlap or exact_id_bonus:
            score = overlap + exact_id_bonus
            scored.append((score, doc))

    scored.sort(key=lambda item: item[0], reverse=True)
    results = []
    for score, doc in scored[:limit]:
        result = {prop: doc.get(prop, "") for prop in properties}
        result["_score"] = float(score)
        result["_collection"] = collection_name
        result["_retrieval_backend"] = "local-stix"
        results.append(result)
    return results


class HybridRetriever:
    """Hybrid BM25 + semantic search over Weaviate collections."""

    def __init__(self, client=None):
        self.client = client
        self._owns_client = False
        self.local_fallback_enabled = RAG_LOCAL_FALLBACK_ENABLED
        if self.client is None:
            try:
                self.client = get_weaviate_client()
                self._owns_client = True
                self._bootstrap_index_if_needed()
            except Exception as e:
                logger.warning(f"Could not connect to Weaviate: {e}; local RAG fallback will be used")
                self.client = None

    def _bootstrap_index_if_needed(self):
        """Optionally run one-time indexing if required collections are missing."""
        global _INDEX_BOOTSTRAP_ATTEMPTED

        if _INDEX_BOOTSTRAP_ATTEMPTED or self.client is None:
            return

        _INDEX_BOOTSTRAP_ATTEMPTED = True

        auto_index = os.getenv("RAG_AUTO_INDEX", "false").lower() == "true"
        if not auto_index:
            return

        try:
            required = ["Technique", "ThreatReport"]
            missing = [name for name in required if not self.client.collections.exists(name)]
            if not missing:
                return

            logger.warning(f"Weaviate collections missing ({missing}); running one-time indexing bootstrap")
            from rag.indexer import run_full_indexing
            result = run_full_indexing()
            logger.info(f"RAG bootstrap indexing result: {result}")
        except Exception as e:
            logger.warning(f"RAG bootstrap indexing skipped due to error: {e}")

    def search_techniques(self, query: str, limit: int = RAG_RETRIEVAL_K) -> List[Dict[str, Any]]:
        """Hybrid search in the Technique collection."""
        return self._hybrid_search("Technique", query, limit, [
            "technique_id", "name", "description", "tactic", "kill_chain_phase", "detection"
        ])

    def search_reports(self, query: str, limit: int = RAG_RETRIEVAL_K) -> List[Dict[str, Any]]:
        """Hybrid search in the ThreatReport collection."""
        return self._hybrid_search("ThreatReport", query, limit, [
            "title", "content", "apt_group", "source"
        ])

    def search_vulnerabilities(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Hybrid search in the Vulnerability collection."""
        return self._hybrid_search("Vulnerability", query, limit, [
            "cve_id", "description", "related_techniques", "severity"
        ])

    def search_all(self, query: str, limit: int = RAG_RETRIEVAL_K) -> Dict[str, List[Dict]]:
        """Search across all collections and return combined results."""
        results = {
            "techniques": self.search_techniques(query, limit),
            "reports": self.search_reports(query, limit // 2),
        }
        return results

    def _hybrid_search(self, collection_name: str, query: str, limit: int,
                       properties: List[str]) -> List[Dict[str, Any]]:
        """Execute hybrid search on a Weaviate collection."""
        if self.client is None:
            if self.local_fallback_enabled:
                return _local_search(collection_name, query, limit, properties)
            logger.warning("No Weaviate connection and local fallback disabled, returning empty results")
            return []

        try:
            collection = self.client.collections.get(collection_name)
            try:
                query_vector = embed_query(query).flatten().tolist()
            except Exception as e:
                logger.warning(f"Embedding unavailable for hybrid search; using BM25/local fallback: {e}")
                try:
                    results = collection.query.bm25(query=query, limit=limit, return_metadata=["score"])
                    documents = []
                    for obj in results.objects:
                        doc = {}
                        for prop in properties:
                            doc[prop] = getattr(obj.properties, prop, "") if hasattr(obj.properties, prop) else obj.properties.get(prop, "")
                        doc["_score"] = obj.metadata.score if obj.metadata and obj.metadata.score else 0.0
                        doc["_collection"] = collection_name
                        doc["_retrieval_backend"] = "weaviate-bm25"
                        documents.append(doc)
                    return documents
                except Exception as bm25_error:
                    logger.warning(f"Weaviate BM25 fallback failed on {collection_name}: {bm25_error}")
                    return _local_search(collection_name, query, limit, properties) if self.local_fallback_enabled else []

            results = collection.query.hybrid(
                query=query,
                vector=query_vector,
                alpha=RAG_HYBRID_ALPHA,  # 0.6 = 60% semantic, 40% BM25
                limit=limit,
                return_metadata=["score"],
            )

            documents = []
            for obj in results.objects:
                doc = {}
                for prop in properties:
                    doc[prop] = getattr(obj.properties, prop, "") if hasattr(obj.properties, prop) else obj.properties.get(prop, "")
                doc["_score"] = obj.metadata.score if obj.metadata and obj.metadata.score else 0.0
                doc["_collection"] = collection_name
                doc["_retrieval_backend"] = "weaviate-hybrid"
                documents.append(doc)

            logger.debug(f"Hybrid search on {collection_name}: {len(documents)} results for '{query[:50]}...'")
            return documents

        except Exception as e:
            logger.warning(f"Hybrid search failed on {collection_name}: {e}")
            return _local_search(collection_name, query, limit, properties) if self.local_fallback_enabled else []

    def close(self):
        """Close the Weaviate client if we own it."""
        if self._owns_client and self.client:
            try:
                self.client.close()
            except Exception:
                pass
