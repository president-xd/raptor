"""
RAPTOR | Hybrid Retriever
Implements hybrid BM25 + semantic search in Weaviate.
Alpha = 0.6 (60% semantic, 40% BM25) per spec Section 3.3.
"""
import os
from typing import List, Dict, Any
from loguru import logger

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import WEAVIATE_URL, WEAVIATE_GRPC_URL, RAG_HYBRID_ALPHA, RAG_RETRIEVAL_K
from rag.embeddings import embed_query


_INDEX_BOOTSTRAP_ATTEMPTED = False


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

    try:
        return weaviate.connect_to_custom(
            http_host=http_host,
            http_port=http_port,
            http_secure=False,
            grpc_host=grpc_host,
            grpc_port=grpc_port,
            grpc_secure=False,
        )
    except Exception:
        # Compatibility fallback for client variants
        return weaviate.connect_to_local(host=http_host, port=http_port)


class HybridRetriever:
    """Hybrid BM25 + semantic search over Weaviate collections."""

    def __init__(self, client=None):
        self.client = client
        self._owns_client = False
        if self.client is None:
            try:
                self.client = get_weaviate_client()
                self._owns_client = True
                self._bootstrap_index_if_needed()
            except Exception as e:
                logger.warning(f"Could not connect to Weaviate: {e}")
                self.client = None

    def _bootstrap_index_if_needed(self):
        """Optionally run one-time indexing if required collections are missing."""
        global _INDEX_BOOTSTRAP_ATTEMPTED

        if _INDEX_BOOTSTRAP_ATTEMPTED or self.client is None:
            return

        _INDEX_BOOTSTRAP_ATTEMPTED = True

        auto_index = os.getenv("RAG_AUTO_INDEX", "true").lower() == "true"
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
            logger.warning("No Weaviate connection, returning empty results")
            return []

        try:
            query_vector = embed_query(query).flatten().tolist()
            collection = self.client.collections.get(collection_name)

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
                documents.append(doc)

            logger.debug(f"Hybrid search on {collection_name}: {len(documents)} results for '{query[:50]}...'")
            return documents

        except Exception as e:
            logger.warning(f"Hybrid search failed on {collection_name}: {e}")
            return []

    def close(self):
        """Close the Weaviate client if we own it."""
        if self._owns_client and self.client:
            try:
                self.client.close()
            except Exception:
                pass
