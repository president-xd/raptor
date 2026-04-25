"""
RAPTOR | Hybrid Retriever
Implements hybrid BM25 + semantic search in Weaviate.
Alpha = 0.6 (60% semantic, 40% BM25) per spec Section 3.3.
"""
from typing import List, Dict, Any
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import WEAVIATE_URL, RAG_HYBRID_ALPHA, RAG_RETRIEVAL_K
from rag.embeddings import embed_query


def get_weaviate_client():
    """Get Weaviate client."""
    import weaviate
    client = weaviate.connect_to_local(
        host=WEAVIATE_URL.replace("http://", "").split(":")[0],
        port=int(WEAVIATE_URL.split(":")[-1]),
    )
    return client


class HybridRetriever:
    """Hybrid BM25 + semantic search over Weaviate collections."""

    def __init__(self, client=None):
        self.client = client
        self._owns_client = False
        if self.client is None:
            try:
                self.client = get_weaviate_client()
                self._owns_client = True
            except Exception as e:
                logger.warning(f"Could not connect to Weaviate: {e}")
                self.client = None

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
