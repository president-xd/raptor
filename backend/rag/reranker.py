"""
RAPTOR | Reranker
Uses BGE-reranker-large to rerank retrieved results from k=20 to k=5.
Per spec Section 3.6: "Do not skip this. Without reranking, top-k retrieval
at k=20 returns too much noise."
"""
from typing import List, Dict, Any, Tuple
from loguru import logger

_reranker = None


def get_reranker():
    """Lazy-load the reranker model."""
    global _reranker
    if _reranker is None:
        try:
            from sentence_transformers import CrossEncoder
            model_name = "BAAI/bge-reranker-base"  # Use base for faster inference; upgrade to -large if GPU available
            logger.info(f"Loading reranker model: {model_name}")
            _reranker = CrossEncoder(model_name, max_length=512)
            logger.info(f"Reranker loaded: {model_name}")
        except Exception as e:
            logger.warning(f"Failed to load reranker: {e}. Reranking will be skipped.")
            _reranker = None
    return _reranker


def rerank_results(query: str, documents: List[Dict[str, Any]], top_k: int = 5,
                   content_key: str = "description") -> List[Dict[str, Any]]:
    """
    Rerank documents using cross-encoder.
    
    Args:
        query: The search query
        documents: List of document dicts from retriever
        top_k: Number of results to keep after reranking
        content_key: Key in document dict containing the text to rerank on
    
    Returns:
        Top-k reranked documents with _rerank_score added
    """
    if not documents:
        return []

    reranker = get_reranker()

    if reranker is None:
        # Fallback: sort by existing score and truncate
        logger.warning("Reranker not available, using retrieval scores only")
        sorted_docs = sorted(documents, key=lambda x: x.get("_score", 0), reverse=True)
        return sorted_docs[:top_k]

    # Build query-document pairs
    pairs = []
    for doc in documents:
        text = doc.get(content_key, "") or doc.get("content", "") or doc.get("name", "")
        if isinstance(text, str):
            pairs.append((query, text[:512]))  # Truncate to max_length
        else:
            pairs.append((query, str(text)[:512]))

    try:
        # Score all pairs
        scores = reranker.predict(pairs, show_progress_bar=False)

        # Attach scores and sort
        for i, doc in enumerate(documents):
            doc["_rerank_score"] = float(scores[i])

        reranked = sorted(documents, key=lambda x: x.get("_rerank_score", 0), reverse=True)

        logger.debug(f"Reranked {len(documents)} -> top {top_k} results")
        return reranked[:top_k]

    except Exception as e:
        logger.warning(f"Reranking failed: {e}. Using original order.")
        return documents[:top_k]


def rerank_technique_results(query: str, techniques: List[Dict], top_k: int = 5) -> List[Dict]:
    """Rerank technique search results."""
    return rerank_results(query, techniques, top_k, content_key="description")


def rerank_report_results(query: str, reports: List[Dict], top_k: int = 5) -> List[Dict]:
    """Rerank threat report search results."""
    return rerank_results(query, reports, top_k, content_key="content")
