"""
RAPTOR | Reranker
Uses the configured BGE cross-encoder reranker to reduce retrieved results from
k=20 to k=5. If the model is unavailable, RAPTOR applies a deterministic lexical
rerank instead of silently skipping the reranking stage.
"""
import re
from typing import List, Dict, Any
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import RERANKER_MODEL

_reranker = None
_TOKEN_RE = re.compile(r"[a-z0-9_.-]+")


def _use_lexical_test_rerank() -> bool:
    return os.environ.get("RAPTOR_ALLOW_TEST_EMBEDDINGS", "false").lower() == "true"


def get_reranker():
    """Lazy-load the reranker model."""
    global _reranker
    if _use_lexical_test_rerank():
        logger.warning("Using lexical rerank fallback (RAPTOR_ALLOW_TEST_EMBEDDINGS=true)")
        _reranker = None
        return None

    if _reranker is None:
        try:
            from sentence_transformers import CrossEncoder
            model_name = RERANKER_MODEL
            logger.info(f"Loading reranker model: {model_name}")
            _reranker = CrossEncoder(model_name, max_length=512)
            logger.info(f"Reranker loaded: {model_name}")
        except Exception as e:
            logger.warning(f"Failed to load reranker: {e}. Lexical rerank fallback will be used.")
            _reranker = None
    return _reranker


def _tokens(text: str) -> set[str]:
    return {token for token in _TOKEN_RE.findall(str(text).lower()) if len(token) > 1}


def _document_text(doc: Dict[str, Any], content_key: str) -> str:
    return str(doc.get(content_key, "") or doc.get("content", "") or doc.get("description", "") or doc.get("name", ""))


def _lexical_rerank(query: str, documents: List[Dict[str, Any]], top_k: int, content_key: str) -> List[Dict[str, Any]]:
    query_tokens = _tokens(query)
    scored = []
    for index, doc in enumerate(documents):
        text = _document_text(doc, content_key)
        overlap = len(query_tokens & _tokens(text))
        score = overlap + float(doc.get("_score", 0) or 0) * 0.01
        updated = dict(doc)
        updated["_rerank_score"] = float(score)
        updated["_rerank_backend"] = "lexical"
        scored.append((score, -index, updated))
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in scored[:top_k]]


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
        logger.warning("Reranker not available, using lexical rerank fallback")
        return _lexical_rerank(query, documents, top_k, content_key)

    # Build query-document pairs
    pairs = []
    for doc in documents:
        text = _document_text(doc, content_key)
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
            doc["_rerank_backend"] = RERANKER_MODEL

        reranked = sorted(documents, key=lambda x: x.get("_rerank_score", 0), reverse=True)

        logger.debug(f"Reranked {len(documents)} -> top {top_k} results")
        return reranked[:top_k]

    except Exception as e:
        logger.warning(f"Reranking failed: {e}. Using lexical fallback.")
        return _lexical_rerank(query, documents, top_k, content_key)


def rerank_technique_results(query: str, techniques: List[Dict], top_k: int = 5) -> List[Dict]:
    """Rerank technique search results."""
    return rerank_results(query, techniques, top_k, content_key="description")


def rerank_report_results(query: str, reports: List[Dict], top_k: int = 5) -> List[Dict]:
    """Rerank threat report search results."""
    return rerank_results(query, reports, top_k, content_key="content")
