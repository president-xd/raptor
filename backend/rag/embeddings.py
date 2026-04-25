"""
RAPTOR | Embedding Wrapper
Uses BAAI/bge-large-en-v1.5 as specified in Section 3.2.
Falls back to a lightweight model if GPU is unavailable.
"""
import os
import numpy as np
from typing import List, Union
from loguru import logger

# Lazy-load to avoid import time penalty
_model = None
_model_name = None


def _allow_test_fallback() -> bool:
    return os.environ.get("RAPTOR_ALLOW_TEST_EMBEDDINGS", "false").lower() == "true"


def _deterministic_test_embedding(text: str, dim: int = 1024) -> np.ndarray:
    """Deterministic non-semantic embedding for explicit test-only mode."""
    import hashlib

    digest = hashlib.sha512(text.encode("utf-8")).digest()
    seed = int.from_bytes(digest[:8], byteorder="big", signed=False)
    rng = np.random.default_rng(seed)
    vec = rng.standard_normal(dim).astype(np.float32)
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def get_model():
    """Lazy-load the embedding model."""
    global _model, _model_name
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            model_name = os.environ.get("EMBEDDING_MODEL", "BAAI/bge-large-en-v1.5")
            logger.info(f"Loading embedding model: {model_name}")
            _model = SentenceTransformer(model_name)
            _model_name = model_name
            logger.info(f"Embedding model loaded: {model_name} (dim={_model.get_sentence_embedding_dimension()})")
        except Exception as e:
            logger.warning(f"Failed to load embedding model: {e}. Using fallback.")
            _model = None
            _model_name = "fallback"
    return _model


def embed_texts(texts: Union[str, List[str]], prefix: str = "") -> np.ndarray:
    """Embed one or more texts. Returns numpy array of shape (n, dim)."""
    if isinstance(texts, str):
        texts = [texts]

    # BGE models benefit from a query prefix for retrieval
    if prefix:
        texts = [f"{prefix}{t}" for t in texts]

    model = get_model()
    if model is not None:
        embeddings = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return np.array(embeddings)

    if _allow_test_fallback():
        logger.warning("Using deterministic test embeddings (RAPTOR_ALLOW_TEST_EMBEDDINGS=true)")
        vectors = [_deterministic_test_embedding(t) for t in texts]
        return np.array(vectors)

    raise RuntimeError(
        "Embedding model is unavailable. Install sentence-transformers or set "
        "RAPTOR_ALLOW_TEST_EMBEDDINGS=true for non-production deterministic test vectors."
    )


def embed_query(text: str) -> np.ndarray:
    """Embed a search query with BGE query prefix."""
    return embed_texts(text, prefix="Represent this sentence for searching relevant passages: ")


def embed_document(text: str) -> np.ndarray:
    """Embed a document chunk for storage."""
    return embed_texts(text, prefix="")


def get_embedding_dimension() -> int:
    """Return the embedding dimension."""
    model = get_model()
    if model is not None:
        return model.get_sentence_embedding_dimension()
    return 1024  # BGE-large default
