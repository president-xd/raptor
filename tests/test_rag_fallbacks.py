import tempfile
import unittest
from pathlib import Path

from helpers import BACKEND_DIR  # noqa: F401
from rag import reranker, retriever


class RagFallbackTests(unittest.TestCase):
    def test_reranker_uses_lexical_fallback_when_model_unavailable(self):
        original_get_reranker = reranker.get_reranker
        reranker.get_reranker = lambda: None
        try:
            docs = [
                {"technique_id": "T0001", "description": "benign service activity", "_score": 0.1},
                {"technique_id": "T1059", "description": "powershell command execution", "_score": 0.1},
            ]
            ranked = reranker.rerank_results("powershell execution", docs, top_k=1)
        finally:
            reranker.get_reranker = original_get_reranker

        self.assertEqual(ranked[0]["technique_id"], "T1059")
        self.assertEqual(ranked[0]["_rerank_backend"], "lexical")

    def test_local_retriever_returns_attack_context_without_weaviate(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_corpus = retriever._LOCAL_CORPUS
            original_stix_dir = retriever.STIX_DIR
            try:
                retriever._LOCAL_CORPUS = None
                retriever.STIX_DIR = Path(tmp)
                retriever.STIX_DIR.mkdir(parents=True, exist_ok=True)
                (retriever.STIX_DIR / "enterprise-attack.json").write_text(
                    """
                    {
                      "objects": [
                        {
                          "type": "attack-pattern",
                          "id": "attack-pattern--1",
                          "name": "Command and Scripting Interpreter",
                          "description": "Adversaries may abuse PowerShell for execution.",
                          "kill_chain_phases": [{"phase_name": "execution"}],
                          "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]
                        }
                      ]
                    }
                    """,
                    encoding="utf-8",
                )
                local = retriever.HybridRetriever.__new__(retriever.HybridRetriever)
                local.client = None
                local._owns_client = False
                local.local_fallback_enabled = True
                results = local.search_techniques("PowerShell execution", limit=3)
            finally:
                retriever._LOCAL_CORPUS = original_corpus
                retriever.STIX_DIR = original_stix_dir

        self.assertEqual(results[0]["technique_id"], "T1059")
        self.assertEqual(results[0]["_retrieval_backend"], "local-stix")


if __name__ == "__main__":
    unittest.main()
