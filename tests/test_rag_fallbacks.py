import tempfile
import unittest
from pathlib import Path

from helpers import BACKEND_DIR  # noqa: F401
from attribution import attack_catalog
from rag import pipeline, reranker, retriever


class RagFallbackTests(unittest.TestCase):
    def test_glm_streaming_collector_discards_reasoning_chunks(self):
        class Delta:
            def __init__(self, content=None, reasoning_content=None):
                self.content = content
                self.reasoning_content = reasoning_content

        class Choice:
            def __init__(self, delta):
                self.delta = delta

        class Chunk:
            def __init__(self, delta):
                self.choices = [Choice(delta)]

        class Completions:
            def __init__(self):
                self.calls = []

            def create(self, **kwargs):
                self.calls.append(kwargs)
                return [
                    Chunk(Delta(reasoning_content="private reasoning")),
                    Chunk(Delta(content="final ")),
                    Chunk(Delta(content="answer")),
                ]

        class Chat:
            def __init__(self):
                self.completions = Completions()

        class Client:
            def __init__(self):
                self.chat = Chat()

        original_stream = pipeline.LLM_STREAM_RESPONSES
        pipeline.LLM_STREAM_RESPONSES = True
        try:
            client = Client()
            content = pipeline._chat_completion_content(client, {"model": "z-ai/glm-5.1"}, "z-ai/glm-5.1")
        finally:
            pipeline.LLM_STREAM_RESPONSES = original_stream

        self.assertEqual(content, "final answer")
        self.assertTrue(client.chat.completions.calls[0]["stream"])

    def test_glm_extra_body_enables_thinking_without_clearing(self):
        original_enable = pipeline.LLM_ENABLE_THINKING
        original_clear = pipeline.LLM_CLEAR_THINKING
        pipeline.LLM_ENABLE_THINKING = True
        pipeline.LLM_CLEAR_THINKING = False
        try:
            extra_body = pipeline._llm_extra_body("z-ai/glm-5.1")
        finally:
            pipeline.LLM_ENABLE_THINKING = original_enable
            pipeline.LLM_CLEAR_THINKING = original_clear

        self.assertEqual(
            extra_body,
            {"chat_template_kwargs": {"enable_thinking": True, "clear_thinking": False}},
        )

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
            original_stix_dir = attack_catalog.STIX_DIR
            try:
                retriever._LOCAL_CORPUS = None
                attack_catalog.STIX_DIR = Path(tmp)
                attack_catalog.STIX_DIR.mkdir(parents=True, exist_ok=True)
                (attack_catalog.STIX_DIR / "enterprise-attack.json").write_text(
                    """
                    {
                      "objects": [
                        {
                          "type": "attack-pattern",
                          "id": "attack-pattern--1",
                          "name": "Command and Scripting Interpreter",
                          "description": "Adversaries may abuse PowerShell for execution.",
                          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
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
                attack_catalog.STIX_DIR = original_stix_dir

        self.assertEqual(results[0]["technique_id"], "T1059")
        self.assertEqual(results[0]["tactics"], ["execution"])
        self.assertEqual(results[0]["_retrieval_backend"], "local-stix")


if __name__ == "__main__":
    unittest.main()
