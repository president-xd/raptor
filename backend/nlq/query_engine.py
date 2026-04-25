"""
RAPTOR | Natural Language Query Engine
Per spec Section 7.3: the killer differentiator.
Routes questions to graph (Cypher), RAG, or simulation sub-pipelines.
"""
import json
from typing import Dict, Any, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import NLQ_CYPHER_PROMPT
from rag.pipeline import call_llm
from rag.retriever import HybridRetriever
from rag.reranker import rerank_technique_results


class QueryEngine:
    """Natural language query engine with multi-pipeline routing."""

    def __init__(self, neo4j_client=None):
        self.neo4j = neo4j_client
        self.retriever = None

    def answer_question(self, question: str, investigation_id: str = "") -> Dict[str, Any]:
        """
        Answer a natural language question by routing to the appropriate pipeline.
        Per spec Section 7.3.
        """
        logger.info(f"NLQ: '{question}' (investigation: {investigation_id})")

        # Classify the question type
        query_type = self._classify_question(question)
        logger.info(f"NLQ classified as: {query_type}")

        if query_type == "graph":
            return self._handle_graph_query(question, investigation_id)
        elif query_type == "simulation":
            return self._handle_simulation_query(question, investigation_id)
        else:
            return self._handle_rag_query(question, investigation_id)

    def _classify_question(self, question: str) -> str:
        """Classify question type for routing."""
        q = question.lower()

        # Graph queries: paths, hops, connections, hosts
        graph_keywords = ['path', 'hop', 'reach', 'connect', 'lateral', 'domain controller',
                         'which hosts', 'how many hosts', 'compromised', 'shortest']
        if any(k in q for k in graph_keywords):
            return "graph"

        # Simulation queries: next, predict, would do, block, contain
        sim_keywords = ['next', 'predict', 'would do', 'likely', 'block', 'contain',
                       'prevent', 'what should i']
        if any(k in q for k in sim_keywords):
            return "simulation"

        # Default: RAG query
        return "rag"

    def _handle_graph_query(self, question: str, investigation_id: str) -> Dict[str, Any]:
        """Translate NL to Cypher and execute against Neo4j."""
        # Generate Cypher via LLM (grounded by schema in prompt)
        prompt = NLQ_CYPHER_PROMPT.format(question=question)
        try:
            cypher = call_llm("You are a Neo4j Cypher expert. Return ONLY the query.", prompt)
        except Exception as e:
            logger.error(f"Cypher generation failed: {e}")
            return {
                "answer": "Graph query generation is unavailable. Review the Attack Graph tab for host movement and observed techniques.",
                "sources": [{"type": "neo4j", "error": str(e)}],
                "confidence": "low",
                "query_type": "graph",
            }

        # Clean the cypher
        cypher = cypher.strip().strip('`').strip()
        if cypher.startswith("cypher"):
            cypher = cypher[6:].strip()

        logger.info(f"Generated Cypher: {cypher}")

        # Execute if Neo4j is available
        results = []
        if self.neo4j and self.neo4j.is_connected():
            try:
                # Inject investigation_id parameter
                results = self.neo4j.run_query(cypher, {"inv_id": investigation_id,
                                                         "investigation_id": investigation_id})
            except Exception as e:
                logger.error(f"Cypher execution failed: {e}")
                results = [{"error": str(e)}]

        # Synthesize answer
        answer = self._synthesize_graph_answer(question, results, cypher)

        return {
            "answer": answer,
            "sources": [{"type": "neo4j", "query": cypher, "results": results[:10]}],
            "confidence": "high" if results else "low",
            "query_type": "graph",
        }

    def _handle_rag_query(self, question: str, investigation_id: str) -> Dict[str, Any]:
        """Answer using RAG retrieval from ATT&CK knowledge base."""
        if self.retriever is None:
            self.retriever = HybridRetriever()

        # Retrieve relevant context
        results = self.retriever.search_all(question)
        techniques = rerank_technique_results(question, results.get("techniques", []), top_k=5)

        # Build context for LLM
        context_lines = []
        sources = []
        for t in techniques:
            context_lines.append(f"- {t.get('technique_id', '')}: {t.get('name', '')} — {t.get('description', '')[:300]}")
            sources.append({"type": "att&ck", "technique_id": t.get("technique_id", ""),
                           "name": t.get("name", "")})

        for r in results.get("reports", [])[:3]:
            context_lines.append(f"- [{r.get('apt_group', '')}] {r.get('content', '')[:300]}")
            sources.append({"type": "threat_report", "apt_group": r.get("apt_group", ""),
                           "title": r.get("title", "")})

        prompt = f"""Based on the following retrieved ATT&CK context, answer this question:

Question: {question}

Retrieved Context:
{chr(10).join(context_lines) if context_lines else 'No relevant context found.'}

Provide a clear, specific answer citing the ATT&CK techniques referenced."""

        try:
            answer = call_llm("You are a cybersecurity analyst. Answer based on the retrieved context.", prompt)
        except Exception as e:
            logger.error(f"RAG answer generation failed: {e}")
            if techniques:
                joined = ", ".join(f"{t.get('technique_id', '')} {t.get('name', '')}".strip() for t in techniques[:5])
                answer = f"LLM answer generation is unavailable. Relevant ATT&CK context retrieved: {joined}."
            else:
                answer = "LLM answer generation is unavailable and no relevant ATT&CK context was retrieved."

        return {
            "answer": answer,
            "sources": sources,
            "confidence": "high" if techniques else "medium",
            "query_type": "rag",
        }

    def _handle_simulation_query(self, question: str, investigation_id: str) -> Dict[str, Any]:
        """Answer simulation/prediction questions."""
        # Use RAG context + simulation reasoning
        if self.retriever is None:
            self.retriever = HybridRetriever()

        results = self.retriever.search_all(question)
        techniques = rerank_technique_results(question, results.get("techniques", []), top_k=5)

        context_lines = []
        for t in techniques:
            context_lines.append(f"- {t.get('technique_id', '')}: {t.get('name', '')} — {t.get('description', '')[:200]}")

        prompt = f"""You are a cybersecurity analyst advising on defense.

Question: {question}

Retrieved ATT&CK Context:
{chr(10).join(context_lines) if context_lines else 'No context available.'}

Provide actionable, specific recommendations based on ATT&CK framework."""

        try:
            answer = call_llm("You are a senior SOC analyst providing defensive recommendations.", prompt)
        except Exception as e:
            logger.error(f"Simulation query generation failed: {e}")
            answer = (
                "LLM recommendation generation is unavailable. Prioritize isolating compromised hosts, "
                "resetting exposed credentials, blocking suspected C2 infrastructure, and hunting for "
                "the observed ATT&CK techniques across adjacent systems."
            )

        return {
            "answer": answer,
            "sources": [{"type": "att&ck", "technique_id": t.get("technique_id", "")} for t in techniques[:5]],
            "confidence": "medium",
            "query_type": "simulation",
        }

    def _synthesize_graph_answer(self, question: str, results: list, cypher: str) -> str:
        """Convert graph query results into natural language answer."""
        if not results:
            return "No matching paths or nodes found in the attack graph for this investigation."

        # Use LLM to synthesize
        prompt = f"""Convert these Neo4j graph query results into a clear natural language answer.

Original question: {question}
Cypher query used: {cypher}
Results: {json.dumps(results[:10], indent=2, default=str)}

Provide a clear, concise answer."""

        try:
            return call_llm("Convert graph database results to natural language.", prompt)
        except Exception as e:
            logger.error(f"Graph answer synthesis failed: {e}")
            return f"Graph results returned {len(results)} rows. First rows: {json.dumps(results[:3], default=str)}"

    def close(self):
        if self.retriever:
            self.retriever.close()
