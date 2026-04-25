"""
RAPTOR | Natural Language Query Engine
Per spec Section 7.3: the killer differentiator.
Routes questions to graph (Cypher), RAG, or simulation sub-pipelines.
"""
import json
import re
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

    WRITE_OR_UNSAFE_CYPHER = re.compile(
        r"\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|LOAD\s+CSV|FOREACH|CALL\s+dbms|CALL\s+apoc)\b",
        re.IGNORECASE,
    )

    GRAPH_LABELS = "Host|User|Process|File|Network|Technique|APTGroup"

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
        cypher = None
        deterministic = self._deterministic_graph_query(question)
        if deterministic:
            cypher = deterministic
            logger.info(f"Using deterministic graph query: {cypher}")
        else:
            # Generate Cypher via LLM (grounded by schema in prompt)
            prompt = NLQ_CYPHER_PROMPT.format(question=question)
            try:
                generated = call_llm("You are a Neo4j Cypher expert. Return ONLY the query.", prompt)
                cypher = self._sanitize_and_scope_query(generated)
            except Exception as e:
                logger.error(f"Cypher generation failed: {e}")

        if not cypher:
            cypher = (
                "MATCH (h:Host {investigation_id: $investigation_id, compromised: true}) "
                "RETURN h.hostname AS hostname, h.ip AS ip, h.compromise_time AS compromise_time "
                "ORDER BY h.compromise_time"
            )
            logger.warning("Falling back to safe default graph query")

        logger.info(f"Executing scoped Cypher: {cypher}")

        # Execute if Neo4j is available
        results = []
        if self.neo4j and self.neo4j.is_connected():
            try:
                results = self.neo4j.run_query(
                    cypher,
                    {"investigation_id": investigation_id, "inv_id": investigation_id},
                )
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

    def _deterministic_graph_query(self, question: str) -> Optional[str]:
        """Return parameterized read-only queries for common graph intents."""
        q = question.lower()

        if "how many" in q and "compromised" in q and "host" in q:
            return (
                "MATCH (h:Host {investigation_id: $investigation_id, compromised: true}) "
                "RETURN count(h) AS compromised_hosts"
            )

        if "lateral" in q and any(token in q for token in ["path", "movement", "move"]):
            return (
                "MATCH (a:Host {investigation_id: $investigation_id})"
                "-[r:LATERAL_MOVED_TO]->"
                "(b:Host {investigation_id: $investigation_id}) "
                "RETURN a.hostname AS source, b.hostname AS target, "
                "r.technique AS technique, r.timestamp AS timestamp "
                "ORDER BY r.timestamp"
            )

        if "domain controller" in q and any(token in q for token in ["hop", "shortest", "path"]):
            return (
                "MATCH p=shortestPath((src:Host {investigation_id: $investigation_id, compromised: true})"
                "-[:LATERAL_MOVED_TO*..6]->"
                "(dc:Host {investigation_id: $investigation_id, is_dc: true})) "
                "RETURN src.hostname AS source_host, dc.hostname AS domain_controller, "
                "length(p) AS hops LIMIT 5"
            )

        return None

    def _sanitize_and_scope_query(self, raw_query: str) -> Optional[str]:
        """Sanitize generated Cypher and enforce per-investigation node scoping."""
        if not raw_query:
            return None

        query = raw_query.strip().strip("`").strip()
        if query.lower().startswith("cypher"):
            query = query[6:].strip()

        if query.count(";") > 0:
            logger.warning("Rejected Cypher with semicolon")
            return None

        if self.WRITE_OR_UNSAFE_CYPHER.search(query):
            logger.warning(f"Rejected unsafe Cypher: {query}")
            return None

        if "return" not in query.lower():
            logger.warning("Rejected Cypher without RETURN clause")
            return None

        query = self._scope_investigation_nodes(query)
        if "$investigation_id" not in query and "$inv_id" not in query:
            logger.warning("Rejected Cypher that could not be scoped")
            return None

        return query

    def _scope_investigation_nodes(self, query: str) -> str:
        """Inject investigation_id property on labeled nodes that support tenant scoping."""
        node_pattern = re.compile(
            rf"\((?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<label>{self.GRAPH_LABELS})(?:\s*(?P<props>\{{[^{{}}]*\}}))?\)"
        )

        def add_scope(match: re.Match) -> str:
            alias = match.group("alias")
            label = match.group("label")
            props = match.group("props")

            if props and "investigation_id" in props:
                return match.group(0)

            if props:
                inner = props[1:-1].strip()
                scoped = f"{{investigation_id: $investigation_id, {inner}}}" if inner else "{investigation_id: $investigation_id}"
            else:
                scoped = "{investigation_id: $investigation_id}"

            return f"({alias}:{label} {scoped})"

        return node_pattern.sub(add_scope, query)

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
        if self.neo4j:
            try:
                self.neo4j.close()
            except Exception:
                pass
