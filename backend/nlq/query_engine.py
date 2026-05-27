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
from llm_redactor import redact
from rag.pipeline import call_llm
from rag.retriever import HybridRetriever
from rag.reranker import rerank_technique_results


class QueryEngine:
    """Natural language query engine with multi-pipeline routing."""

    UNSAFE_CYPHER = re.compile(
        r"\b("
        r"CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|ALTER|GRANT|DENY|REVOKE|"
        r"LOAD\s+CSV|FOREACH|CALL|UNION|USE|EXPLAIN|PROFILE|START|PERIODIC\s+COMMIT"
        r")\b|//|/\*",
        re.IGNORECASE,
    )
    READ_ONLY_START = re.compile(r"^\s*(MATCH|OPTIONAL\s+MATCH)\b", re.IGNORECASE)

    GRAPH_LABELS = ("Host", "User", "Process", "File", "Network", "Technique", "APTGroup")
    GRAPH_LABEL_PATTERN = "|".join(GRAPH_LABELS)
    LABELED_NODE_PATTERN = re.compile(
        rf"(?<![A-Za-z0-9_])\("
        rf"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)?\s*:\s*"
        rf"(?P<label>[A-Za-z_][A-Za-z0-9_]*)"
        rf"(?:\s*(?P<props>\{{[^{{}}]*\}}))?"
        rf"\)"
    )
    UNLABELED_NODE_PATTERN = re.compile(
        r"(?<![A-Za-z0-9_])\(\s*(?:[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\{[^{}]*\})?\s*\)"
    )

    def __init__(self, neo4j_client=None):
        self.neo4j = neo4j_client
        self.retriever = None

    def answer_question(self, question: str, investigation_id: str = "") -> Dict[str, Any]:
        """
        Answer a natural language question by routing to the appropriate pipeline.
        Per spec Section 7.3.
        """
        # Redact PII/secrets from the question before it reaches any LLM or log
        question = redact(question)
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
            logger.warning("No allowlisted graph query matched; using safe default")

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

        if not results and self._is_lateral_question(question) and self.neo4j and self.neo4j.is_connected():
            evidence_cypher = self._lateral_evidence_query()
            logger.info(f"No explicit lateral path found; checking technique evidence: {evidence_cypher}")
            try:
                evidence_results = self.neo4j.run_query(
                    evidence_cypher,
                    {"investigation_id": investigation_id, "inv_id": investigation_id},
                )
                if evidence_results:
                    cypher = evidence_cypher
                    results = evidence_results
            except Exception as e:
                logger.error(f"Lateral evidence query failed: {e}")

        # Synthesize answer
        answer = self._synthesize_graph_answer(question, results, cypher)
        has_error = bool(results and isinstance(results[0], dict) and results[0].get("error"))
        confidence = "low" if has_error or not results else "medium" if self._is_lateral_evidence_results(results) else "high"

        return {
            "answer": answer,
            "sources": [{"type": "neo4j", "query": cypher, "results": results[:10]}],
            "confidence": confidence,
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

        if "compromised" in q and "host" in q:
            return (
                "MATCH (h:Host {investigation_id: $investigation_id, compromised: true}) "
                "RETURN h.hostname AS hostname, h.ip AS ip, h.compromise_time AS compromise_time "
                "ORDER BY h.compromise_time"
            )

        if "lateral" in q and any(token in q for token in ["path", "movement", "move"]):
            return (
                "MATCH (a:Host {investigation_id: $investigation_id})"
                "-[r:LATERAL_MOVED_TO {investigation_id: $investigation_id}]->"
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
                "WHERE all(n IN nodes(p) WHERE n.investigation_id = $investigation_id) "
                "RETURN src.hostname AS source_host, dc.hostname AS domain_controller, "
                "length(p) AS hops LIMIT 5"
            )

        return None

    def _is_lateral_question(self, question: str) -> bool:
        q = question.lower()
        return "lateral" in q and any(token in q for token in ["path", "movement", "move"])

    def _lateral_evidence_query(self) -> str:
        return (
            "MATCH (t:Technique {investigation_id: $investigation_id})"
            "-[:OBSERVED_IN {investigation_id: $investigation_id}]->"
            "(h:Host {investigation_id: $investigation_id}) "
            "WHERE t.id STARTS WITH 'T1021' "
            "OR toLower(coalesce(t.tactic, '')) CONTAINS 'lateral' "
            "OR toLower(coalesce(t.kill_chain_phase, '')) CONTAINS 'lateral' "
            "OR any(tactic IN coalesce(t.tactics, []) WHERE toLower(tactic) CONTAINS 'lateral') "
            "RETURN h.hostname AS host, h.ip AS ip, t.id AS technique_id, "
            "t.name AS technique_name, coalesce(t.kill_chain_phase, t.tactic, '') AS tactic "
            "ORDER BY h.hostname, t.id"
        )

    def _is_lateral_evidence_results(self, results: list) -> bool:
        first = results[0] if results and isinstance(results[0], dict) else {}
        return {"host", "technique_id"}.issubset(first.keys())

    def _sanitize_and_scope_query(self, raw_query: str) -> Optional[str]:
        """Sanitize generated Cypher and enforce per-investigation node scoping."""
        query = self._extract_cypher(raw_query)
        if not query:
            return None

        if query.count(";") > 0:
            logger.warning("Rejected Cypher with semicolon")
            return None

        if self.UNSAFE_CYPHER.search(query):
            logger.warning(f"Rejected unsafe Cypher: {query}")
            return None

        if not self.READ_ONLY_START.search(query):
            logger.warning(f"Rejected Cypher that does not start with read-only MATCH: {query}")
            return None

        if not re.search(r"\bRETURN\b", query, re.IGNORECASE):
            logger.warning("Rejected Cypher without RETURN clause")
            return None

        query = self._scope_investigation_nodes(query)
        if not self._all_node_patterns_are_scoped(query):
            logger.warning(f"Rejected Cypher with unscoped or unsupported node patterns: {query}")
            return None

        if "$investigation_id" not in query and "$inv_id" not in query:
            logger.warning("Rejected Cypher that could not be scoped")
            return None

        return query

    def _extract_cypher(self, raw_query: str) -> Optional[str]:
        """Extract a single Cypher statement from plain text or a fenced code block."""
        if not raw_query:
            return None

        query = raw_query.strip()
        fenced = re.search(r"```(?:cypher)?\s*(.*?)```", query, re.IGNORECASE | re.DOTALL)
        if fenced:
            query = fenced.group(1).strip()

        query = query.strip().strip("`").strip()
        if query.lower().startswith("cypher"):
            query = query[6:].strip()

        return query or None

    def _scope_investigation_nodes(self, query: str) -> str:
        """Inject investigation_id property on labeled nodes that support tenant scoping."""
        node_pattern = re.compile(
            rf"\((?P<alias>[A-Za-z_][A-Za-z0-9_]*)?\s*:\s*"
            rf"(?P<label>{self.GRAPH_LABEL_PATTERN})"
            rf"(?:\s*(?P<props>\{{[^{{}}]*\}}))?\)"
        )

        def add_scope(match: re.Match) -> str:
            alias = match.group("alias") or ""
            label = match.group("label")
            props = match.group("props")

            if props and "investigation_id" in props:
                return match.group(0)

            if props:
                inner = props[1:-1].strip()
                scoped = f"{{investigation_id: $investigation_id, {inner}}}" if inner else "{investigation_id: $investigation_id}"
            else:
                scoped = "{investigation_id: $investigation_id}"

            alias_prefix = f"{alias}:" if alias else ":"
            return f"({alias_prefix}{label} {scoped})"

        return node_pattern.sub(add_scope, query)

    def _all_node_patterns_are_scoped(self, query: str) -> bool:
        """Require every graph node pattern to use known labels and investigation scoping."""
        if self.UNLABELED_NODE_PATTERN.search(query):
            return False

        matches = list(self.LABELED_NODE_PATTERN.finditer(query))
        if not matches:
            return False

        allowed = set(self.GRAPH_LABELS)
        for match in matches:
            label = match.group("label")
            props = match.group("props") or ""
            if label not in allowed:
                return False
            if "investigation_id" not in props:
                return False

        return True

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

        if not context_lines:
            return {
                "answer": (
                    "RAG retrieval returned no indexed ATT&CK or threat-report context for this question. "
                    "Check Weaviate indexing/health before treating this as a grounded answer."
                ),
                "sources": [{"type": "rag", "status": "empty", "detail": "no retrieved context"}],
                "confidence": "low",
                "query_type": "rag",
            }

        prompt = f"""Based on the following retrieved ATT&CK context, answer this question:

Question: {question}

Retrieved Context:
{chr(10).join(context_lines) if context_lines else 'No relevant context found.'}

Provide a clear, specific answer citing the ATT&CK techniques referenced."""

        try:
            answer = call_llm("You are a cybersecurity analyst. Answer based on the retrieved context.", prompt)
        except Exception as e:
            logger.error(f"RAG answer generation failed: {e}")
            answer = self._local_rag_answer(techniques)

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

        if not context_lines:
            return {
                "answer": self._local_simulation_answer(question, investigation_id, techniques),
                "sources": self._simulation_sources(investigation_id, techniques),
                "confidence": "low",
                "query_type": "simulation",
            }

        prompt = f"""You are a cybersecurity analyst advising on defense.

Question: {question}

Retrieved ATT&CK Context:
{chr(10).join(context_lines) if context_lines else 'No context available.'}

Provide actionable, specific recommendations based on ATT&CK framework."""

        try:
            answer = call_llm("You are a senior SOC analyst providing defensive recommendations.", prompt)
        except Exception as e:
            logger.error(f"Simulation query generation failed: {e}")
            answer = self._local_simulation_answer(question, investigation_id, techniques)

        return {
            "answer": answer,
            "sources": self._simulation_sources(investigation_id, techniques),
            "confidence": "medium",
            "query_type": "simulation",
        }

    def _synthesize_graph_answer(self, question: str, results: list, cypher: str) -> str:
        """Convert graph query results into natural language answer."""
        if not results:
            if self._is_lateral_question(question):
                return (
                    "No explicit host-to-host lateral movement path or lateral ATT&CK technique evidence "
                    "was found in this investigation graph."
                )
            return "No matching paths or nodes found in the attack graph for this investigation."
        if isinstance(results[0], dict) and results[0].get("error"):
            return f"The graph query failed: {results[0].get('error')}"

        deterministic = self._deterministic_graph_answer(question, results)
        if deterministic:
            return deterministic

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
            return self._format_generic_graph_answer(results)

    def _deterministic_graph_answer(self, question: str, results: list) -> Optional[str]:
        """Produce analyst-readable answers for common graph query result shapes."""
        q = question.lower()
        first = results[0] if results and isinstance(results[0], dict) else {}

        if "compromised_hosts" in first:
            count = first.get("compromised_hosts", 0)
            noun = "host is" if count == 1 else "hosts are"
            return f"{count} compromised {noun} present in the selected investigation graph."

        if "hostname" in first and ("compromised" in q or "which hosts" in q or "host" in q):
            lines = [f"{len(results)} compromised host{'s' if len(results) != 1 else ''} found:"]
            for row in results:
                hostname = row.get("hostname") or "Unknown host"
                details = []
                if row.get("ip"):
                    details.append(f"IP {row['ip']}")
                if row.get("compromise_time"):
                    details.append(f"compromised at {row['compromise_time']}")
                suffix = f" ({'; '.join(details)})" if details else ""
                lines.append(f"- {hostname}{suffix}")
            lines.append("")
            lines.append("These hosts are marked compromised=true in the investigation attack graph.")
            return "\n".join(lines)

        if {"source", "target"}.issubset(first.keys()):
            lines = [f"{len(results)} lateral movement path{'s' if len(results) != 1 else ''} found:"]
            for row in results:
                source = row.get("source") or "Unknown source"
                target = row.get("target") or "Unknown target"
                technique = row.get("technique") or "unknown technique"
                timestamp = f" at {row['timestamp']}" if row.get("timestamp") else ""
                lines.append(f"- {source} -> {target} via {technique}{timestamp}")
            return "\n".join(lines)

        if {"host", "technique_id"}.issubset(first.keys()) and self._is_lateral_question(question):
            lines = [
                "No explicit host-to-host lateral movement path is encoded in this graph, "
                "but lateral movement evidence was observed:"
            ]
            for row in results:
                host = row.get("host") or "Unknown host"
                technique_id = row.get("technique_id") or "unknown technique"
                technique_name = row.get("technique_name") or ""
                ip = f" ({row['ip']})" if row.get("ip") else ""
                label = f"{technique_id} {technique_name}".strip()
                lines.append(f"- {host}{ip}: {label}")
            lines.append("")
            lines.append("The graph stores this as Technique -> Host evidence, not as a Host -> Host lateral edge.")
            return "\n".join(lines)

        if {"source_host", "domain_controller", "hops"}.issubset(first.keys()):
            lines = [f"{len(results)} path{'s' if len(results) != 1 else ''} to a domain controller found:"]
            for row in results:
                source = row.get("source_host") or "Unknown source"
                dc = row.get("domain_controller") or "Unknown domain controller"
                hops = row.get("hops")
                hop_text = f"{hops} hop{'s' if hops != 1 else ''}" if hops is not None else "unknown hop count"
                lines.append(f"- {source} -> {dc} ({hop_text})")
            return "\n".join(lines)

        return None

    def _format_generic_graph_answer(self, results: list) -> str:
        """Fallback that avoids exposing raw JSON as the primary user-facing answer."""
        lines = [f"Graph query returned {len(results)} row{'s' if len(results) != 1 else ''}:"]
        for index, row in enumerate(results[:5], start=1):
            if isinstance(row, dict):
                parts = [f"{key}: {value}" for key, value in row.items() if value not in ("", None, [])]
                lines.append(f"{index}. {'; '.join(parts) if parts else 'empty row'}")
            else:
                lines.append(f"{index}. {row}")
        if len(results) > 5:
            lines.append(f"...and {len(results) - 5} more rows.")
        return "\n".join(lines)

    def _local_rag_answer(self, techniques: list) -> str:
        if not techniques:
            return (
                "No grounded ATT&CK context was retrieved for this question. "
                "Check the Weaviate index and ask a more specific question with a technique, host, or tactic."
            )

        lines = ["Relevant ATT&CK context retrieved:"]
        for technique in techniques[:5]:
            technique_id = technique.get("technique_id") or "unknown technique"
            name = technique.get("name") or ""
            tactic = technique.get("kill_chain_phase") or ", ".join(technique.get("tactics") or [])
            suffix = f" ({tactic})" if tactic else ""
            lines.append(f"- {technique_id} {name}{suffix}".strip())
        return "\n".join(lines)

    def _local_simulation_answer(self, question: str, investigation_id: str, techniques: list) -> str:
        q = question.lower()
        graph_context = self._investigation_graph_context(investigation_id)
        hosts = graph_context.get("compromised_hosts", [])
        lateral = graph_context.get("lateral_evidence", [])
        observed = graph_context.get("techniques", []) or techniques

        host_text = ", ".join(host["hostname"] for host in hosts if host.get("hostname")) or "confirmed compromised hosts"
        technique_text = self._format_technique_refs(observed)
        lateral_text = self._format_lateral_refs(lateral)

        if "contain" in q or "what should i" in q:
            lines = [
                "Containment priority:",
                f"1. Isolate {host_text} from user subnets while preserving forensic access.",
                "2. Revoke or reset credentials that touched those systems, especially privileged and service accounts.",
                "3. Block suspected C2 and remote admin paths, then hunt for the same techniques on adjacent hosts.",
            ]
            if lateral_text:
                lines.append(f"4. Treat lateral movement evidence as active until disproven: {lateral_text}.")
            if technique_text:
                lines.append(f"Observed techniques guiding this: {technique_text}.")
            return "\n".join(lines)

        if "next" in q or "would do" in q or "likely" in q or "predict" in q:
            lines = [
                "Likely next actor actions based on the current case evidence:",
                "1. Expand access laterally from compromised workstations toward privileged systems.",
                "2. Attempt credential access or reuse harvested credentials to increase privileges.",
                "3. Establish persistence and stage collection or exfiltration once a high-value host is reached.",
            ]
            if lateral_text:
                lines.append(f"Current lateral indicator: {lateral_text}.")
            if technique_text:
                lines.append(f"Observed techniques guiding this: {technique_text}.")
            return "\n".join(lines)

        lines = [
            "Recommended defensive action:",
            f"- Prioritize {host_text}, credential reset, C2 blocking, and focused hunting across adjacent systems.",
        ]
        if technique_text:
            lines.append(f"- Ground the hunt on observed techniques: {technique_text}.")
        return "\n".join(lines)

    def _simulation_sources(self, investigation_id: str, techniques: list) -> list:
        graph_context = self._investigation_graph_context(investigation_id)
        sources = []
        if any(graph_context.values()):
            sources.append({"type": "neo4j", "detail": "investigation graph context"})

        for technique in graph_context.get("techniques", [])[:5]:
            technique_id = technique.get("technique_id") or ""
            if technique_id:
                sources.append({
                    "type": "att&ck",
                    "technique_id": technique_id,
                    "name": technique.get("name", ""),
                    "source": "investigation_graph",
                })

        if sources:
            return sources

        rag_sources = [
            {
                "type": "att&ck",
                "technique_id": technique.get("technique_id", ""),
                "name": technique.get("name", ""),
                "source": "retrieval",
            }
            for technique in techniques[:5]
            if technique.get("technique_id")
        ]
        return rag_sources or [{"type": "rag", "status": "empty", "detail": "no retrieved simulation context"}]

    def _investigation_graph_context(self, investigation_id: str) -> Dict[str, list]:
        context = {"compromised_hosts": [], "lateral_evidence": [], "techniques": []}
        if not investigation_id or not self.neo4j or not self.neo4j.is_connected():
            return context

        try:
            context["compromised_hosts"] = self.neo4j.run_query(
                "MATCH (h:Host {investigation_id: $investigation_id, compromised: true}) "
                "RETURN h.hostname AS hostname, h.ip AS ip, h.compromise_time AS compromise_time "
                "ORDER BY h.compromise_time",
                {"investigation_id": investigation_id, "inv_id": investigation_id},
            )
        except Exception as e:
            logger.error(f"Compromised host context query failed: {e}")

        try:
            context["lateral_evidence"] = self.neo4j.run_query(
                self._lateral_evidence_query(),
                {"investigation_id": investigation_id, "inv_id": investigation_id},
            )
        except Exception as e:
            logger.error(f"Lateral context query failed: {e}")

        try:
            context["techniques"] = self.neo4j.run_query(
                "MATCH (t:Technique {investigation_id: $investigation_id}) "
                "RETURN t.id AS technique_id, t.name AS name, "
                "coalesce(t.kill_chain_phase, t.tactic, '') AS kill_chain_phase "
                "ORDER BY t.id",
                {"investigation_id": investigation_id, "inv_id": investigation_id},
            )
        except Exception as e:
            logger.error(f"Technique context query failed: {e}")

        return context

    def _format_technique_refs(self, techniques: list) -> str:
        refs = []
        for technique in techniques[:5]:
            technique_id = technique.get("technique_id") or technique.get("id") or ""
            name = technique.get("name") or technique.get("technique_name") or ""
            label = f"{technique_id} {name}".strip()
            if label and label not in refs:
                refs.append(label)
        return ", ".join(refs)

    def _format_lateral_refs(self, rows: list) -> str:
        refs = []
        for row in rows[:3]:
            host = row.get("host") or "unknown host"
            technique_id = row.get("technique_id") or "unknown technique"
            name = row.get("technique_name") or ""
            refs.append(f"{host} via {technique_id} {name}".strip())
        return "; ".join(refs)

    def close(self):
        if self.retriever:
            self.retriever.close()
        if self.neo4j:
            try:
                self.neo4j.close()
            except Exception:
                pass
