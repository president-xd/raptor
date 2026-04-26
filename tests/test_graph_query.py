import unittest

from helpers import BACKEND_DIR  # noqa: F401
from graph.graph_builder import GraphBuilder
from nlq.query_engine import QueryEngine
from schema import AnalysisResult, Finding, RaptorEvent


class RecordingNeo4j:
    def __init__(self, rows=None):
        self.writes = []
        self.rows = rows or []
        self.queries = []

    def is_connected(self):
        return True

    def run_write(self, query, params=None):
        self.writes.append((query, params or {}))

    def run_query(self, query, params=None):
        self.queries.append((query, params or {}))
        return self.rows

    def close(self):
        pass


class ExportNeo4j(RecordingNeo4j):
    def run_query(self, query, params=None):
        self.queries.append((query, params or {}))
        if "MATCH (n {investigation_id: $inv_id})" in query:
            return [
                {
                    "element_id": "node-1",
                    "labels": ["Host"],
                    "props": {
                        "hostname": "DC-01",
                        "ip": "10.0.0.10",
                        "compromised": True,
                        "is_dc": True,
                        "investigation_id": params["inv_id"],
                    },
                },
                {
                    "element_id": "node-2",
                    "labels": ["Technique"],
                    "props": {
                        "id": "T1021.002",
                        "name": "SMB/Windows Admin Shares",
                        "investigation_id": params["inv_id"],
                    },
                },
            ]
        if "MATCH (a {investigation_id: $inv_id})-[r" in query:
            return [
                {
                    "rel_id": "rel-1",
                    "rel_type": "OBSERVED_IN",
                    "props": {"investigation_id": params["inv_id"]},
                    "src_props": {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
                    "src_labels": ["Technique"],
                    "dst_props": {"hostname": "DC-01", "compromised": True},
                    "dst_labels": ["Host"],
                }
            ]
        return []


class GraphBuilderTests(unittest.TestCase):
    def test_graph_writes_and_export_are_scoped(self):
        neo4j = RecordingNeo4j()
        graph = GraphBuilder(neo4j).build_graph(
            "case-a",
            [
                RaptorEvent(
                    event_id="evt-1",
                    timestamp="2026-04-25T10:00:00Z",
                    source_host="WKSTN-01",
                    source_ip="10.0.0.5",
                    dest_host="DC-01",
                    dest_ip="10.0.0.10",
                    event_type="lateral",
                    raw="net use \\\\DC-01\\ADMIN$",
                    sigma_matches=["T1021.002"],
                )
            ],
            AnalysisResult(
                findings=[
                    Finding(
                        event_ids=["evt-1"],
                        technique_id="T1021.002",
                        technique_name="SMB/Windows Admin Shares",
                        kill_chain_phase="lateral-movement",
                    )
                ],
                attack_sequence=["T1021.002"],
            ),
        )

        self.assertEqual(graph.investigation_id, "case-a")
        self.assertTrue(any(edge.edge_type == "lateral_movement" for edge in graph.edges))
        self.assertTrue(neo4j.writes)
        for query, params in neo4j.writes:
            self.assertIn("investigation_id", query)
            self.assertEqual(params.get("inv_id"), "case-a")

    def test_neo4j_graph_json_uses_frontend_shape(self):
        graph = GraphBuilder(ExportNeo4j()).get_graph_json("case-a")

        self.assertEqual(graph["investigation_id"], "case-a")
        self.assertEqual(graph["nodes"][0]["id"], "host_DC-01")
        self.assertEqual(graph["nodes"][0]["node_type"], "host")
        self.assertEqual(graph["edges"][0]["source"], "tech_T1021.002")
        self.assertEqual(graph["edges"][0]["target"], "host_DC-01")

    def test_stable_positions_are_deterministic_per_investigation(self):
        builder = GraphBuilder(RecordingNeo4j())
        builder.investigation_id = "case-a"

        first = builder._stable_position("host_DC-01", "x")
        second = builder._stable_position("host_DC-01", "x")

        self.assertEqual(first, second)
        self.assertGreaterEqual(first, -100.0)
        self.assertLessEqual(first, 100.0)


class QueryEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = QueryEngine()

    def test_question_classification_routes_common_intents(self):
        self.assertEqual(self.engine._classify_question("Which hosts are compromised?"), "graph")
        self.assertEqual(self.engine._classify_question("What should I block next?"), "simulation")
        self.assertEqual(self.engine._classify_question("Explain Kerberoasting"), "rag")

    def test_generated_cypher_is_scoped_and_read_only(self):
        query = self.engine._sanitize_and_scope_query("MATCH (h:Host) RETURN h.hostname AS hostname")

        self.assertEqual(
            query,
            "MATCH (h:Host {investigation_id: $investigation_id}) RETURN h.hostname AS hostname",
        )

    def test_unsafe_and_unscoped_cypher_is_rejected(self):
        self.assertIsNone(self.engine._sanitize_and_scope_query("MATCH (h:Host) DETACH DELETE h RETURN h"))
        self.assertIsNone(self.engine._sanitize_and_scope_query("MATCH (h:Host) RETURN h UNION MATCH (u:User) RETURN u"))
        self.assertIsNone(self.engine._sanitize_and_scope_query("MATCH (h:Host) WITH h MATCH (n) RETURN n"))

    def test_graph_answer_executes_with_investigation_params(self):
        import nlq.query_engine as query_engine_module

        neo4j = RecordingNeo4j(rows=[{"compromised_hosts": 2}])
        engine = QueryEngine(neo4j_client=neo4j)

        original_call_llm = query_engine_module.call_llm
        query_engine_module.call_llm = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
        try:
            result = engine.answer_question("How many compromised hosts?", "case-a")
        finally:
            query_engine_module.call_llm = original_call_llm

        self.assertEqual(result["query_type"], "graph")
        self.assertEqual(result["confidence"], "high")
        self.assertEqual(neo4j.queries[0][1]["investigation_id"], "case-a")
        self.assertIn("compromised_hosts", result["sources"][0]["results"][0])

    def test_empty_rag_and_simulation_contexts_are_low_confidence(self):
        class EmptyRetriever:
            def search_all(self, _query):
                return {"techniques": [], "reports": []}

            def close(self):
                pass

        engine = QueryEngine()
        engine.retriever = EmptyRetriever()

        rag = engine._handle_rag_query("What should I investigate?", "case-a")
        simulation = engine._handle_simulation_query("What should I block next?", "case-a")

        self.assertEqual(rag["confidence"], "low")
        self.assertEqual(simulation["confidence"], "low")
        self.assertEqual(rag["sources"][0]["status"], "empty")
        self.assertEqual(simulation["sources"][0]["status"], "empty")


if __name__ == "__main__":
    unittest.main()
