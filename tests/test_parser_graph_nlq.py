import json
import sys
import unittest

from helpers import BACKEND_DIR  # noqa: F401 — adds backend/ to sys.path

from graph.graph_builder import GraphBuilder
from ingestion.log_parser import LogParser
from nlq.query_engine import QueryEngine
from schema import AnalysisResult, Finding, RaptorEvent


class RecordingNeo4j:
    def __init__(self):
        self.writes = []

    def is_connected(self):
        return True

    def run_write(self, query, params=None):
        self.writes.append((query, params or {}))

    def run_query(self, query, params=None):
        return []


class ExportNeo4j(RecordingNeo4j):
    def run_query(self, query, params=None):
        if "MATCH (n {investigation_id: $inv_id})" in query:
            return [
                {
                    "element_id": "1",
                    "labels": ["Host"],
                    "props": {
                        "hostname": "DC-01",
                        "ip": "10.0.1.10",
                        "investigation_id": params["inv_id"],
                        "compromised": True,
                        "is_dc": True,
                    },
                }
            ]
        if "MATCH (a {investigation_id: $inv_id})-[r" in query:
            return []
        return []


class EmptyRetriever:
    def search_all(self, query):
        return {"techniques": [], "reports": []}


class LogParserRegressionTests(unittest.TestCase):
    def test_json_parser_preserves_provided_event_type_and_null_destinations(self):
        content = json.dumps(
            [
                {
                    "timestamp": "2026-04-25T10:00:00Z",
                    "host": "WORKSTATION-01",
                    "event_type": "auth",
                    "dest_host": None,
                    "dest_ip": "null",
                    "raw": "powershell should not overwrite structured auth type",
                }
            ]
        )

        event = LogParser().parse_content(content)[0]

        self.assertEqual(event["event_type"], "auth")
        self.assertIsNone(event["dest_host"])
        self.assertIsNone(event["dest_ip"])
        self.assertNotEqual(event["dest_host"], "None")


class GraphBuilderRegressionTests(unittest.TestCase):
    def test_graph_writes_are_scoped_by_investigation_id(self):
        neo4j = RecordingNeo4j()
        builder = GraphBuilder(neo4j)
        events = [
            RaptorEvent(
                event_id="evt-1",
                timestamp="2026-04-25T10:00:00Z",
                source_host="WORKSTATION-01",
                dest_host="DC-01",
                event_type="lateral",
                sigma_matches=["T1021.002"],
                raw="SMB lateral movement from WORKSTATION-01 to DC-01",
            )
        ]
        analysis = AnalysisResult(
            findings=[
                Finding(
                    event_ids=["evt-1"],
                    technique_id="T1021.002",
                    technique_name="SMB/Windows Admin Shares",
                    kill_chain_phase="lateral-movement",
                    confidence="high",
                )
            ],
            attack_sequence=["T1021.002"],
        )

        graph = builder.build_graph("case-a", events, analysis)

        self.assertEqual(graph.investigation_id, "case-a")
        dc_node = next(node for node in graph.nodes if node.id == "host_DC-01")
        self.assertTrue(dc_node.metadata["compromised"])
        self.assertEqual(dc_node.metadata["compromise_time"], "2026-04-25T10:00:00Z")
        self.assertTrue(neo4j.writes)
        for query, params in neo4j.writes:
            self.assertIn("investigation_id", query)
            self.assertEqual(params.get("inv_id"), "case-a")

    def test_neo4j_graph_export_is_sigma_shape(self):
        builder = GraphBuilder(ExportNeo4j())
        graph = builder.get_graph_json("case-a")

        self.assertEqual(graph["investigation_id"], "case-a")
        self.assertEqual(graph["nodes"][0]["id"], "host_DC-01")
        self.assertEqual(graph["nodes"][0]["node_type"], "host")
        self.assertTrue(graph["nodes"][0]["metadata"]["compromised"])


class QueryEngineGuardTests(unittest.TestCase):
    def setUp(self):
        self.engine = QueryEngine()

    def test_generated_query_is_scoped(self):
        query = self.engine._sanitize_and_scope_query("MATCH (h:Host) RETURN h.hostname AS hostname")

        self.assertEqual(
            query,
            "MATCH (h:Host {investigation_id: $investigation_id}) RETURN h.hostname AS hostname",
        )

    def test_fenced_anonymous_node_query_is_scoped(self):
        query = self.engine._sanitize_and_scope_query(
            "```cypher\nMATCH (:Host {compromised: true}) RETURN count(*) AS compromised\n```"
        )

        self.assertEqual(
            query,
            "MATCH (:Host {investigation_id: $investigation_id, compromised: true}) RETURN count(*) AS compromised",
        )

    def test_write_query_is_rejected(self):
        query = self.engine._sanitize_and_scope_query("MATCH (h:Host) DETACH DELETE h RETURN h")

        self.assertIsNone(query)

    def test_unscoped_second_match_is_rejected(self):
        query = self.engine._sanitize_and_scope_query(
            "MATCH (h:Host) WITH h MATCH (n) RETURN n"
        )

        self.assertIsNone(query)

    def test_union_query_is_rejected(self):
        query = self.engine._sanitize_and_scope_query(
            "MATCH (h:Host) RETURN h UNION MATCH (u:User) RETURN u"
        )

        self.assertIsNone(query)

    def test_empty_rag_context_is_reported_as_low_confidence(self):
        self.engine.retriever = EmptyRetriever()

        result = self.engine._handle_rag_query("What should I block?", "case-a")

        self.assertEqual(result["confidence"], "low")
        self.assertEqual(result["sources"][0]["status"], "empty")


if __name__ == "__main__":
    unittest.main()
