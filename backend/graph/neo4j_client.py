"""
RAPTOR | Neo4j Client
Neo4j driver wrapper with schema creation and indexes.
Graph data model from spec Section 4.2.
"""
from typing import Optional, List, Dict, Any
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD


class Neo4jClient:
    """Neo4j driver wrapper for RAPTOR graph operations."""

    def __init__(self, uri: str = None, user: str = None, password: str = None):
        from neo4j import GraphDatabase
        self.uri = uri or NEO4J_URI
        self.user = user or NEO4J_USER
        self.password = password or NEO4J_PASSWORD
        self.driver = None
        self._connect()

    def _connect(self):
        from neo4j import GraphDatabase
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {self.uri}")
        except Exception as e:
            logger.warning(f"Could not connect to Neo4j: {e}")
            self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def is_connected(self) -> bool:
        return self.driver is not None

    def run_query(self, query: str, params: dict = None) -> List[Dict[str, Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        if not self.driver:
            logger.warning("Neo4j not connected")
            return []
        try:
            with self.driver.session() as session:
                result = session.run(query, params or {})
                return [dict(record) for record in result]
        except Exception as e:
            logger.error(f"Neo4j query failed: {e}\nQuery: {query}")
            return []

    def run_write(self, query: str, params: dict = None) -> None:
        """Execute a write query."""
        if not self.driver:
            return
        try:
            with self.driver.session() as session:
                session.run(query, params or {})
        except Exception as e:
            logger.error(f"Neo4j write failed: {e}")

    def setup_schema(self) -> None:
        """Create indexes and constraints per spec Section 4.2."""
        schema_queries = [
            "CREATE INDEX host_hostname IF NOT EXISTS FOR (h:Host) ON (h.hostname)",
            "CREATE INDEX user_username IF NOT EXISTS FOR (u:User) ON (u.username)",
            "CREATE INDEX technique_id IF NOT EXISTS FOR (t:Technique) ON (t.id)",
            "CREATE CONSTRAINT apt_name IF NOT EXISTS FOR (a:APTGroup) REQUIRE a.name IS UNIQUE",
            "CREATE INDEX process_pid IF NOT EXISTS FOR (p:Process) ON (p.pid)",
            "CREATE INDEX file_hash IF NOT EXISTS FOR (f:File) ON (f.hash_sha256)",
            "CREATE INDEX network_ip IF NOT EXISTS FOR (n:Network) ON (n.dest_ip)",
        ]
        for q in schema_queries:
            try:
                self.run_write(q)
                logger.debug(f"Schema: {q}")
            except Exception as e:
                logger.debug(f"Schema query (may already exist): {e}")

        logger.info("Neo4j schema setup complete")

    def clear_investigation(self, investigation_id: str) -> None:
        """Clear all nodes/edges for a specific investigation."""
        self.run_write(
            "MATCH (n {investigation_id: $inv_id}) DETACH DELETE n",
            {"inv_id": investigation_id}
        )

    def get_graph_stats(self) -> Dict[str, int]:
        """Get count of each node type."""
        stats = {}
        for label in ["Host", "User", "Process", "File", "Network", "Technique", "APTGroup"]:
            result = self.run_query(f"MATCH (n:{label}) RETURN count(n) as cnt")
            stats[label] = result[0]["cnt"] if result else 0
        return stats
