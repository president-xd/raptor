"""
RAPTOR | Provenance DAG
Process-level forensics: build provenance directed acyclic graph.
Per spec Section 4.4: backward slicing from suspicious events.
"""
import networkx as nx
from typing import List, Dict, Optional, Set
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import RaptorEvent


class ProvenanceDAG:
    """Provenance graph for process-level forensic reconstruction."""

    MAX_EDGES = 1_000_000  # Per spec Section 4.4

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_events(self, events: List[RaptorEvent]) -> nx.DiGraph:
        """Build provenance DAG from events."""
        for event in events:
            node_id = event.event_id
            self.graph.add_node(node_id, **{
                "timestamp": event.timestamp,
                "host": event.source_host,
                "type": event.event_type,
                "raw": event.raw[:200],
                "sigma_matches": event.sigma_matches,
            })

        # Build causal edges based on temporal + host relationships
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        host_chains: Dict[str, List[str]] = {}

        for event in sorted_events:
            host = event.source_host
            if host not in host_chains:
                host_chains[host] = []

            # Connect to previous event on same host (temporal causality)
            if host_chains[host]:
                prev_id = host_chains[host][-1]
                self.graph.add_edge(prev_id, event.event_id, edge_type="temporal")

            host_chains[host].append(event.event_id)

            # Cross-host edges for lateral movement
            if event.event_type == "lateral" and event.dest_host:
                dest_events = [e for e in sorted_events
                               if e.source_host == event.dest_host and e.timestamp >= event.timestamp]
                if dest_events:
                    self.graph.add_edge(event.event_id, dest_events[0].event_id,
                                       edge_type="lateral_movement")

            # Enforce edge limit
            if self.graph.number_of_edges() > self.MAX_EDGES:
                logger.warning(f"Provenance DAG hit edge limit ({self.MAX_EDGES})")
                break

        logger.info(f"Provenance DAG: {self.graph.number_of_nodes()} nodes, "
                    f"{self.graph.number_of_edges()} edges")
        return self.graph

    def backward_slice(self, target_event_id: str, max_depth: int = 20) -> nx.DiGraph:
        """
        Backward slicing from a suspicious event.
        Per spec Section 9.3: trace backward through causal graph to initial access.
        """
        if target_event_id not in self.graph:
            return nx.DiGraph()

        # BFS backward from target
        visited: Set[str] = set()
        queue = [(target_event_id, 0)]
        subgraph_nodes = set()

        while queue:
            node, depth = queue.pop(0)
            if node in visited or depth > max_depth:
                continue
            visited.add(node)
            subgraph_nodes.add(node)

            # Get predecessors (causal parents)
            for pred in self.graph.predecessors(node):
                if pred not in visited:
                    queue.append((pred, depth + 1))

        return self.graph.subgraph(subgraph_nodes).copy()

    def get_critical_path(self) -> List[str]:
        """Find the longest path in the DAG (likely attack chain)."""
        if not self.graph.nodes():
            return []
        try:
            return nx.dag_longest_path(self.graph)
        except (nx.NetworkXError, nx.NetworkXUnfeasible):
            return []

    def get_summary(self) -> Dict:
        """Return DAG summary for LLM context."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "critical_path_length": len(self.get_critical_path()),
            "hosts_involved": len(set(
                self.graph.nodes[n].get("host", "") for n in self.graph.nodes
                if self.graph.nodes[n].get("host")
            )),
        }
