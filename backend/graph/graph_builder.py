"""
RAPTOR | Graph Builder
Builds Neo4j attack graph from analysis findings + events.
Creates nodes (Host, User, Process, File, Network, Technique) and
edges (EXECUTED, CREATED, CONNECTED_TO, LOGGED_INTO, LATERAL_MOVED_TO, OBSERVED_IN).
"""
import re
import uuid
import random
from typing import List, Dict, Any
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import RaptorEvent, Finding, AnalysisResult, GraphNode, GraphEdge, AttackGraph
from graph.neo4j_client import Neo4jClient


class GraphBuilder:
    """Build attack graph in Neo4j from analysis results."""

    def __init__(self, neo4j_client: Neo4jClient = None):
        self.neo4j = neo4j_client or Neo4jClient()
        self.investigation_id = ""

    def build_graph(self, investigation_id: str, events: List[RaptorEvent],
                    analysis: AnalysisResult) -> AttackGraph:
        """Build the complete attack graph from events and analysis."""
        self.investigation_id = investigation_id
        logger.info(f"Building graph for investigation {investigation_id}")

        # Create nodes from events
        hosts = self._extract_hosts(events)
        users = self._extract_users(events)
        techniques = self._extract_techniques(analysis)

        # Write to Neo4j
        self._write_hosts(hosts)
        self._write_users(users)
        self._write_techniques(techniques)
        self._write_events_to_graph(events, analysis)

        # Build Sigma.js compatible graph
        graph = self._build_sigma_graph(hosts, users, techniques, events, analysis)
        logger.info(f"Graph built: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        return graph

    def _extract_hosts(self, events: List[RaptorEvent]) -> Dict[str, Dict]:
        """Extract unique hosts from events."""
        hosts = {}
        for event in events:
            if event.source_host and event.source_host not in hosts:
                hosts[event.source_host] = {
                    "hostname": event.source_host,
                    "ip": event.source_ip,
                    "compromised": len(event.sigma_matches) > 0,
                    "compromise_time": event.timestamp if event.sigma_matches else None,
                }
            if event.dest_host and event.dest_host not in hosts:
                hosts[event.dest_host] = {
                    "hostname": event.dest_host,
                    "ip": event.dest_ip or "",
                    "compromised": False,
                    "compromise_time": None,
                }
        return hosts

    def _extract_users(self, events: List[RaptorEvent]) -> Dict[str, Dict]:
        """Extract user references from event raw logs."""
        users = {}
        user_patterns = [
            r'(?:user|username|account)[:\s]+(\w+)',
            r'(?:CORP|DOMAIN)\\(\w+)',
            r'logged_into.*?as\s+(\w+)',
        ]
        for event in events:
            for pattern in user_patterns:
                matches = re.findall(pattern, event.raw, re.IGNORECASE)
                for username in matches:
                    if username not in users and len(username) > 2:
                        users[username] = {
                            "username": username,
                            "domain": "CORP",
                            "privilege_level": "admin" if "admin" in username.lower() else "user",
                            "compromised": "credential" in event.raw.lower() or "mimikatz" in event.raw.lower(),
                        }
        return users

    def _extract_techniques(self, analysis: AnalysisResult) -> List[Dict]:
        """Extract techniques from analysis findings."""
        techniques = []
        seen = set()
        for finding in analysis.findings:
            if finding.technique_id and finding.technique_id not in seen:
                seen.add(finding.technique_id)
                techniques.append({
                    "id": finding.technique_id,
                    "name": finding.technique_name,
                    "tactic": finding.kill_chain_phase,
                    "kill_chain_phase": finding.kill_chain_phase,
                })
        return techniques

    def _write_hosts(self, hosts: Dict[str, Dict]):
        """Write Host nodes to Neo4j."""
        for hostname, data in hosts.items():
            is_dc = "DC" in hostname.upper() or "DOMAIN" in hostname.upper()
            self.neo4j.run_write(
                """MERGE (h:Host {hostname: $hostname})
                SET h.ip = $ip, h.compromised = $compromised,
                    h.compromise_time = $compromise_time,
                    h.is_dc = $is_dc,
                    h.investigation_id = $inv_id""",
                {
                    "hostname": hostname, "ip": data["ip"],
                    "compromised": data["compromised"],
                    "compromise_time": data.get("compromise_time"),
                    "is_dc": is_dc,
                    "inv_id": self.investigation_id,
                }
            )

    def _write_users(self, users: Dict[str, Dict]):
        """Write User nodes to Neo4j."""
        for username, data in users.items():
            self.neo4j.run_write(
                """MERGE (u:User {username: $username})
                SET u.domain = $domain, u.privilege_level = $priv,
                    u.compromised = $compromised,
                    u.investigation_id = $inv_id""",
                {
                    "username": username, "domain": data["domain"],
                    "priv": data["privilege_level"],
                    "compromised": data["compromised"],
                    "inv_id": self.investigation_id,
                }
            )

    def _write_techniques(self, techniques: List[Dict]):
        """Write Technique nodes to Neo4j."""
        for tech in techniques:
            self.neo4j.run_write(
                """MERGE (t:Technique {id: $id})
                SET t.name = $name, t.tactic = $tactic,
                    t.kill_chain_phase = $phase,
                    t.investigation_id = $inv_id""",
                {
                    "id": tech["id"], "name": tech["name"],
                    "tactic": tech.get("tactic", ""),
                    "phase": tech.get("kill_chain_phase", ""),
                    "inv_id": self.investigation_id,
                }
            )

    def _write_events_to_graph(self, events: List[RaptorEvent], analysis: AnalysisResult):
        """Create edges based on event types and analysis."""
        # Lateral movement edges
        for event in events:
            if event.event_type == "lateral" and event.source_host and event.dest_host:
                technique = ""
                for m in event.sigma_matches:
                    technique = m
                    break
                self.neo4j.run_write(
                    """MATCH (a:Host {hostname: $src}), (b:Host {hostname: $dst})
                    MERGE (a)-[:LATERAL_MOVED_TO {technique: $tech, timestamp: $ts,
                           investigation_id: $inv_id}]->(b)
                    SET b.compromised = true, b.compromise_time = $ts""",
                    {
                        "src": event.source_host, "dst": event.dest_host,
                        "tech": technique, "ts": event.timestamp,
                        "inv_id": self.investigation_id,
                    }
                )

        # Technique -> Host observations
        technique_hosts = {}
        for finding in analysis.findings:
            for event in events:
                if event.event_id in finding.event_ids or any(m == finding.technique_id for m in event.sigma_matches):
                    key = (finding.technique_id, event.source_host)
                    if key not in technique_hosts and event.source_host:
                        technique_hosts[key] = True
                        self.neo4j.run_write(
                            """MATCH (t:Technique {id: $tid}), (h:Host {hostname: $host})
                            MERGE (t)-[:OBSERVED_IN {investigation_id: $inv_id}]->(h)""",
                            {"tid": finding.technique_id, "host": event.source_host,
                             "inv_id": self.investigation_id}
                        )

    def _build_sigma_graph(self, hosts, users, techniques, events, analysis) -> AttackGraph:
        """Build Sigma.js compatible graph for frontend rendering."""
        nodes = []
        edges = []
        node_map = {}
        idx = 0

        # Professional color palette — curated for dark backgrounds
        colors = {
            "uncompromised": "#64748b",    # Cool slate
            "compromised_medium": "#d97706",  # Amber-600
            "compromised": "#e11d48",       # Rose-600
            "dc": "#7c3aed",               # Violet-600
            "user": "#2563eb",             # Blue-600
            "technique": "#059669",         # Emerald-600
            "process": "#d97706",           # Amber-600
        }

        # Host nodes
        for hostname, data in hosts.items():
            is_dc = "DC" in hostname.upper()
            if is_dc:
                color = colors["dc"]
            elif data["compromised"]:
                color = colors["compromised"]
            else:
                color = colors["uncompromised"]

            node_id = f"host_{hostname}"
            nodes.append(GraphNode(
                id=node_id, label=hostname, node_type="host",
                color=color, size=is_dc and 20 or 15,
                x=random.uniform(-100, 100), y=random.uniform(-100, 100),
                metadata={"ip": data["ip"], "compromised": data["compromised"],
                          "is_dc": is_dc, "compromise_time": data.get("compromise_time")},
            ))
            node_map[hostname] = node_id
            idx += 1

        # User nodes
        for username, data in users.items():
            node_id = f"user_{username}"
            nodes.append(GraphNode(
                id=node_id, label=username, node_type="user",
                color=colors["user"], size=10,
                x=random.uniform(-100, 100), y=random.uniform(-100, 100),
                metadata={"domain": data["domain"], "privilege": data["privilege_level"],
                          "compromised": data["compromised"]},
            ))
            node_map[username] = node_id
            idx += 1

        # Technique nodes
        for tech in techniques:
            node_id = f"tech_{tech['id']}"
            nodes.append(GraphNode(
                id=node_id, label=f"{tech['id']}\n{tech['name']}", node_type="technique",
                color=colors["technique"], size=12,
                x=random.uniform(-100, 100), y=random.uniform(-100, 100),
                metadata={"tactic": tech.get("tactic", ""), "phase": tech.get("kill_chain_phase", "")},
            ))
            node_map[tech['id']] = node_id
            idx += 1

        # Edges
        edge_idx = 0
        for event in events:
            # Lateral movement edges (orange)
            if event.event_type == "lateral" and event.source_host and event.dest_host:
                src_id = node_map.get(event.source_host)
                dst_id = node_map.get(event.dest_host)
                if src_id and dst_id:
                    tech_label = ",".join(event.sigma_matches) if event.sigma_matches else "lateral"
                    edges.append(GraphEdge(
                        id=f"edge_{edge_idx}", source=src_id, target=dst_id,
                        label=tech_label, edge_type="lateral_movement",
                        color="#fb923c", size=3,
                        metadata={"timestamp": event.timestamp, "technique": tech_label},
                    ))
                    edge_idx += 1

            # Technique -> Host observations
            for match in event.sigma_matches:
                tech_id = node_map.get(match)
                host_id = node_map.get(event.source_host)
                if tech_id and host_id:
                    edges.append(GraphEdge(
                        id=f"edge_{edge_idx}", source=tech_id, target=host_id,
                        label="observed", edge_type="observed_in",
                        color="#a78bfa", size=1,
                        metadata={"timestamp": event.timestamp},
                    ))
                    edge_idx += 1

        # Mark critical path edges in red
        attack_seq = analysis.attack_sequence
        if len(attack_seq) >= 2:
            for i in range(len(attack_seq) - 1):
                src_id = node_map.get(attack_seq[i])
                dst_id = node_map.get(attack_seq[i + 1])
                if src_id and dst_id:
                    edges.append(GraphEdge(
                        id=f"edge_{edge_idx}", source=src_id, target=dst_id,
                        label="attack_flow", edge_type="attack_sequence",
                        color="#f87171", size=2,
                        metadata={"sequence_index": i},
                    ))
                    edge_idx += 1

        return AttackGraph(nodes=nodes, edges=edges)

    def get_graph_json(self, investigation_id: str) -> Dict:
        """Retrieve graph from Neo4j and return Sigma.js format."""
        # Query all nodes and relationships for this investigation
        nodes_query = """
        MATCH (n {investigation_id: $inv_id})
        RETURN labels(n) as labels, properties(n) as props
        """
        edges_query = """
        MATCH (a {investigation_id: $inv_id})-[r]->(b)
        RETURN type(r) as rel_type, properties(r) as props,
               properties(a) as src_props, labels(a) as src_labels,
               properties(b) as dst_props, labels(b) as dst_labels
        """
        nodes = self.neo4j.run_query(nodes_query, {"inv_id": investigation_id})
        edges = self.neo4j.run_query(edges_query, {"inv_id": investigation_id})

        return {"nodes": nodes, "edges": edges, "investigation_id": investigation_id}
