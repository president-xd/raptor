"""
RAPTOR | Pre-built Cypher Queries
Key graph queries from spec Section 4.3 (BloodHound-inspired).
"""

# Shortest path from compromised user to Domain Admin
SHORTEST_PATH_TO_DA = """
MATCH p=shortestPath((u:User {username: $username})-[*]->(h:Host {is_dc: true}))
RETURN p
"""

# All hosts reachable from a compromised host
REACHABLE_HOSTS = """
MATCH (h:Host {hostname: $hostname})-[:LATERAL_MOVED_TO*1..5]->(target:Host)
RETURN DISTINCT target.hostname as hostname, target.ip as ip,
       target.compromised as compromised
"""

# Full attack path for an investigation
ATTACK_PATH = """
MATCH (h1:Host {investigation_id: $inv_id})-[r:LATERAL_MOVED_TO]->(h2:Host)
RETURN h1.hostname as source, h2.hostname as target,
       r.technique as technique, r.timestamp as timestamp
ORDER BY r.timestamp
"""

# Techniques observed on a specific host
HOST_TECHNIQUES = """
MATCH (t:Technique)-[:OBSERVED_IN]->(h:Host {hostname: $hostname})
RETURN t.id as technique_id, t.name as technique_name,
       t.kill_chain_phase as phase
"""

# All compromised hosts in an investigation
COMPROMISED_HOSTS = """
MATCH (h:Host {investigation_id: $inv_id, compromised: true})
RETURN h.hostname as hostname, h.ip as ip,
       h.compromise_time as compromise_time
ORDER BY h.compromise_time
"""

# APT group techniques
APT_TECHNIQUES = """
MATCH (a:APTGroup {name: $apt_name})-[:USES]->(t:Technique)
RETURN t.id as technique_id, t.name as technique_name
"""

# Full graph for investigation (Sigma.js export)
FULL_INVESTIGATION_GRAPH = """
MATCH (n {investigation_id: $inv_id})
OPTIONAL MATCH (n)-[r]->(m {investigation_id: $inv_id})
RETURN labels(n) as src_labels, properties(n) as src_props,
       type(r) as rel_type, properties(r) as rel_props,
       labels(m) as dst_labels, properties(m) as dst_props
"""

# Graph summary statistics
GRAPH_SUMMARY = """
MATCH (n {investigation_id: $inv_id})
WITH labels(n) as label_list, count(n) as cnt
RETURN label_list[0] as label, cnt
ORDER BY cnt DESC
"""

# Timeline of events on a host
HOST_TIMELINE = """
MATCH (t:Technique)-[:OBSERVED_IN]->(h:Host {hostname: $hostname})
RETURN t.id as technique_id, t.name as technique_name,
       t.kill_chain_phase as phase
ORDER BY t.kill_chain_phase
"""
