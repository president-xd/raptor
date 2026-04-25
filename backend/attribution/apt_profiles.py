"""
RAPTOR | APT Profile Loader
Loads APT group TTP profiles from MITRE ATT&CK STIX bundle.
Per spec Section 5.4: store as APTGroup nodes with USES edges to Technique nodes.
"""
import json
from typing import Dict, List, Set, Tuple
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import STIX_DIR, ATTACK_STIX_URL


def load_stix_bundle() -> dict:
    """Load the ATT&CK STIX bundle (cached or download)."""
    cache_path = STIX_DIR / "enterprise-attack.json"
    if cache_path.exists():
        with open(cache_path, 'r') as f:
            return json.load(f)

    import requests
    logger.info(f"Downloading ATT&CK STIX bundle...")
    resp = requests.get(ATTACK_STIX_URL, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    with open(cache_path, 'w') as f:
        json.dump(data, f)
    return data


def load_apt_profiles() -> Dict[str, Dict]:
    """
    Load all APT group profiles with their techniques.
    Returns: {apt_name: {"aliases": [...], "techniques": set([...]), "nation_state": str}}
    """
    bundle = load_stix_bundle()
    objects = bundle.get("objects", [])

    # Build lookup maps
    id_to_technique = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    id_to_technique[obj["id"]] = ref.get("external_id", "")
                    break

    # Get intrusion sets (APT groups)
    groups = [o for o in objects if o.get("type") == "intrusion-set"]

    # Get relationships: group -> technique
    relationships = [o for o in objects if o.get("type") == "relationship"
                     and o.get("relationship_type") == "uses"]

    # Build group -> technique mappings
    group_techniques: Dict[str, Set[str]] = {}
    group_id_to_name: Dict[str, str] = {}
    group_info: Dict[str, Dict] = {}

    for group in groups:
        name = group.get("name", "")
        aliases = group.get("aliases", [])
        # Try to extract nation state from description
        desc = group.get("description", "").lower()
        nation_state = ""
        for country in ["russia", "china", "iran", "north korea", "dprk", "israel", "vietnam", "pakistan", "india"]:
            if country in desc:
                nation_state = country.title()
                break

        group_id_to_name[group["id"]] = name
        group_techniques[name] = set()
        group_info[name] = {
            "aliases": aliases,
            "nation_state": nation_state,
            "description": group.get("description", "")[:500],
        }

    # Map techniques to groups
    for rel in relationships:
        source_ref = rel.get("source_ref", "")
        target_ref = rel.get("target_ref", "")

        group_name = group_id_to_name.get(source_ref)
        technique_id = id_to_technique.get(target_ref)

        if group_name and technique_id:
            group_techniques[group_name].add(technique_id)

    # Build final profiles
    profiles = {}
    for name, techs in group_techniques.items():
        if len(techs) >= 2:  # Only include groups with meaningful technique sets
            profiles[name] = {
                "aliases": group_info[name]["aliases"],
                "nation_state": group_info[name]["nation_state"],
                "techniques": techs,
                "technique_count": len(techs),
                "description": group_info[name]["description"],
            }

    logger.info(f"Loaded {len(profiles)} APT profiles "
                f"(avg {sum(len(p['techniques']) for p in profiles.values()) / max(len(profiles), 1):.0f} techniques each)")
    return profiles


def write_profiles_to_neo4j(profiles: Dict[str, Dict], neo4j_client) -> None:
    """Write APT profiles as nodes + USES edges in Neo4j."""
    for name, profile in profiles.items():
        # Create APTGroup node
        neo4j_client.run_write(
            """MERGE (a:APTGroup {name: $name})
            SET a.aliases = $aliases, a.nation_state = $nation_state,
                a.technique_count = $tech_count""",
            {
                "name": name,
                "aliases": profile["aliases"],
                "nation_state": profile["nation_state"],
                "tech_count": len(profile["techniques"]),
            }
        )
        # Create USES edges
        for tid in profile["techniques"]:
            neo4j_client.run_write(
                """MERGE (t:Technique {id: $tid})
                MERGE (a:APTGroup {name: $name})
                MERGE (a)-[:USES]->(t)""",
                {"tid": tid, "name": name}
            )

    logger.info(f"Wrote {len(profiles)} APT profiles to Neo4j")


def get_profile_summaries(profiles: Dict[str, Dict]) -> List[Dict]:
    """Get summary list of all APT profiles for API response."""
    summaries = []
    for name, profile in sorted(profiles.items()):
        summaries.append({
            "name": name,
            "aliases": profile["aliases"],
            "nation_state": profile["nation_state"],
            "technique_count": len(profile["techniques"]),
            "techniques": sorted(list(profile["techniques"])),
        })
    return summaries
