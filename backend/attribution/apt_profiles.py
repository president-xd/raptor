"""
RAPTOR | APT Profile Loader
Loads APT group TTP profiles from MITRE ATT&CK STIX bundle.
Per spec Section 5.4: store as APTGroup nodes with USES edges to Technique nodes.
"""
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import time
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attribution.attack_catalog import is_active_attack_pattern, load_stix_bundle
from config import STIX_DIR


_PROFILE_CACHE: Optional[Dict[str, Dict]] = None
_PROFILE_CACHE_META = {"expires_at": 0.0, "stix_mtime": None}
_DEFAULT_PROFILE_TTL_SECONDS = 300


def _stix_cache_path() -> Path:
    return STIX_DIR / "enterprise-attack.json"


def _stix_cache_mtime() -> float:
    path = _stix_cache_path()
    return path.stat().st_mtime if path.exists() else 0.0


def load_apt_profiles(force_reload: bool = False, ttl_seconds: int = _DEFAULT_PROFILE_TTL_SECONDS) -> Dict[str, Dict]:
    """
    Load all APT group profiles with their techniques.
    Returns: {apt_name: {"aliases": [...], "techniques": set([...]), "nation_state": str}}
    """
    global _PROFILE_CACHE, _PROFILE_CACHE_META
    now = time.time()
    stix_mtime = _stix_cache_mtime()
    if not force_reload and _PROFILE_CACHE is not None:
        cache_valid = _PROFILE_CACHE_META["expires_at"] > now
        stix_unchanged = _PROFILE_CACHE_META["stix_mtime"] == stix_mtime
        if cache_valid and stix_unchanged:
            return _PROFILE_CACHE

    bundle = load_stix_bundle()
    objects = bundle.get("objects", [])

    # Build lookup maps
    id_to_technique = {}
    for obj in objects:
        if is_active_attack_pattern(obj):
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    id_to_technique[obj["id"]] = ref.get("external_id", "")
                    break

    # Get intrusion sets (APT groups)
    groups = [
        o for o in objects
        if o.get("type") == "intrusion-set" and not o.get("revoked") and not o.get("x_mitre_deprecated")
    ]

    # Get relationships: group -> technique
    relationships = [
        o for o in objects
        if o.get("type") == "relationship"
        and o.get("relationship_type") == "uses"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    ]

    # Build group -> technique mappings
    group_techniques: Dict[str, Set[str]] = {}
    group_id_to_name: Dict[str, str] = {}
    group_info: Dict[str, Dict] = {}

    for group in groups:
        name = group.get("name", "")
        aliases = group.get("aliases", [])
        # ATT&CK does not provide a normalized country field. Keep the derived
        # value explicit so API consumers do not mistake it for authoritative
        # attribution.
        desc = group.get("description", "").lower()
        nation_state = ""
        nation_state_source = "unknown"
        for country in ["russia", "china", "iran", "north korea", "dprk", "israel", "vietnam", "pakistan", "india"]:
            if country in desc:
                nation_state = country.title()
                nation_state_source = "description_keyword"
                break

        group_id_to_name[group["id"]] = name
        group_techniques[name] = set()
        group_info[name] = {
            "aliases": aliases,
            "nation_state": nation_state,
            "nation_state_source": nation_state_source,
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
                "nation_state_source": group_info[name]["nation_state_source"],
                "techniques": techs,
                "technique_count": len(techs),
                "description": group_info[name]["description"],
            }

    logger.info(f"Loaded {len(profiles)} APT profiles "
                f"(avg {sum(len(p['techniques']) for p in profiles.values()) / max(len(profiles), 1):.0f} techniques each)")

    _PROFILE_CACHE = profiles
    _PROFILE_CACHE_META = {
        "expires_at": now + max(int(ttl_seconds), 0),
        "stix_mtime": _stix_cache_mtime(),
    }
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


def get_profile_summary(
    name: str,
    profile: Dict,
    include_techniques: bool = False,
    preview_count: int = 0,
) -> Dict:
    techniques = sorted(list(profile["techniques"]))
    if not include_techniques:
        techniques = techniques[: max(int(preview_count), 0)] if preview_count else []

    return {
        "name": name,
        "aliases": profile["aliases"],
        "nation_state": profile["nation_state"],
        "nation_state_source": profile.get("nation_state_source", "unknown"),
        "technique_count": len(profile["techniques"]),
        "techniques": techniques,
    }


def get_profile_summaries(
    profiles: Dict[str, Dict],
    include_techniques: bool = False,
    preview_count: int = 0,
) -> List[Dict]:
    """Get summary list of all APT profiles for API response."""
    summaries = []
    for name, profile in sorted(profiles.items()):
        summaries.append(
            get_profile_summary(
                name,
                profile,
                include_techniques=include_techniques,
                preview_count=preview_count,
            )
        )
    return summaries
