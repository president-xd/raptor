"""
RAPTOR | Jaccard Attribution Engine
Per spec Section 4.5: Jaccard similarity between observed TTPs and known APT profiles.
"""
from typing import Dict, List, Set
from loguru import logger


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculate Jaccard similarity between two sets."""
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def jaccard_attribution(observed_ttps: Set[str], apt_profiles: Dict[str, Dict]) -> List[Dict]:
    """
    Rank APT groups by Jaccard similarity to observed TTPs.
    Per spec Section 4.5.
    
    Args:
        observed_ttps: Set of observed ATT&CK technique IDs
        apt_profiles: Dict of {apt_name: {"techniques": set([...]), ...}}
    
    Returns:
        Sorted list of attribution scores
    """
    scores = []
    for apt_name, profile in apt_profiles.items():
        apt_ttps = profile.get("techniques", set())
        if isinstance(apt_ttps, list):
            apt_ttps = set(apt_ttps)

        jaccard = jaccard_similarity(observed_ttps, apt_ttps)
        overlap = sorted(list(observed_ttps & apt_ttps))

        scores.append({
            "apt": apt_name,
            "aliases": profile.get("aliases", []),
            "nation_state": profile.get("nation_state", ""),
            "jaccard": jaccard,
            "overlap": overlap,
            "overlap_count": len(overlap),
            "apt_total_techniques": len(apt_ttps),
            "observed_total": len(observed_ttps),
        })

    # Sort by jaccard score descending
    scores.sort(key=lambda x: x["jaccard"], reverse=True)
    logger.info(f"Jaccard attribution: top match is {scores[0]['apt']} "
                f"({scores[0]['jaccard']:.3f}) with {scores[0]['overlap_count']} overlapping TTPs"
                if scores else "No matches")
    return scores
