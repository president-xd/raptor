"""
RAPTOR | Confidence Scoring Engine
Full confidence formula from spec Section 5.2 (The False Flag Problem).

Base score: Jaccard similarity
Penalty 1: -0.15 if observed TTPs overlap with >=2 other APT groups at >0.4 Jaccard
Penalty 2: -0.10 if campaign duration < 72h
Bonus 1:   +0.10 if infrastructure (C2 IPs/domains) matches known APT infrastructure
Bonus 2:   +0.05 if malware families match
Bonus 3:   +0.10 if temporal TTP sequence matches known APT playbook order

Final confidence:
  > 0.75: HIGH
  0.50-0.75: MEDIUM
  0.30-0.50: LOW
  < 0.30: UNKNOWN
"""
from typing import List, Dict, Set, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from schema import AttributionResult
from attribution.jaccard import jaccard_attribution


def calculate_confidence(
    observed_ttps: Set[str],
    apt_profiles: Dict[str, Dict],
    campaign_duration_hours: float = 0,
    matched_infrastructure: bool = False,
    matched_malware: bool = False,
    temporal_sequence_match: bool = False,
    top_n: int = 3,
) -> List[AttributionResult]:
    """
    Calculate full attribution confidence with penalties and bonuses.
    Per spec Section 5.2. Always returns top-3 (never just top-1, per Section 9.2).
    """
    # Get base Jaccard scores
    jaccard_results = jaccard_attribution(observed_ttps, apt_profiles)

    if not jaccard_results:
        return []

    # Check for multi-group overlap (Penalty 1)
    high_overlap_count = sum(1 for r in jaccard_results if r["jaccard"] > 0.4)

    attribution_results = []
    for i, result in enumerate(jaccard_results[:top_n]):
        base_score = result["jaccard"]
        penalties = []
        bonuses = []

        # Penalty 1: Multi-group overlap
        if high_overlap_count >= 2 and i == 0:
            base_score -= 0.15
            penalties.append(f"Multi-group overlap penalty (-0.15): {high_overlap_count} groups have Jaccard > 0.4")

        # Penalty 2: Short campaign duration
        if campaign_duration_hours > 0 and campaign_duration_hours < 72:
            base_score -= 0.10
            penalties.append(f"Short campaign penalty (-0.10): {campaign_duration_hours:.0f}h < 72h threshold")

        # Bonus 1: Infrastructure match
        if matched_infrastructure:
            base_score += 0.10
            bonuses.append("Infrastructure match bonus (+0.10): C2 IP/domain matches known APT infrastructure")

        # Bonus 2: Malware family match
        if matched_malware:
            base_score += 0.05
            bonuses.append("Malware family match bonus (+0.05)")

        # Bonus 3: Temporal sequence match
        if temporal_sequence_match:
            base_score += 0.10
            bonuses.append("Temporal sequence match bonus (+0.10): TTP order matches known playbook")

        # Clamp to [0, 1]
        confidence_score = max(0.0, min(1.0, base_score))

        # Determine confidence label
        if confidence_score > 0.75:
            label = "HIGH"
        elif confidence_score >= 0.50:
            label = "MEDIUM"
        elif confidence_score >= 0.30:
            label = "LOW"
        else:
            label = "UNKNOWN"

        attribution_results.append(AttributionResult(
            apt_name=result["apt"],
            aliases=result.get("aliases", []),
            jaccard_score=result["jaccard"],
            confidence_score=round(confidence_score, 3),
            confidence_label=label,
            overlapping_ttps=result["overlap"],
            ttp_count=result["apt_total_techniques"],
            penalties_applied=penalties,
            bonuses_applied=bonuses,
        ))

    # Log the false flag warning per spec Section 9.2
    if len(attribution_results) >= 2:
        top = attribution_results[0]
        runner_up = attribution_results[1]
        if runner_up.confidence_score > 0.4:
            logger.warning(
                f"False flag alert: Top match {top.apt_name} ({top.confidence_score:.0%}), "
                f"but {runner_up.apt_name} is also plausible ({runner_up.confidence_score:.0%}). "
                f"Note: APT groups have been observed mimicking each other's TTPs."
            )

    return attribution_results


def format_attribution_summary(results: List[AttributionResult]) -> str:
    """Format attribution results as human-readable summary."""
    if not results:
        return "No attribution data available."

    lines = []
    for i, r in enumerate(results):
        indicator = "→" if i == 0 else " "
        lines.append(
            f"{indicator} {r.apt_name} ({r.confidence_score:.0%} confidence, {r.confidence_label}) — "
            f"{len(r.overlapping_ttps)} technique overlaps: {', '.join(r.overlapping_ttps[:7])}"
            f"{'...' if len(r.overlapping_ttps) > 7 else ''}"
        )
        if r.penalties_applied:
            for p in r.penalties_applied:
                lines.append(f"    [penalty] {p}")
        if r.bonuses_applied:
            for b in r.bonuses_applied:
                lines.append(f"    [bonus] {b}")

    return "\n".join(lines)
