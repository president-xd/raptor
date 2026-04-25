"""
RAPTOR | STIX Technique ID Validator
Per spec Section 9.4: "After every LLM call, validate all technique IDs
in the output against the STIX bundle. Reject any ID not found."
This is a REQUIRED post-processing step, not optional.
"""
import json
from typing import List, Set, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import STIX_DIR
from schema import Finding, AnalysisResult


# Cache of valid technique IDs
_valid_ids: Optional[Set[str]] = None


def load_valid_technique_ids() -> Set[str]:
    """Load all valid ATT&CK technique IDs from the STIX bundle."""
    global _valid_ids
    if _valid_ids is not None:
        return _valid_ids

    cache_path = STIX_DIR / "enterprise-attack.json"
    if not cache_path.exists():
        logger.warning("STIX bundle not found, cannot validate technique IDs")
        return set()

    with open(cache_path, 'r') as f:
        bundle = json.load(f)

    _valid_ids = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    _valid_ids.add(ref.get("external_id", ""))

    logger.info(f"Loaded {len(_valid_ids)} valid ATT&CK technique IDs for validation")
    return _valid_ids


def validate_technique_id(technique_id: str) -> bool:
    """Check if a technique ID is valid."""
    valid_ids = load_valid_technique_ids()
    if not valid_ids:
        return True  # Can't validate without bundle, allow through
    return technique_id in valid_ids


def validate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Validate all technique IDs in findings against the STIX bundle.
    Reject any finding with a hallucinated technique ID.
    Per spec Section 9.4.
    """
    valid_ids = load_valid_technique_ids()
    if not valid_ids:
        logger.warning("No STIX bundle available for validation")
        return findings

    validated = []
    rejected_count = 0

    for finding in findings:
        tid = finding.technique_id
        if tid in valid_ids:
            validated.append(finding)
        else:
            rejected_count += 1
            logger.warning(f"Rejected hallucinated technique ID: {tid} "
                          f"(claimed: {finding.technique_name})")

    if rejected_count > 0:
        hallucination_rate = rejected_count / max(len(findings), 1) * 100
        logger.warning(f"STIX validation: rejected {rejected_count}/{len(findings)} findings "
                      f"({hallucination_rate:.1f}% hallucination rate)")

    return validated


def validate_analysis_result(result: AnalysisResult) -> AnalysisResult:
    """Validate and clean an entire AnalysisResult."""
    valid_ids = load_valid_technique_ids()

    # Validate findings
    result.findings = validate_findings(result.findings)

    # Validate attack sequence
    if valid_ids:
        result.attack_sequence = [tid for tid in result.attack_sequence if tid in valid_ids]

    return result
