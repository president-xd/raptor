"""
Canonical MITRE ATT&CK Enterprise metadata loader.

This module is the single backend source of truth for active ATT&CK
techniques, tactic placement, STIX cache metadata, and matrix construction.
"""
import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import ATTACK_STIX_SHA256, ATTACK_STIX_URL, STIX_DIR
from schema import Finding


TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_ALIASES = {
    "c2": "command-and-control",
    "command-and-control": "command-and-control",
    "privilege-esc": "privilege-escalation",
    "exfil": "exfiltration",
    "recon": "reconnaissance",
    "resource-dev": "resource-development",
}

_CATALOG: Optional[Dict[str, Any]] = None


def _cache_path() -> Path:
    return STIX_DIR / "enterprise-attack.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _verify_expected_sha256(actual: str) -> None:
    if ATTACK_STIX_SHA256 and actual.lower() != ATTACK_STIX_SHA256.lower():
        raise ValueError(
            f"ATT&CK STIX SHA-256 mismatch: expected {ATTACK_STIX_SHA256}, got {actual}"
        )


def load_stix_bundle(download_if_missing: bool = True) -> dict:
    """Load the cached Enterprise ATT&CK STIX bundle with optional download."""
    path = _cache_path()
    if path.exists():
        digest = _file_sha256(path)
        _verify_expected_sha256(digest)
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    if not download_if_missing:
        raise FileNotFoundError(f"ATT&CK STIX bundle not found at {path}")

    import requests
    logger.info(f"Downloading Enterprise ATT&CK STIX bundle from {ATTACK_STIX_URL}")
    response = requests.get(ATTACK_STIX_URL, timeout=120)
    response.raise_for_status()
    raw = response.content
    digest = _sha256_bytes(raw)
    _verify_expected_sha256(digest)
    STIX_DIR.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return response.json()


def _external_attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _external_attack_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def is_active_attack_pattern(obj: dict) -> bool:
    return (
        obj.get("type") == "attack-pattern"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    )


def normalize_tactic(value: str) -> str:
    tactic = str(value or "").strip().lower().replace("_", "-")
    return TACTIC_ALIASES.get(tactic, tactic)


def _extract_tactics(obj: dict) -> List[str]:
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        tactic = normalize_tactic(phase.get("phase_name", ""))
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    return sorted(tactics, key=lambda item: TACTIC_ORDER.index(item) if item in TACTIC_ORDER else 999)


def _parent_technique_id(technique_id: str) -> str:
    return technique_id.split(".", 1)[0] if "." in technique_id else ""


def load_attack_catalog(force_reload: bool = False) -> Dict[str, Any]:
    """Return active Enterprise ATT&CK technique metadata and matrix columns."""
    global _CATALOG
    if _CATALOG is not None and not force_reload:
        return _CATALOG

    path = _cache_path()
    bundle = load_stix_bundle()
    objects = bundle.get("objects", [])
    active_patterns = [obj for obj in objects if is_active_attack_pattern(obj)]
    inactive_patterns = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern" and not is_active_attack_pattern(obj)
    ]

    techniques: Dict[str, Dict[str, Any]] = {}
    for obj in active_patterns:
        technique_id = _external_attack_id(obj)
        if not technique_id:
            continue
        tactics = _extract_tactics(obj)
        techniques[technique_id] = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "kill_chain_phase": tactics[0] if tactics else "unknown",
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent_technique_id": _parent_technique_id(technique_id),
            "url": _external_attack_url(obj),
            "stix_id": obj.get("id", ""),
            "created": obj.get("created", ""),
            "modified": obj.get("modified", ""),
        }

    columns = []
    for tactic in TACTIC_ORDER:
        cells = [
            deepcopy(technique)
            for technique in techniques.values()
            if tactic in technique.get("tactics", [])
        ]
        cells.sort(key=lambda item: (item.get("parent_technique_id") or item["technique_id"], item["technique_id"]))
        columns.append({"tactic": tactic, "techniques": cells})

    digest = _file_sha256(path) if path.exists() else ""
    modified_values = [obj.get("modified", "") for obj in active_patterns if obj.get("modified")]
    latest_modified = max(modified_values) if modified_values else ""
    file_mtime = (
        datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        if path.exists()
        else ""
    )

    _CATALOG = {
        "source": {
            "bundle_id": bundle.get("id", ""),
            "spec_version": bundle.get("spec_version", ""),
            "attack_stix_url": ATTACK_STIX_URL,
            "cache_path": str(path),
            "cache_sha256": digest,
            "cache_last_modified": file_mtime,
            "latest_object_modified": latest_modified,
            "object_count": len(objects),
            "active_technique_count": len(techniques),
            "inactive_attack_pattern_count": len(inactive_patterns),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "techniques": techniques,
        "matrix": columns,
        "tactic_order": list(TACTIC_ORDER),
    }
    logger.info(
        "Loaded Enterprise ATT&CK catalog: "
        f"{len(techniques)} active techniques, {len(inactive_patterns)} inactive attack-patterns"
    )
    return _CATALOG


def get_technique_metadata(technique_id: str) -> Optional[Dict[str, Any]]:
    return load_attack_catalog().get("techniques", {}).get(str(technique_id or "").strip())


def get_valid_technique_ids() -> set[str]:
    return set(load_attack_catalog().get("techniques", {}).keys())


def canonicalize_finding(finding: Finding) -> Optional[Finding]:
    """Return a Finding enriched from active STIX metadata, or None if invalid."""
    metadata = get_technique_metadata(finding.technique_id)
    if not metadata:
        return None

    tactics = list(metadata.get("tactics") or [])
    supplied_phase = normalize_tactic(finding.kill_chain_phase)
    canonical_phase = supplied_phase if supplied_phase in tactics else (tactics[0] if tactics else "unknown")
    finding.technique_name = metadata.get("name") or finding.technique_name or finding.technique_id
    finding.tactics = tactics
    finding.kill_chain_phase = canonical_phase
    return finding


def canonicalize_findings(findings: Iterable[Finding]) -> List[Finding]:
    validated = []
    for finding in findings:
        canonical = canonicalize_finding(finding)
        if canonical:
            validated.append(canonical)
    return validated


def build_observed_lookup(findings: Iterable[Finding]) -> Dict[str, Dict[str, Any]]:
    observed: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        canonical = canonicalize_finding(finding)
        if not canonical:
            continue
        observed[canonical.technique_id] = {
            "observed": True,
            "confidence": canonical.confidence,
            "evidence_summary": canonical.evidence_summary,
            "event_ids": list(canonical.event_ids or []),
            "kill_chain_phase": canonical.kill_chain_phase,
            "tactics": list(canonical.tactics or []),
        }
    return observed


def build_matrix(findings: Optional[Iterable[Finding]] = None) -> Dict[str, Any]:
    catalog = load_attack_catalog()
    observed = build_observed_lookup(findings or [])
    columns = []
    for column in catalog["matrix"]:
        techniques = []
        for technique in column["techniques"]:
            cell = deepcopy(technique)
            cell.update(observed.get(cell["technique_id"], {"observed": False}))
            techniques.append(cell)
        columns.append({"tactic": column["tactic"], "techniques": techniques})

    return {
        "source": deepcopy(catalog["source"]),
        "tactic_order": list(catalog["tactic_order"]),
        "matrix": columns,
        "observed_count": len(observed),
    }
