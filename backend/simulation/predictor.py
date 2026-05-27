"""
RAPTOR | Next-Step Prediction (Simulation Layer)

Predicts likely adversary moves from the current investigation state. The
simulation is intentionally case-grounded: observed ATT&CK sequence, compromised
hosts, current tactic stage, and attribution overlap drive the forecast before
broader actor profile context is considered.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attribution.apt_profiles import load_apt_profiles
from attribution.attack_catalog import TACTIC_ORDER, get_technique_metadata, normalize_tactic
from schema import AttributionResult, Finding, SimulationPrediction


NEXT_MOVE_LIBRARY: List[Dict] = [
    {
        "technique_id": "T1003.001",
        "preferred_after": ["execution", "persistence", "privilege-escalation", "discovery"],
        "base_score": 82,
        "urgency": "critical",
        "tools": ["credential dumping tooling", "signed admin utilities", "endpoint memory access"],
        "preconditions": ["Interactive access to a Windows host", "Credential material likely present in memory"],
        "rationale": "The actor has execution or discovery telemetry and would likely try to expand privileges by harvesting reusable credentials.",
        "detection": "Prioritize LSASS access telemetry, suspicious handle opens, credential dumping signatures, and abnormal authentication fan-out from the same host.",
        "actions": ["Isolate the source host", "Invalidate exposed sessions", "Review privileged logons after the first execution event"],
    },
    {
        "technique_id": "T1021.002",
        "preferred_after": ["credential-access", "discovery", "lateral-movement"],
        "base_score": 86,
        "urgency": "critical",
        "tools": ["SMB admin shares", "service-control activity", "remote admin tooling"],
        "preconditions": ["Reusable credentials", "Reachable Windows admin shares"],
        "rationale": "Credential access and host discovery make SMB admin-share movement the next practical expansion path.",
        "detection": "Watch admin-share sessions, remote service creation, and authentication from newly compromised hosts to servers or domain controllers.",
        "actions": ["Restrict admin shares", "Block lateral SMB where possible", "Review logon type 3 and service creation events"],
    },
    {
        "technique_id": "T1047",
        "preferred_after": ["credential-access", "discovery", "lateral-movement"],
        "base_score": 78,
        "urgency": "high",
        "tools": ["WMI remote execution", "Windows native management", "scripted lateral execution"],
        "preconditions": ["Administrative credentials", "WMI/RPC reachable between hosts"],
        "rationale": "If SMB or admin credentials are available, WMI gives the operator a quieter remote execution lane.",
        "detection": "Correlate WMI process creation, remote logons, and unusual parent-child process trees on the destination host.",
        "actions": ["Limit remote WMI", "Inspect destination process ancestry", "Alert on cross-subnet WMI bursts"],
    },
    {
        "technique_id": "T1003.003",
        "preferred_after": ["lateral-movement", "credential-access", "collection"],
        "base_score": 91,
        "urgency": "critical",
        "requires_dc": True,
        "tools": ["directory database access", "volume shadow copy abuse", "credential extraction framework"],
        "preconditions": ["Domain controller access", "Privilege sufficient to read directory secrets"],
        "rationale": "A compromised domain controller changes the objective: directory credential theft becomes one of the highest-value next actions.",
        "detection": "Monitor ntds.dit access, shadow copy creation, suspicious backup privilege use, and outbound transfer from domain controllers.",
        "actions": ["Quarantine DC egress", "Rotate domain admin credentials", "Review backup/replication activity immediately"],
    },
    {
        "technique_id": "T1560",
        "preferred_after": ["collection", "credential-access", "lateral-movement"],
        "base_score": 80,
        "urgency": "high",
        "tools": ["archive utilities", "PowerShell compression", "staging directories"],
        "preconditions": ["Collected files or credential material", "Writable staging path"],
        "rationale": "After reaching file servers or identity infrastructure, operators commonly stage data before exfiltration.",
        "detection": "Track large archive creation, unusual compression processes, and temporary staging paths on compromised servers.",
        "actions": ["Preserve staged files", "Block external transfer paths", "Hunt for archive creation across adjacent servers"],
    },
    {
        "technique_id": "T1041",
        "preferred_after": ["collection", "command-and-control", "exfiltration"],
        "base_score": 83,
        "urgency": "critical",
        "tools": ["existing C2 channel", "beacon upload", "HTTPS egress"],
        "preconditions": ["Collection or staging complete", "Outbound C2 path still available"],
        "rationale": "Collection activity and active C2 make exfiltration over the established channel a likely objective.",
        "detection": "Correlate C2 beaconing with outbound byte spikes from compromised hosts and newly created archives.",
        "actions": ["Block known C2", "Capture proxy/DNS evidence", "Limit egress from affected hosts"],
    },
    {
        "technique_id": "T1048",
        "preferred_after": ["collection", "exfiltration"],
        "base_score": 77,
        "urgency": "high",
        "tools": ["alternative protocol egress", "cloud upload utility", "non-standard transfer path"],
        "preconditions": ["Staged data", "Open outbound protocol or unmanaged cloud path"],
        "rationale": "If primary C2 is disrupted, a financially motivated operator may pivot to alternate protocol exfiltration.",
        "detection": "Look for unusual destination ports, protocol mismatches, cloud uploads, and high-volume transfers from non-user systems.",
        "actions": ["Apply temporary egress allow-listing", "Review proxy logs", "Snapshot staged directories"],
    },
    {
        "technique_id": "T1070.001",
        "preferred_after": ["exfiltration", "impact", "collection", "credential-access"],
        "base_score": 74,
        "urgency": "high",
        "tools": ["event log clearing", "audit policy tampering", "cleanup scripts"],
        "preconditions": ["Local administrative rights", "Operator preparing to exit or escalate impact"],
        "rationale": "Once high-value activity is complete, log clearing or audit tampering is a common attempt to reduce visibility.",
        "detection": "Alert on Security log clearing, audit policy changes, and gaps in endpoint telemetry after privileged activity.",
        "actions": ["Export logs immediately", "Preserve EDR telemetry", "Compare endpoint logs with domain controller logs"],
    },
    {
        "technique_id": "T1098",
        "preferred_after": ["credential-access", "lateral-movement", "exfiltration"],
        "base_score": 76,
        "urgency": "high",
        "tools": ["account permission changes", "new privileged membership", "persistence through identity"],
        "preconditions": ["Credential or directory control", "Access to identity management plane"],
        "rationale": "After credential theft or domain movement, the actor may create durable access through account manipulation.",
        "detection": "Monitor privileged group changes, unexpected account creation, service principal changes, and dormant account reactivation.",
        "actions": ["Freeze privileged group changes", "Review account deltas", "Force credential rotation for affected users"],
    },
    {
        "technique_id": "T1105",
        "preferred_after": ["execution", "command-and-control", "lateral-movement"],
        "base_score": 69,
        "urgency": "medium",
        "tools": ["tool transfer over C2", "remote download", "internal staging"],
        "preconditions": ["Active C2 or remote execution path", "Need for additional tooling"],
        "rationale": "Operators often bring in additional tooling once they understand the environment and target path.",
        "detection": "Watch for new binaries or scripts landing on compromised hosts shortly after C2 or remote execution events.",
        "actions": ["Block unknown downloads", "Collect new files for triage", "Review process execution after file creation"],
    },
    {
        "technique_id": "T1490",
        "preferred_after": ["exfiltration", "defense-evasion", "impact"],
        "base_score": 72,
        "urgency": "high",
        "tools": ["recovery inhibition", "backup disruption", "shadow copy removal"],
        "preconditions": ["Administrative rights", "Operator preparing impact or extortion phase"],
        "rationale": "After exfiltration and cleanup behavior, the next risk is preparation for impact or extortion by weakening recovery paths.",
        "detection": "Alert on shadow copy deletion, backup service tampering, and recovery tooling changes on servers.",
        "actions": ["Protect backups", "Restrict admin execution", "Verify recovery points before containment steps"],
    },
    {
        "technique_id": "T1486",
        "preferred_after": ["exfiltration", "defense-evasion", "impact"],
        "base_score": 68,
        "urgency": "critical",
        "tools": ["encryption payload", "mass file modification", "extortion workflow"],
        "preconditions": ["Broad file access", "Recovery paths weakened", "Operator objective shifts to impact"],
        "rationale": "When exfiltration is already present, impact through encryption becomes a high-consequence scenario to preempt even if not yet observed.",
        "detection": "Detect rapid file renames, entropy shifts, ransom-note creation, and abnormal writes from privileged accounts.",
        "actions": ["Segment file servers", "Disable compromised accounts", "Enable high-sensitivity file integrity monitoring"],
    },
]


def predict_next_steps(
    attribution: AttributionResult,
    compromised_hosts: List[str],
    privilege_level: str,
    observed_ttps: List[str],
    network_info: str = "Corporate network, multiple subnets",
    findings: Optional[List[Finding]] = None,
    attack_sequence: Optional[List[str]] = None,
) -> List[SimulationPrediction]:
    """Predict the most likely next techniques from the current case state."""
    apt_name = attribution.apt_name or "Unknown actor"
    logger.info(
        f"Simulating next steps for {apt_name} "
        f"(confidence: {attribution.confidence_score:.0%})"
    )
    findings = findings or []
    observed = _dedupe([*observed_ttps, *(attack_sequence or [])])
    observed_set = set(observed)
    current_stage = _current_stage(observed, findings)
    allowed_next_tactics = _next_tactic_window(current_stage)
    actor_techniques = _actor_techniques(apt_name)
    dc_compromised = _has_domain_controller(compromised_hosts, findings)

    scored: List[tuple[int, Dict]] = []
    for candidate in NEXT_MOVE_LIBRARY:
        tid = candidate["technique_id"]
        if tid in observed_set:
            continue
        metadata = get_technique_metadata(tid) or {}
        tactic = _primary_tactic(metadata, candidate)
        if tactic not in allowed_next_tactics:
            continue
        if candidate.get("requires_dc") and not dc_compromised:
            continue

        score = int(candidate.get("base_score", 50))
        if tid in actor_techniques:
            score += 13
        if tid in set(attribution.overlapping_ttps or []):
            score += 8
        if candidate.get("requires_dc"):
            score += 9
        if tactic in _observed_tactics(findings):
            score -= 6
        if attribution.confidence_label == "UNKNOWN":
            score -= 4
        scored.append((score, {**candidate, "metadata": metadata, "tactic": tactic}))

    if len(scored) < 3:
        for candidate in NEXT_MOVE_LIBRARY:
            tid = candidate["technique_id"]
            if tid in observed_set or any(item[1]["technique_id"] == tid for item in scored):
                continue
            metadata = get_technique_metadata(tid) or {}
            if candidate.get("requires_dc") and not dc_compromised:
                continue
            tactic = _primary_tactic(metadata, candidate)
            scored.append((int(candidate.get("base_score", 50)) - 12, {**candidate, "metadata": metadata, "tactic": tactic}))
            if len(scored) >= 5:
                break

    scored.sort(key=lambda item: item[0], reverse=True)
    top = scored[:3]
    if not top:
        top = [(60, {**candidate, "metadata": get_technique_metadata(candidate["technique_id"]) or {}, "tactic": "unknown"}) for candidate in NEXT_MOVE_LIBRARY[:3]]

    max_score = max(score for score, _ in top) or 1
    predictions: List[SimulationPrediction] = []
    for score, candidate in top:
        metadata = candidate.get("metadata") or {}
        probability = min(88, max(42, round(50 + (score / max_score) * 32)))
        name = metadata.get("name") or candidate.get("technique_name") or candidate["technique_id"]
        basis = _evidence_basis(current_stage, compromised_hosts, observed, findings, attribution)
        predictions.append(SimulationPrediction(
            technique_id=candidate["technique_id"],
            technique_name=name,
            tactic=candidate.get("tactic") or metadata.get("kill_chain_phase", "unknown"),
            probability=probability,
            rationale=_grounded_rationale(candidate, current_stage, attribution, compromised_hosts, privilege_level, network_info),
            likely_tools=list(candidate.get("tools", [])),
            preconditions=list(candidate.get("preconditions", [])),
            immediate_actions=list(candidate.get("actions", [])),
            detection_guidance=candidate.get("detection", "Review endpoint, identity, and network telemetry for this technique."),
            evidence_basis=basis,
            urgency=candidate.get("urgency", "medium"),
        ))
    return predictions


def build_simulation_context_summary(
    attribution: AttributionResult,
    findings: Sequence[Finding],
    compromised_hosts: Sequence[str],
    observed_ttps: Sequence[str],
) -> str:
    stage = derive_current_stage(observed_ttps, findings)
    host_text = ", ".join(compromised_hosts[:5]) if compromised_hosts else "no explicitly compromised host extracted"
    confidence = attribution.confidence_label or "UNKNOWN"
    return (
        f"Current case is in the {stage.replace('-', ' ')} portion of the attack path with "
        f"{len(set(observed_ttps))} observed ATT&CK techniques and compromised assets: {host_text}. "
        f"Top attribution candidate is {attribution.apt_name or 'Unknown'} ({confidence}); treat actor-specific moves as leads, not proof."
    )


def derive_current_stage(observed_ttps: Sequence[str], findings: Sequence[Finding]) -> str:
    return _current_stage(list(observed_ttps), list(findings))


def build_response_actions(predictions: Sequence[SimulationPrediction]) -> List[str]:
    actions: List[str] = []
    for prediction in predictions:
        for action in prediction.immediate_actions:
            if action and action not in actions:
                actions.append(action)
            if len(actions) >= 5:
                return actions
    return actions or [
        "Preserve volatile telemetry before containment.",
        "Isolate confirmed compromised hosts from user networks.",
        "Hunt for the predicted techniques across adjacent systems.",
    ]


def _current_stage(observed_ttps: Sequence[str], findings: Sequence[Finding]) -> str:
    phases: List[str] = []
    finding_by_tid = {finding.technique_id: finding for finding in findings}
    for tid in observed_ttps:
        finding = finding_by_tid.get(tid)
        phase = normalize_tactic(finding.kill_chain_phase if finding else "")
        if not phase:
            metadata = get_technique_metadata(tid) or {}
            phase = normalize_tactic(metadata.get("kill_chain_phase", ""))
        if phase:
            phases.append(phase)
    phases.extend(normalize_tactic(finding.kill_chain_phase) for finding in findings if finding.kill_chain_phase)
    ranked = [phase for phase in phases if phase in TACTIC_ORDER]
    if not ranked:
        return "execution"
    return max(ranked, key=lambda phase: TACTIC_ORDER.index(phase))


def _next_tactic_window(stage: str) -> set[str]:
    stage = normalize_tactic(stage)
    if stage in {"reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation"}:
        return {"discovery", "credential-access", "defense-evasion", "command-and-control", "lateral-movement"}
    if stage in {"defense-evasion", "credential-access", "discovery"}:
        return {"lateral-movement", "credential-access", "collection", "command-and-control", "defense-evasion"}
    if stage == "lateral-movement":
        return {"credential-access", "collection", "command-and-control", "exfiltration", "defense-evasion"}
    if stage == "collection":
        return {"exfiltration", "defense-evasion", "impact", "command-and-control"}
    if stage in {"command-and-control", "exfiltration", "impact"}:
        return {"exfiltration", "defense-evasion", "impact", "persistence", "command-and-control"}
    return {"credential-access", "discovery", "lateral-movement", "collection"}


def _actor_techniques(apt_name: str) -> set[str]:
    try:
        profile = load_apt_profiles().get(apt_name or "") or {}
        return set(profile.get("techniques") or [])
    except Exception as exc:
        logger.warning(f"APT profile lookup failed for simulation: {exc}")
        return set()


def _primary_tactic(metadata: Dict, candidate: Dict) -> str:
    tactics = metadata.get("tactics") or []
    preferred = candidate.get("preferred_after") or []
    for tactic in tactics:
        if tactic in preferred:
            return tactic
    return normalize_tactic(metadata.get("kill_chain_phase") or (tactics[0] if tactics else "")) or "unknown"


def _observed_tactics(findings: Iterable[Finding]) -> set[str]:
    return {normalize_tactic(finding.kill_chain_phase) for finding in findings if finding.kill_chain_phase}


def _has_domain_controller(compromised_hosts: Sequence[str], findings: Sequence[Finding]) -> bool:
    host_text = " ".join(compromised_hosts).lower()
    if "dc" in host_text or "domain" in host_text:
        return True
    return any("domain controller" in finding.evidence_summary.lower() or "ntds" in finding.technique_name.lower() for finding in findings)


def _grounded_rationale(candidate: Dict, current_stage: str, attribution: AttributionResult, compromised_hosts: Sequence[str], privilege_level: str, network_info: str) -> str:
    host_text = ", ".join(compromised_hosts[:4]) if compromised_hosts else "the currently scoped assets"
    actor = attribution.apt_name or "the attributed actor"
    return (
        f"{candidate.get('rationale', '').rstrip()} In this case, {actor} is being assessed from a "
        f"{current_stage.replace('-', ' ')} stage with {privilege_level} and focus on {host_text}. "
        f"Network context: {network_info}."
    )


def _evidence_basis(current_stage: str, compromised_hosts: Sequence[str], observed_ttps: Sequence[str], findings: Sequence[Finding], attribution: AttributionResult) -> str:
    recent = ", ".join(observed_ttps[-5:]) if observed_ttps else "no ordered sequence"
    hosts = ", ".join(compromised_hosts[:4]) if compromised_hosts else "host context unavailable"
    overlap_count = len(attribution.overlapping_ttps or [])
    return (
        f"Stage={current_stage}; recent observed TTPs={recent}; compromised hosts={hosts}; "
        f"actor overlap={overlap_count} ATT&CK techniques."
    )


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for value in values:
        item = str(value or "").strip()
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
