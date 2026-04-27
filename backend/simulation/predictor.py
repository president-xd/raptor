"""
RAPTOR | Next-Step Prediction (Simulation Layer)
Per spec Section 6: predict what the APT would do next given current foothold.
Uses RAG-grounded LLM inference (no naked calls).
"""
import json
from typing import List, Dict, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import SIMULATION_PROMPT_TEMPLATE
from schema import SimulationPrediction, AttributionResult
from rag.pipeline import call_llm
from rag.retriever import HybridRetriever
from rag.reranker import rerank_technique_results


def predict_next_steps(
    attribution: AttributionResult,
    compromised_hosts: List[str],
    privilege_level: str,
    observed_ttps: List[str],
    network_info: str = "Corporate network, multiple subnets",
) -> List[SimulationPrediction]:
    """
    Predict the 3 most likely next techniques for the attributed APT.
    Per spec Section 6.2 workflow.
    """
    apt_name = attribution.apt_name
    logger.info(f"Simulating next steps for {apt_name} (confidence: {attribution.confidence_score:.0%})")

    # Retrieve ATT&CK context for likely next techniques (RAG - no naked LLM calls)
    retriever = HybridRetriever()
    query = f"APT {apt_name} next attack techniques after {', '.join(observed_ttps[-5:])}"
    results = retriever.search_all(query)

    # Rerank
    technique_context = rerank_technique_results(query, results.get("techniques", []), top_k=5)

    # Format retrieved context
    rag_context_lines = []
    for t in technique_context:
        rag_context_lines.append(
            f"- {t.get('technique_id', '')}: {t.get('name', '')} — {t.get('description', '')[:200]}"
        )

    # Build the simulation prompt
    prompt = SIMULATION_PROMPT_TEMPLATE.format(
        apt_name=apt_name,
        host_list=", ".join(compromised_hosts),
        privilege_level=privilege_level,
        observed_ttps=", ".join(observed_ttps),
        network_info=network_info,
        retrieved_abilities=f"Known techniques: {', '.join(attribution.overlapping_ttps)}",
        rag_context="\n".join(rag_context_lines) if rag_context_lines else "No additional context retrieved.",
    )

    # Call LLM (through RAG-grounded prompt), with deterministic fallback.
    system = "You are a red team simulation engine. Output JSON only."
    try:
        response = call_llm(system, prompt)
        predictions = _parse_predictions(response)
    except Exception as e:
        logger.error(f"Simulation LLM failed, using deterministic context predictions: {e}")
        predictions = _fallback_predictions(observed_ttps, technique_context, attribution)

    retriever.close()
    return predictions


def _parse_predictions(response: str) -> List[SimulationPrediction]:
    """Parse LLM prediction response into SimulationPrediction objects."""
    # Extract JSON
    json_str = response.strip()
    if json_str.startswith("```"):
        lines = json_str.split("\n")
        json_lines = [l for l in lines if not l.strip().startswith("```")]
        json_str = "\n".join(json_lines)

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        import re
        match = re.search(r'\{.*\}', json_str, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                logger.error("Could not parse simulation response")
                return []
        else:
            return []

    predictions = []
    for p in data.get("predictions", []):
        predictions.append(SimulationPrediction(
            technique_id=p.get("technique_id", ""),
            technique_name=p.get("technique_name", ""),
            rationale=p.get("rationale", ""),
            likely_tools=p.get("likely_tools", []),
            detection_guidance=p.get("detection_guidance", ""),
            urgency=p.get("urgency", "medium"),
        ))

    logger.info(f"Generated {len(predictions)} next-step predictions")
    return predictions


def _fallback_predictions(
    observed_ttps: List[str],
    technique_context: Optional[List[Dict]] = None,
    attribution: Optional[AttributionResult] = None,
) -> List[SimulationPrediction]:
    """Deterministic next-step predictions grounded in retrieved/attribution context."""
    seen = set(observed_ttps)
    context_predictions: List[SimulationPrediction] = []
    for technique in technique_context or []:
        technique_id = technique.get("technique_id", "")
        if not technique_id or technique_id in seen:
            continue
        technique_name = technique.get("name", technique_id)
        context_predictions.append(SimulationPrediction(
            technique_id=technique_id,
            technique_name=technique_name,
            rationale=(
                f"Retrieved ATT&CK context for {attribution.apt_name if attribution else 'the attributed actor'} "
                f"matched the current foothold and observed sequence."
            ),
            likely_tools=["Actor-specific tooling unknown", "Technique-dependent native utilities"],
            detection_guidance=technique.get("detection") or f"Monitor telemetry associated with {technique_name}.",
            urgency="high",
        ))
        if len(context_predictions) >= 3:
            return context_predictions

    candidates = [
        SimulationPrediction(
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
            rationale="Credential access and discovery often precede lateral movement into high-value servers.",
            likely_tools=["PsExec", "net use", "sc.exe"],
            detection_guidance="Alert on admin share connections from newly compromised hosts and service creation events.",
            urgency="critical",
        ),
        SimulationPrediction(
            technique_id="T1003.003",
            technique_name="NTDS",
            rationale="If domain controller access is achieved, attackers commonly attempt directory database theft.",
            likely_tools=["ntdsutil", "vssadmin", "secretsdump"],
            detection_guidance="Monitor shadow copy creation and access to ntds.dit on domain controllers.",
            urgency="high",
        ),
        SimulationPrediction(
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            rationale="Collection and archiving activity frequently leads to staged exfiltration over existing C2.",
            likely_tools=["curl", "PowerShell WebClient", "C2 beacon upload"],
            detection_guidance="Look for unusual outbound volume from servers involved in collection activity.",
            urgency="high",
        ),
        SimulationPrediction(
            technique_id="T1070.001",
            technique_name="Clear Windows Event Logs",
            rationale="After high-impact activity, operators often remove local evidence.",
            likely_tools=["wevtutil", "Clear-EventLog"],
            detection_guidance="Alert on Security log clearing and audit policy changes.",
            urgency="medium",
        ),
    ]
    return [candidate for candidate in candidates if candidate.technique_id not in seen][:3] or candidates[:3]
