"""
RAPTOR | Investigation Report Generator
Per spec Section 8: generates a 1-page analyst report in natural language.
Uses RAG-grounded LLM (no naked calls).
"""
import json
from typing import List, Dict, Optional
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import REPORT_GENERATION_PROMPT
from schema import AnalysisResult, AttributionResult
from rag.pipeline import call_llm


def generate_report(
    analysis: AnalysisResult,
    attribution: List[AttributionResult],
    graph_summary: Dict,
    investigation_id: str = "",
) -> str:
    """
    Generate a full natural-language investigation report.
    Per spec Section 8, MVP deliverable #5.
    """
    logger.info(f"Generating investigation report for {investigation_id}")

    # Format findings for prompt
    findings_data = []
    for f in analysis.findings:
        findings_data.append({
            "technique_id": f.technique_id,
            "technique_name": f.technique_name,
            "kill_chain_phase": f.kill_chain_phase,
            "confidence": f.confidence,
            "evidence_summary": f.evidence_summary,
            "apt_indicators": f.apt_indicators,
        })

    # Format attribution for prompt
    attribution_data = []
    for a in attribution:
        attribution_data.append({
            "apt_name": a.apt_name,
            "confidence_score": f"{a.confidence_score:.0%}",
            "confidence_label": a.confidence_label,
            "overlapping_ttps": a.overlapping_ttps,
            "penalties": a.penalties_applied,
            "bonuses": a.bonuses_applied,
        })

    prompt = REPORT_GENERATION_PROMPT.format(
        findings_json=json.dumps(findings_data, indent=2),
        attribution_json=json.dumps(attribution_data, indent=2),
        graph_summary=json.dumps(graph_summary, indent=2),
    )

    system = """You are a senior cybersecurity analyst writing an investigation report
for the SOC team. Write in professional, clear language. Use markdown formatting.
Include specific evidence and technique IDs. The report should be thorough but concise (1 page)."""

    try:
        report = call_llm(system, prompt)
    except Exception as e:
        logger.error(f"Report LLM failed, using deterministic report: {e}")
        report = _build_fallback_report(analysis, attribution, graph_summary, investigation_id, str(e))
    logger.info(f"Report generated ({len(report)} chars)")
    return report


def _build_fallback_report(
    analysis: AnalysisResult,
    attribution: List[AttributionResult],
    graph_summary: Dict,
    investigation_id: str,
    reason: str,
) -> str:
    top = attribution[0] if attribution else None
    lines = [
        f"# RAPTOR Investigation Report",
        "",
        f"Investigation ID: `{investigation_id or 'unknown'}`",
        "",
        "## Executive Summary",
    ]
    if top:
        lines.append(
            f"RAPTOR observed {len(analysis.findings)} ATT&CK technique findings. "
            f"The closest attribution match is **{top.apt_name}** with "
            f"{top.confidence_score:.0%} confidence ({top.confidence_label})."
        )
    else:
        lines.append(
            f"RAPTOR observed {len(analysis.findings)} ATT&CK technique findings, "
            "but attribution evidence was insufficient for a high-confidence actor match."
        )

    lines.extend([
        "",
        "## Techniques Observed",
    ])
    if analysis.findings:
        for finding in analysis.findings:
            lines.append(
                f"- `{finding.technique_id}` **{finding.technique_name}** "
                f"({finding.kill_chain_phase}, {finding.confidence}): "
                f"{finding.evidence_summary}"
            )
    else:
        lines.append("- No ATT&CK techniques were identified by the local fallback pipeline.")

    lines.extend([
        "",
        "## Attack Sequence",
        ", ".join(f"`{tid}`" for tid in analysis.attack_sequence) or "No sequence available.",
        "",
        "## Attribution Assessment",
    ])
    if attribution:
        for result in attribution:
            lines.append(
                f"- **{result.apt_name}**: {result.confidence_score:.0%} "
                f"({result.confidence_label}), overlaps: "
                f"{', '.join(result.overlapping_ttps[:10]) or 'none'}"
            )
    else:
        lines.append("- No attribution data available.")

    lines.extend([
        "",
        "## Graph Summary",
        f"- Total events: {graph_summary.get('total_events', 0)}",
        f"- Unique hosts: {graph_summary.get('unique_hosts', 0)}",
        f"- Hosts with lateral movement: {graph_summary.get('hosts_compromised', 0)}",
        f"- Campaign duration: {graph_summary.get('campaign_duration_hours', 0):.1f} hours",
        "",
        "## Recommendations",
        "- Isolate compromised hosts and preserve volatile evidence.",
        "- Reset credentials observed in the affected timeline.",
        "- Hunt for the listed ATT&CK techniques across adjacent hosts.",
        "- Block suspected C2 infrastructure and review egress logs.",
        "",
        f"_Generated by deterministic fallback because the LLM report step failed: {reason[:180]}_",
    ])
    return "\n".join(lines)
