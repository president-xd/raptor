"""
RAPTOR | Analysis Router
POST /api/v1/simulate              — next-step attack simulation
POST /api/v1/query                 — NLQ against investigation
GET  /api/v1/mitre/matrix          — MITRE ATT&CK matrix (+ overlay)
GET  /api/v1/apt/profiles          — list APT profiles
GET  /api/v1/apt/profiles/{name}   — single APT profile
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from loguru import logger

from auth_core import audit_log, enforce_rate_limit, ensure_investigation_access, require_role
from models import (
    APTProfileListResponse,
    APTProfileSummary,
    MitreMatrixResponse,
    QueryRequest,
    QueryResponse,
    SimulateRequest,
    SimulationResponse,
)
from schema import AttributionResult, Finding

router = APIRouter(tags=["analysis"])


@router.post("/api/v1/simulate", response_model=SimulationResponse)
def simulate(request: Request, payload: SimulateRequest) -> SimulationResponse:
    """Predict next attack steps for the attributed APT group."""
    record = ensure_investigation_access(request, payload.investigation_id, "analyst")
    if record["status"] != "complete":
        raise HTTPException(status_code=400, detail="Investigation not complete yet")

    attribution_data = json.loads(record.get("attribution_json") or "[]")
    if not attribution_data:
        raise HTTPException(status_code=400, detail="No attribution data available")

    target_apt = payload.apt_group
    attribution: Optional[AttributionResult] = None
    for a in attribution_data:
        attr = AttributionResult(**a)
        if target_apt and attr.apt_name == target_apt:
            attribution = attr
            break
        elif not target_apt:
            attribution = attr
            break
    if attribution is None:
        attribution = AttributionResult(**attribution_data[0])

    if attribution.confidence_label in {"UNKNOWN", "LOW"}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Simulation blocked: low-confidence attribution "
                f"({attribution.confidence_label}, {attribution.confidence_score:.0%}). "
                "Refine evidence before prediction."
            ),
        )

    observed_ttps = [
        f.get("technique_id", "")
        for f in json.loads(record.get("findings_json") or "[]")
        if f.get("technique_id")
    ]

    compromised_hosts: list[str] = []
    try:
        for node in json.loads(record.get("graph_json") or "{}").get("nodes", []):
            if node.get("node_type") == "host" and node.get("metadata", {}).get("compromised"):
                compromised_hosts.append(node.get("label") or node.get("id"))
    except Exception:
        pass

    if not compromised_hosts:
        raise HTTPException(
            status_code=400,
            detail="Simulation requires at least one compromised host in the graph.",
        )

    from simulation.predictor import predict_next_steps

    predictions = predict_next_steps(
        attribution=attribution,
        compromised_hosts=compromised_hosts,
        privilege_level="domain user / admin",
        observed_ttps=observed_ttps,
    )
    audit_log(
        request,
        "simulation.run",
        payload.investigation_id,
        {"apt_group": attribution.apt_name, "prediction_count": len(predictions)},
    )
    return SimulationResponse(
        investigation_id=payload.investigation_id,
        apt_group=attribution.apt_name,
        predictions=predictions,
        confidence=attribution.confidence_label,
    )


@router.post("/api/v1/query", response_model=QueryResponse)
def query(request: Request, payload: QueryRequest) -> QueryResponse:
    """Answer a natural-language question about a completed investigation."""
    enforce_rate_limit(request, "query")
    record = ensure_investigation_access(request, payload.investigation_id, "viewer")
    if record["status"] != "complete":
        raise HTTPException(status_code=400, detail="Investigation not complete yet")

    from nlq.query_engine import QueryEngine

    neo4j = None
    try:
        from graph.neo4j_client import Neo4jClient

        neo4j = Neo4jClient()
    except Exception:
        neo4j = None

    engine = QueryEngine(neo4j_client=neo4j)
    try:
        result = engine.answer_question(payload.question, payload.investigation_id)
    finally:
        engine.close()

    audit_log(
        request,
        "query.asked",
        payload.investigation_id,
        {
            "query_type": result.get("query_type", ""),
            "question": payload.question[:200],
            "answer_preview": str(result.get("answer", ""))[:500],
            "source_count": len(result.get("sources", [])),
        },
    )
    return QueryResponse(
        answer=result.get("answer", ""),
        sources=result.get("sources", []),
        confidence=result.get("confidence", ""),
        query_type=result.get("query_type", ""),
    )


@router.get("/api/v1/mitre/matrix", response_model=MitreMatrixResponse)
def get_mitre_matrix(
    request: Request, investigation_id: Optional[str] = None
) -> MitreMatrixResponse:
    """Return the Enterprise ATT&CK matrix, optionally overlaid with investigation findings."""
    require_role(request, "viewer")

    findings: list[Finding] = []
    if investigation_id:
        record = ensure_investigation_access(request, investigation_id, "viewer")
        for item in json.loads(record.get("findings_json") or "[]"):
            findings.append(Finding(**item))

    from attribution.attack_catalog import build_matrix

    matrix = build_matrix(findings)
    audit_log(
        request,
        "mitre_matrix.viewed",
        investigation_id,
        {
            "observed_count": matrix.get("observed_count", 0),
            "active_technique_count": matrix.get("source", {}).get(
                "active_technique_count", 0
            ),
        },
    )
    return MitreMatrixResponse(**matrix)


@router.get("/api/v1/apt/profiles", response_model=APTProfileListResponse)
def get_apt_profiles(
    request: Request, include_techniques: bool = False
) -> APTProfileListResponse:
    """List all APT group profiles with TTP counts."""
    require_role(request, "viewer")
    from attribution.apt_profiles import get_profile_summaries, load_apt_profiles

    profiles = load_apt_profiles()
    summaries = get_profile_summaries(profiles, include_techniques=include_techniques)
    audit_log(request, "apt_profiles.listed", None, {"count": len(summaries)})
    return APTProfileListResponse(
        profiles=[APTProfileSummary(**s) for s in summaries],
        total_count=len(summaries),
    )


@router.get("/api/v1/apt/profiles/{apt_name}", response_model=APTProfileSummary)
def get_apt_profile(request: Request, apt_name: str) -> APTProfileSummary:
    """Return full TTP details for a single APT profile."""
    require_role(request, "viewer")
    from attribution.apt_profiles import get_profile_summary, load_apt_profiles

    profiles = load_apt_profiles()
    profile = profiles.get(apt_name)
    if not profile:
        raise HTTPException(status_code=404, detail="APT profile not found")
    return APTProfileSummary(
        **get_profile_summary(apt_name, profile, include_techniques=True)
    )
