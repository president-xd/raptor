"""
RAPTOR | Investigations Router
POST /api/v1/investigate               — upload file
POST /api/v1/investigate/text          — paste logs or Elasticsearch query
GET  /api/v1/investigations            — list investigations
GET  /api/v1/investigate/{id}/status   — poll progress
GET  /api/v1/investigate/{id}/report   — full report
GET  /api/v1/investigate/{id}/graph    — Sigma.js graph JSON
GET  /api/v1/investigate/{id}/evidence — stored raw evidence metadata
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from loguru import logger

from auth_core import (
    audit_log,
    enforce_rate_limit,
    ensure_investigation_access,
    require_role,
)
from config import MAX_UPLOAD_BYTES
from database import db_list, db_update, list_evidence_files
from models import (
    EvidenceFileSummary,
    EvidenceListResponse,
    InvestigateResponse,
    InvestigateTextRequest,
    InvestigationListItem,
    InvestigationListResponse,
    InvestigationReport,
    InvestigationStatus,
)
from pipeline_runner import fetch_elasticsearch_logs, start_investigation_from_content
from report.generator import build_enterprise_report, report_needs_upgrade
from schema import AnalysisResult, AttributionResult, Finding

router = APIRouter(tags=["investigations"])


@router.post("/api/v1/investigate", response_model=InvestigateResponse)
async def investigate(
    request: Request,
    file: UploadFile = File(...),
    case_name: Optional[str] = Form(None),
) -> InvestigateResponse:
    """Upload a log file and start an investigation."""
    enforce_rate_limit(request, "upload")
    principal = require_role(request, "analyst")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(content)} bytes). Max is {MAX_UPLOAD_BYTES}.",
        )

    log_content = content.decode("utf-8", errors="replace")
    metadata = {
        "source": "file",
        "filename": file.filename,
        "content_type": file.content_type or "application/octet-stream",
        "case_name": case_name or file.filename or "",
        "owner_id": principal.get("user_id") or principal.get("actor"),
        "tenant_id": principal.get("tenant_id", "default"),
    }
    response = start_investigation_from_content(log_content, metadata, raw_bytes=content)
    audit_log(
        request,
        "investigation.created",
        response.investigation_id,
        {"source": "file", "filename": file.filename, "case_name": metadata["case_name"]},
    )
    return response


@router.post("/api/v1/investigate/text", response_model=InvestigateResponse)
def investigate_text(
    request: Request, payload: InvestigateTextRequest
) -> InvestigateResponse:
    """Start an investigation from pasted logs or an Elasticsearch query."""
    enforce_rate_limit(request, "upload")
    principal = require_role(request, "analyst")

    log_content = payload.log_content or ""
    if not log_content.strip() and payload.elastic_query:
        log_content = fetch_elasticsearch_logs(
            payload.elastic_query,
            payload.time_range_start,
            payload.time_range_end,
        )

    metadata = {
        "source": payload.source,
        "filename": f"{payload.source or 'text'}_input.jsonl",
        "case_name": payload.case_name,
        "elastic_query": payload.elastic_query,
        "time_range_start": payload.time_range_start,
        "time_range_end": payload.time_range_end,
        "sensitivity": payload.sensitivity,
        "apt_filters": payload.apt_filters,
        "owner_id": principal.get("user_id") or principal.get("actor"),
        "tenant_id": principal.get("tenant_id", "default"),
    }
    response = start_investigation_from_content(log_content, metadata)
    audit_log(
        request,
        "investigation.created",
        response.investigation_id,
        {"source": payload.source, "case_name": payload.case_name},
    )
    return response


@router.get("/api/v1/investigations", response_model=InvestigationListResponse)
async def list_investigations(
    request: Request, limit: int = 25, offset: int = 0
) -> InvestigationListResponse:
    """List recent investigations for case-management UI."""
    principal = require_role(request, "viewer")
    rows = db_list(max(1, min(limit, 100)), max(0, offset), principal)
    items = [
        InvestigationListItem(
            investigation_id=row.get("id", ""),
            name=row.get("name") or "",
            source=row.get("source") or "",
            status=row.get("status", "queued"),
            progress=row.get("progress", 0) or 0,
            current_phase=row.get("current_phase") or "",
            event_count=row.get("event_count") or 0,
            technique_count=row.get("technique_count") or 0,
            host_count=row.get("host_count") or 0,
            input_bytes=row.get("input_bytes") or 0,
            top_candidate=row.get("top_candidate") or "",
            confidence_score=float(row.get("confidence_score") or 0.0),
            confidence_label=row.get("confidence_label") or "",
            created_at=row.get("created_at") or "",
            completed_at=row.get("completed_at"),
            error=row.get("error"),
        )
        for row in rows
    ]
    return InvestigationListResponse(investigations=items, total_count=len(items))


@router.get(
    "/api/v1/investigate/{investigation_id}/status",
    response_model=InvestigationStatus,
)
async def get_status(
    request: Request, investigation_id: uuid.UUID
) -> InvestigationStatus:
    """Poll investigation progress."""
    investigation_id = str(investigation_id)
    record = ensure_investigation_access(request, investigation_id, "viewer")
    return InvestigationStatus(
        investigation_id=investigation_id,
        name=record.get("name") or "",
        status=record["status"],
        progress=record["progress"],
        current_phase=record.get("current_phase") or "",
        error=record.get("error"),
    )


@router.get(
    "/api/v1/investigate/{investigation_id}/report",
    response_model=InvestigationReport,
)
async def get_report(
    request: Request, investigation_id: uuid.UUID
) -> InvestigationReport:
    """Return the full investigation report."""
    investigation_id = str(investigation_id)
    record = ensure_investigation_access(request, investigation_id, "viewer")

    findings: list[Finding] = []
    if record.get("findings_json"):
        for f in json.loads(record["findings_json"]):
            findings.append(Finding(**f))
    try:
        from attribution.attack_catalog import canonicalize_findings
        findings = canonicalize_findings(findings)
    except Exception as exc:
        logger.warning(f"Could not canonicalize findings for {investigation_id}: {exc}")

    attribution: list[AttributionResult] = []
    if record.get("attribution_json"):
        for a in json.loads(record["attribution_json"]):
            attribution.append(AttributionResult(**a))

    attack_seq = json.loads(record["attack_sequence_json"]) if record.get("attack_sequence_json") else []
    anomalies = json.loads(record["anomalies_json"]) if record.get("anomalies_json") else []
    narrative_report = record.get("narrative_report") or ""
    if record.get("status") == "complete" and report_needs_upgrade(narrative_report):
        analysis = AnalysisResult(
            findings=findings,
            attack_sequence=attack_seq,
            anomalies=anomalies,
        )
        narrative_report = build_enterprise_report(
            analysis,
            attribution,
            _graph_summary_from_record(record, findings),
            investigation_id,
            report_name=record.get("name") or "",
            generation_note="Legacy or missing report upgraded and persisted by report view endpoint.",
        )
        db_update(investigation_id, narrative_report=narrative_report)
        logger.info(f"Upgraded stored enterprise report for {investigation_id}")

    audit_log(request, "report.viewed", investigation_id, {"status": record["status"]})
    return InvestigationReport(
        investigation_id=investigation_id,
        name=record.get("name") or "",
        status=record["status"],
        findings=findings,
        attack_sequence=attack_seq,
        anomalies=anomalies,
        attribution=attribution,
        narrative_report=narrative_report,
        event_count=record.get("event_count") or 0,
        technique_count=record.get("technique_count") or 0,
        timestamp=record.get("created_at") or "",
    )


def _graph_summary_from_record(record: dict, findings: list[Finding]) -> dict:
    graph = {}
    if record.get("graph_json"):
        try:
            graph = json.loads(record.get("graph_json") or "{}")
        except Exception:
            graph = {}
    nodes = graph.get("nodes") if isinstance(graph, dict) else []
    nodes = nodes if isinstance(nodes, list) else []
    host_nodes = [
        node for node in nodes
        if str(node.get("node_type") or node.get("kind") or "").lower() == "host"
    ]
    compromised = 0
    for node in host_nodes:
        metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
        if metadata.get("compromised") or node.get("compromised"):
            compromised += 1

    def _labels(kind: str) -> list[str]:
        out: list[str] = []
        for node in nodes:
            node_type = str(node.get("node_type") or node.get("kind") or "").lower()
            if node_type != kind:
                continue
            label = str(node.get("label") or node.get("id") or "").split("\n")[0].strip()
            if label and label not in out:
                out.append(label)
        return out[:12]

    return {
        "total_events": int(record.get("event_count") or 0),
        "unique_hosts": len(host_nodes) or _host_count_from_findings(findings),
        "hosts_compromised": compromised,
        "campaign_duration_hours": 0.0,
        # Scope derived from persisted graph nodes so legacy report upgrades keep
        # populating these fields after evidence summaries stopped carrying JSON.
        "affected_hosts": _labels("host"),
        "observed_users": _labels("user"),
        "observed_processes": _labels("process"),
    }


def _host_count_from_findings(findings: list[Finding]) -> int:
    hosts: set[str] = set()
    for finding in findings:
        summary = finding.evidence_summary or ""
        for marker in ('"host": "', '"source_host": "', '"dest_host": "'):
            start = 0
            while True:
                index = summary.find(marker, start)
                if index < 0:
                    break
                index += len(marker)
                end = summary.find('"', index)
                if end < 0:
                    break
                value = summary[index:end].strip()
                if value:
                    hosts.add(value)
                start = end + 1
    return len(hosts)


@router.get("/api/v1/investigate/{investigation_id}/graph")
async def get_graph(request: Request, investigation_id: uuid.UUID) -> JSONResponse:
    """Return the Sigma.js-compatible attack graph JSON."""
    investigation_id = str(investigation_id)
    record = ensure_investigation_access(request, investigation_id, "viewer")
    audit_log(request, "graph.viewed", investigation_id, {})
    graph_json = record.get("graph_json", "{}")
    return JSONResponse(
        content=json.loads(graph_json) if graph_json else {"nodes": [], "edges": []}
    )


@router.get(
    "/api/v1/investigate/{investigation_id}/evidence",
    response_model=EvidenceListResponse,
)
async def get_evidence(
    request: Request, investigation_id: uuid.UUID
) -> EvidenceListResponse:
    """List stored raw evidence metadata for an investigation."""
    investigation_id = str(investigation_id)
    ensure_investigation_access(request, investigation_id, "viewer")
    rows = list_evidence_files(investigation_id)
    audit_log(request, "evidence.listed", investigation_id, {"count": len(rows)})
    return EvidenceListResponse(
        investigation_id=investigation_id,
        evidence=[EvidenceFileSummary(**row) for row in rows],
        total_count=len(rows),
    )
