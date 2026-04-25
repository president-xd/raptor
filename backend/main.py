"""
RAPTOR | FastAPI Application
All 7 API endpoints per spec Section 7.1.
Background processing via asyncio (SQLite for job state per MVP spec).
"""
import os
import sys
import json
import uuid
import asyncio
import sqlite3
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

# Ensure backend dir is on path
sys.path.insert(0, os.path.dirname(__file__))

from config import API_HOST, API_PORT, DB_PATH
from schema import (
    RaptorEvent, Finding, AnalysisResult, AttributionResult,
    SimulationPrediction, AttackGraph
)
from models import (
    InvestigateResponse, InvestigationStatus, InvestigationReport,
    SimulateRequest, SimulationResponse,
    QueryRequest, QueryResponse,
    APTProfileSummary, APTProfileListResponse,
)

# ─── App Setup ────────────────────────────────────────────────────────

app = FastAPI(
    title="RAPTOR API",
    description="Retrieval-Augmented Persistent Threat Orchestration and Reasoning",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── SQLite Job State ────────────────────────────────────────────────

def init_db():
    """Initialize SQLite database for job tracking."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'queued',
            progress INTEGER DEFAULT 0,
            current_phase TEXT DEFAULT '',
            error TEXT,
            findings_json TEXT,
            attack_sequence_json TEXT,
            anomalies_json TEXT,
            attribution_json TEXT,
            graph_json TEXT,
            narrative_report TEXT,
            event_count INTEGER DEFAULT 0,
            technique_count INTEGER DEFAULT 0,
            created_at TEXT,
            completed_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


def db_get(inv_id: str) -> Optional[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def db_update(inv_id: str, **kwargs):
    conn = sqlite3.connect(str(DB_PATH))
    sets = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [inv_id]
    conn.execute(f"UPDATE investigations SET {sets} WHERE id = ?", values)
    conn.commit()
    conn.close()


def db_create(inv_id: str):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO investigations (id, status, created_at) VALUES (?, 'queued', ?)",
        (inv_id, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


# ─── Background Investigation Pipeline ──────────────────────────────

def run_investigation(investigation_id: str, log_content: str):
    """Full investigation pipeline running in background thread (sync, NOT async).
    
    IMPORTANT: This MUST be a sync function (not async) so that FastAPI's
    BackgroundTasks runs it in a thread pool. If this were async, it would
    block the event loop and make ALL endpoints unresponsive during analysis.
    """
    try:
        db_update(investigation_id, status="processing", progress=5,
                  current_phase="Parsing logs")

        # Phase 1: Parse and normalize logs
        from ingestion.normalizer import LogNormalizer
        normalizer = LogNormalizer()
        events = normalizer.normalize_content(log_content)
        db_update(investigation_id, progress=15,
                  current_phase="Log parsing complete", event_count=len(events))
        logger.info(f"[{investigation_id}] Parsed {len(events)} events")

        # Phase 2: RAG Analysis
        db_update(investigation_id, progress=25, current_phase="RAG analysis (LLM reasoning)")
        from rag.pipeline import analyze_events_batch
        analysis = analyze_events_batch(events)
        logger.info(f"[{investigation_id}] Analysis: {len(analysis.findings)} findings")

        # Phase 3: STIX Validation (non-negotiable)
        db_update(investigation_id, progress=45, current_phase="Validating technique IDs (STIX)")
        from attribution.stix_validator import validate_analysis_result
        analysis = validate_analysis_result(analysis)
        logger.info(f"[{investigation_id}] After validation: {len(analysis.findings)} findings")

        # Phase 4: Build Attack Graph
        db_update(investigation_id, progress=55, current_phase="Building attack graph")
        graph_json = "{}"
        try:
            from graph.neo4j_client import Neo4jClient
            from graph.graph_builder import GraphBuilder
            neo4j = Neo4jClient()
            if neo4j.is_connected():
                neo4j.setup_schema()
                builder = GraphBuilder(neo4j)
                attack_graph = builder.build_graph(investigation_id, events, analysis)
                graph_json = attack_graph.model_dump_json()
                neo4j.close()
            else:
                # Build graph without Neo4j (in-memory only)
                builder = GraphBuilder.__new__(GraphBuilder)
                builder.neo4j = type('Mock', (), {'run_write': lambda *a, **kw: None, 'run_query': lambda *a, **kw: []})()
                builder.investigation_id = investigation_id
                attack_graph = builder._build_sigma_graph(
                    builder._extract_hosts(events),
                    builder._extract_users(events),
                    builder._extract_techniques(analysis),
                    events, analysis
                )
                graph_json = attack_graph.model_dump_json()
        except Exception as e:
            logger.warning(f"Graph building error (non-fatal): {e}")

        # Phase 5: APT Attribution
        db_update(investigation_id, progress=70, current_phase="APT attribution scoring")
        from attribution.apt_profiles import load_apt_profiles
        from attribution.confidence import calculate_confidence

        observed_ttps = set()
        for f in analysis.findings:
            if f.technique_id:
                observed_ttps.add(f.technique_id)
        for tid in analysis.attack_sequence:
            observed_ttps.add(tid)

        apt_profiles = load_apt_profiles()

        # Calculate campaign duration from events
        campaign_hours = 0
        if events:
            timestamps = sorted([e.timestamp for e in events if e.timestamp])
            if len(timestamps) >= 2:
                try:
                    from datetime import datetime as dt
                    t1 = dt.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                    t2 = dt.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                    campaign_hours = (t2 - t1).total_seconds() / 3600
                except Exception:
                    pass

        attribution_results = calculate_confidence(
            observed_ttps=observed_ttps,
            apt_profiles=apt_profiles,
            campaign_duration_hours=campaign_hours,
        )
        attribution_json = json.dumps([a.model_dump() for a in attribution_results])
        logger.info(f"[{investigation_id}] Attribution: {attribution_results[0].apt_name if attribution_results else 'None'}")

        # Phase 6: Generate Report
        db_update(investigation_id, progress=85, current_phase="Generating analyst report")
        from report.generator import generate_report

        graph_summary = {
            "hosts_compromised": sum(1 for e in events if e.event_type == "lateral"),
            "total_events": len(events),
            "unique_hosts": len(set(e.source_host for e in events if e.source_host)),
            "campaign_duration_hours": campaign_hours,
        }

        narrative = generate_report(analysis, attribution_results, graph_summary, investigation_id)

        # Save results
        findings_json = json.dumps([f.model_dump() for f in analysis.findings])
        seq_json = json.dumps(analysis.attack_sequence)
        anomalies_json = json.dumps(analysis.anomalies)

        db_update(
            investigation_id,
            status="complete", progress=100,
            current_phase="Investigation complete",
            findings_json=findings_json,
            attack_sequence_json=seq_json,
            anomalies_json=anomalies_json,
            attribution_json=attribution_json,
            graph_json=graph_json,
            narrative_report=narrative,
            technique_count=len(analysis.findings),
            completed_at=datetime.utcnow().isoformat(),
        )
        logger.info(f"[{investigation_id}] Investigation complete!")

    except Exception as e:
        logger.error(f"[{investigation_id}] Investigation failed: {e}\n{traceback.format_exc()}")
        db_update(investigation_id, status="failed", error=str(e),
                  current_phase=f"Failed: {str(e)[:200]}")


# ─── API Endpoints ───────────────────────────────────────────────────

@app.post("/api/v1/investigate", response_model=InvestigateResponse)
async def investigate(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Upload a log file and start an investigation.
    POST /api/v1/investigate
    """
    investigation_id = str(uuid.uuid4())
    content = await file.read()
    log_content = content.decode('utf-8', errors='replace')

    db_create(investigation_id)
    background_tasks.add_task(run_investigation, investigation_id, log_content)

    logger.info(f"Investigation {investigation_id} started ({len(log_content)} bytes)")
    return InvestigateResponse(
        investigation_id=investigation_id,
        status="queued",
        message=f"Investigation started. {len(log_content)} bytes of logs received.",
    )


@app.get("/api/v1/investigate/{investigation_id}/status", response_model=InvestigationStatus)
async def get_status(investigation_id: str):
    """
    Check investigation status and progress.
    GET /api/v1/investigate/{id}/status
    """
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return InvestigationStatus(
        investigation_id=investigation_id,
        status=record["status"],
        progress=record["progress"],
        current_phase=record["current_phase"] or "",
        error=record.get("error"),
    )


@app.get("/api/v1/investigate/{investigation_id}/report", response_model=InvestigationReport)
async def get_report(investigation_id: str):
    """
    Get full investigation report.
    GET /api/v1/investigate/{id}/report
    """
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    findings = []
    if record.get("findings_json"):
        for f in json.loads(record["findings_json"]):
            findings.append(Finding(**f))

    attribution = []
    if record.get("attribution_json"):
        for a in json.loads(record["attribution_json"]):
            attribution.append(AttributionResult(**a))

    attack_seq = json.loads(record["attack_sequence_json"]) if record.get("attack_sequence_json") else []
    anomalies = json.loads(record["anomalies_json"]) if record.get("anomalies_json") else []

    return InvestigationReport(
        investigation_id=investigation_id,
        status=record["status"],
        findings=findings,
        attack_sequence=attack_seq,
        anomalies=anomalies,
        attribution=attribution,
        narrative_report=record.get("narrative_report") or "",
        event_count=record.get("event_count") or 0,
        technique_count=record.get("technique_count") or 0,
        timestamp=record.get("created_at") or "",
    )


@app.get("/api/v1/investigate/{investigation_id}/graph")
async def get_graph(investigation_id: str):
    """
    Get Sigma.js compatible attack graph JSON.
    GET /api/v1/investigate/{id}/graph
    """
    record = db_get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    graph_json = record.get("graph_json", "{}")
    if graph_json:
        return JSONResponse(content=json.loads(graph_json))
    return JSONResponse(content={"nodes": [], "edges": []})


@app.post("/api/v1/simulate", response_model=SimulationResponse)
async def simulate(request: SimulateRequest):
    """
    Simulate next attack steps for attributed APT.
    POST /api/v1/simulate
    """
    record = db_get(request.investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if record["status"] != "complete":
        raise HTTPException(status_code=400, detail="Investigation not complete yet")

    # Get attribution
    attribution_data = json.loads(record.get("attribution_json") or "[]")
    if not attribution_data:
        raise HTTPException(status_code=400, detail="No attribution data available")

    # Use specified APT group or top attribution
    target_apt = request.apt_group
    attribution = None
    for a in attribution_data:
        attr = AttributionResult(**a)
        if target_apt and attr.apt_name == target_apt:
            attribution = attr
            break
        elif not target_apt:
            attribution = attr
            break

    if not attribution:
        attribution = AttributionResult(**attribution_data[0])

    # Get findings for observed TTPs
    findings_data = json.loads(record.get("findings_json") or "[]")
    observed_ttps = [f.get("technique_id", "") for f in findings_data if f.get("technique_id")]

    compromised_hosts = []
    try:
        graph_data = json.loads(record.get("graph_json") or "{}")
        for node in graph_data.get("nodes", []):
            if node.get("node_type") == "host" and node.get("metadata", {}).get("compromised"):
                compromised_hosts.append(node.get("label") or node.get("id"))
    except Exception:
        compromised_hosts = []

    if not compromised_hosts:
        compromised_hosts = ["unknown compromised hosts"]

    # Run simulation
    from simulation.predictor import predict_next_steps
    predictions = predict_next_steps(
        attribution=attribution,
        compromised_hosts=compromised_hosts,
        privilege_level="domain user / admin",
        observed_ttps=observed_ttps,
    )

    return SimulationResponse(
        investigation_id=request.investigation_id,
        apt_group=attribution.apt_name,
        predictions=predictions,
        confidence=attribution.confidence_label,
    )


@app.get("/api/v1/apt/profiles", response_model=APTProfileListResponse)
async def get_apt_profiles():
    """
    List all APT group profiles with TTP counts.
    GET /api/v1/apt/profiles
    """
    from attribution.apt_profiles import load_apt_profiles, get_profile_summaries
    profiles = load_apt_profiles()
    summaries = get_profile_summaries(profiles)

    return APTProfileListResponse(
        profiles=[APTProfileSummary(**s) for s in summaries],
        total_count=len(summaries),
    )


@app.post("/api/v1/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    """
    Natural language query against investigation.
    POST /api/v1/query
    """
    record = db_get(request.investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    from nlq.query_engine import QueryEngine
    try:
        from graph.neo4j_client import Neo4jClient
        neo4j = Neo4jClient()
    except Exception:
        neo4j = None

    engine = QueryEngine(neo4j_client=neo4j)
    result = engine.answer_question(request.question, request.investigation_id)
    engine.close()

    return QueryResponse(
        answer=result.get("answer", ""),
        sources=result.get("sources", []),
        confidence=result.get("confidence", ""),
        query_type=result.get("query_type", ""),
    )


# ─── Health Check ────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "RAPTOR API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ─── Run ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting RAPTOR API on {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=int(API_PORT))
