"""
RAPTOR | API Request/Response Models
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from schema import (
    Finding, AnalysisResult, AttributionResult,
    SimulationPrediction, AttackGraph
)


# ─── Investigation ────────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    """Request body for POST /api/v1/investigate"""
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None


class InvestigateTextRequest(BaseModel):
    """Request body for text/query based investigations."""
    case_name: str = ""
    log_content: str = ""
    source: str = "paste"
    elastic_query: Optional[str] = None
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    sensitivity: str = "medium"
    apt_filters: List[str] = Field(default_factory=list)


class InvestigateResponse(BaseModel):
    """Response for POST /api/v1/investigate"""
    investigation_id: str
    status: str = "queued"
    message: str = "Investigation started"


class InvestigationStatus(BaseModel):
    """Response for GET /api/v1/investigate/{id}/status"""
    investigation_id: str
    name: str = ""
    status: str  # queued | processing | complete | failed
    progress: int = 0  # 0-100
    current_phase: str = ""
    error: Optional[str] = None


class InvestigationListItem(BaseModel):
    """Summary row for investigation listing endpoint."""
    investigation_id: str
    name: str = ""
    source: str = ""
    status: str
    progress: int
    current_phase: str = ""
    event_count: int = 0
    technique_count: int = 0
    host_count: int = 0
    input_bytes: int = 0
    top_candidate: str = ""
    confidence_score: float = 0.0
    confidence_label: str = ""
    created_at: str = ""
    completed_at: Optional[str] = None
    error: Optional[str] = None


class InvestigationReport(BaseModel):
    """Response for GET /api/v1/investigate/{id}/report"""
    investigation_id: str
    name: str = ""
    status: str
    findings: List[Finding] = Field(default_factory=list)
    attack_sequence: List[str] = Field(default_factory=list)
    anomalies: List[str] = Field(default_factory=list)
    attribution: List[AttributionResult] = Field(default_factory=list)
    narrative_report: str = ""
    event_count: int = 0
    technique_count: int = 0
    timestamp: str = ""


class InvestigationListResponse(BaseModel):
    """Response payload for investigation list endpoint."""
    investigations: List[InvestigationListItem] = Field(default_factory=list)
    total_count: int = 0


# ─── Simulation ───────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    """Request body for POST /api/v1/simulate"""
    investigation_id: str
    apt_group: Optional[str] = None


class SimulationResponse(BaseModel):
    """Response for POST /api/v1/simulate"""
    investigation_id: str
    apt_group: str
    predictions: List[SimulationPrediction] = Field(default_factory=list)
    confidence: str = ""


# ─── Query ────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    """Request body for POST /api/v1/query"""
    question: str
    investigation_id: str


class QueryResponse(BaseModel):
    """Response for POST /api/v1/query"""
    answer: str
    sources: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: str = ""
    query_type: str = ""  # graph | rag | simulation


# ─── APT Profiles ────────────────────────────────────────────────────

class APTProfileSummary(BaseModel):
    """Summary of an APT group profile."""
    name: str
    aliases: List[str] = Field(default_factory=list)
    nation_state: str = ""
    technique_count: int = 0
    techniques: List[str] = Field(default_factory=list)


class APTProfileListResponse(BaseModel):
    """Response for GET /api/v1/apt/profiles"""
    profiles: List[APTProfileSummary] = Field(default_factory=list)
    total_count: int = 0
