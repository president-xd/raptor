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
    time_range_start: Optional[str] = Field(default=None, max_length=64)
    time_range_end: Optional[str] = Field(default=None, max_length=64)


class InvestigateTextRequest(BaseModel):
    """Request body for text/query based investigations."""
    case_name: str = Field(default="", max_length=200)
    log_content: str = Field(default="", max_length=10_485_760)
    source: str = Field(default="paste", max_length=64)
    elastic_query: Optional[str] = Field(default=None, max_length=1000)
    time_range_start: Optional[str] = Field(default=None, max_length=64)
    time_range_end: Optional[str] = Field(default=None, max_length=64)
    sensitivity: str = Field(default="medium", max_length=32)
    apt_filters: List[str] = Field(default_factory=list, max_length=50)


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


class MitreTechniqueCell(BaseModel):
    """Canonical ATT&CK matrix technique cell, optionally overlaid with investigation evidence."""
    technique_id: str
    name: str = ""
    description: str = ""
    tactics: List[str] = Field(default_factory=list)
    kill_chain_phase: str = ""
    platforms: List[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_technique_id: str = ""
    url: str = ""
    observed: bool = False
    confidence: str = ""
    evidence_summary: str = ""
    event_ids: List[str] = Field(default_factory=list)


class MitreTacticColumn(BaseModel):
    tactic: str
    techniques: List[MitreTechniqueCell] = Field(default_factory=list)


class MitreMatrixResponse(BaseModel):
    source: Dict[str, Any] = Field(default_factory=dict)
    tactic_order: List[str] = Field(default_factory=list)
    matrix: List[MitreTacticColumn] = Field(default_factory=list)
    observed_count: int = 0


class EvidenceFileSummary(BaseModel):
    """Stored raw evidence metadata."""
    id: int = 0
    investigation_id: str
    original_filename: str = ""
    sha256: str = ""
    size_bytes: int = 0
    content_type: str = ""
    source: str = ""
    encrypted: bool = False
    retention_expires_at: str = ""
    created_at: str = ""


class EvidenceListResponse(BaseModel):
    """Response payload for investigation evidence."""
    investigation_id: str
    evidence: List[EvidenceFileSummary] = Field(default_factory=list)
    total_count: int = 0


class AuditEntry(BaseModel):
    """Append-only audit entry."""
    id: int = 0
    timestamp: str = ""
    actor: str = ""
    action: str = ""
    investigation_id: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)
    ip_address: str = ""


class AuditLogResponse(BaseModel):
    """Response payload for audit log queries."""
    entries: List[AuditEntry] = Field(default_factory=list)
    total_count: int = 0


class AuthSessionRequest(BaseModel):
    """Runtime browser authentication request."""
    api_key: str = Field(default="", max_length=256)
    username: str = Field(default="", max_length=128)
    password: str = Field(default="", max_length=256)


class AuthSessionResponse(BaseModel):
    """Response after establishing an HttpOnly browser session."""
    authenticated: bool = True
    actor: str = ""
    roles: List[str] = Field(default_factory=list)
    tenant_id: str = "default"


class PrincipalResponse(BaseModel):
    """Authenticated principal context."""
    actor: str
    roles: List[str] = Field(default_factory=list)
    tenant_id: str = "default"


class CisaKevVulnerability(BaseModel):
    """CISA KEV vulnerability summary."""
    cve_id: str = Field(default="", alias="cveID")
    vendor_project: str = Field(default="", alias="vendorProject")
    product: str = ""
    vulnerability_name: str = Field(default="", alias="vulnerabilityName")
    date_added: str = Field(default="", alias="dateAdded")
    short_description: str = Field(default="", alias="shortDescription")
    required_action: str = Field(default="", alias="requiredAction")
    due_date: str = Field(default="", alias="dueDate")
    known_ransomware_campaign_use: str = Field(default="", alias="knownRansomwareCampaignUse")
    notes: str = ""


class CisaKevResponse(BaseModel):
    """Response payload for the CISA KEV connector."""
    title: str = ""
    catalog_version: str = Field(default="", alias="catalogVersion")
    date_released: str = Field(default="", alias="dateReleased")
    count: int = 0
    source: str = ""
    cached_at: str = ""
    vulnerabilities: List[CisaKevVulnerability] = Field(default_factory=list)


class ElasticPollRequest(BaseModel):
    """Request body for manually polling Elasticsearch."""
    query: str = Field(default="*", min_length=1, max_length=1000)
    time_range_start: Optional[str] = Field(default=None, max_length=64)
    time_range_end: Optional[str] = Field(default=None, max_length=64)
    case_name: str = Field(default="", max_length=200)
    apt_filters: List[str] = Field(default_factory=list, max_length=50)


class ElasticPollResponse(BaseModel):
    """Response payload for Elasticsearch polling."""
    status: str
    message: str = ""
    investigation_id: Optional[str] = None
    event_bytes: int = 0


class ElasticPollStatus(BaseModel):
    """Stored poller status."""
    enabled: bool = False
    query: str = ""
    interval_seconds: int = 0
    window_minutes: int = 0
    last_polled_at: str = ""
    last_status: str = ""
    last_error: str = ""
    investigation_count: int = 0


# ─── Simulation ───────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    """Request body for POST /api/v1/simulate"""
    investigation_id: str = Field(..., max_length=64)
    apt_group: Optional[str] = Field(default=None, max_length=200)


class SimulationResponse(BaseModel):
    """Response for POST /api/v1/simulate"""
    investigation_id: str
    apt_group: str
    predictions: List[SimulationPrediction] = Field(default_factory=list)
    confidence: str = ""


# ─── Query ────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    """Request body for POST /api/v1/query"""
    question: str = Field(..., min_length=1, max_length=2000)
    investigation_id: str = Field(..., max_length=64)


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
    nation_state_source: str = "unknown"
    technique_count: int = 0
    techniques: List[str] = Field(default_factory=list)


class APTProfileListResponse(BaseModel):
    """Response for GET /api/v1/apt/profiles"""
    profiles: List[APTProfileSummary] = Field(default_factory=list)
    total_count: int = 0
