"""
RAPTOR Event Schema — Unified format for all ingested log events.
Matches the schema defined in WHAT_TO_CREATE.md Section 2.4.
"""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List
from datetime import datetime, timezone
import uuid


class RaptorEvent(BaseModel):
    """Unified event schema for all log sources."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "event_id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2026-04-23T10:30:00Z",
                "source_host": "WORKSTATION-01",
                "source_ip": "192.168.1.100",
                "dest_host": "DC-01",
                "dest_ip": "192.168.1.10",
                "event_type": "lateral",
                "raw": "SMB session established from WORKSTATION-01 to DC-01",
                "sigma_matches": ["T1021.002"],
                "ioc_score": 0.85,
                "enriched": True,
            }
        }
    )

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_host: str = ""
    source_ip: str = ""
    dest_host: Optional[str] = None
    dest_ip: Optional[str] = None
    event_type: str = "process"  # process | network | file | registry | auth | lateral
    raw: str = ""
    sigma_matches: List[str] = Field(default_factory=list)
    ioc_score: float = 0.0
    enriched: bool = False

class Finding(BaseModel):
    """A single forensic finding from LLM analysis."""
    event_ids: List[str] = Field(default_factory=list)
    technique_id: str = ""
    technique_name: str = ""
    tactics: List[str] = Field(default_factory=list)
    kill_chain_phase: str = ""
    confidence: str = "low"  # high | medium | low
    evidence_summary: str = ""
    apt_indicators: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Structured output from the RAG pipeline."""
    findings: List[Finding] = Field(default_factory=list)
    attack_sequence: List[str] = Field(default_factory=list)
    anomalies: List[str] = Field(default_factory=list)


class AttributionResult(BaseModel):
    """APT attribution result with confidence scoring."""
    apt_name: str = ""
    aliases: List[str] = Field(default_factory=list)
    jaccard_score: float = 0.0
    confidence_score: float = 0.0
    confidence_label: str = "UNKNOWN"  # HIGH | MEDIUM | LOW | UNKNOWN
    overlapping_ttps: List[str] = Field(default_factory=list)
    ttp_count: int = 0
    penalties_applied: List[str] = Field(default_factory=list)
    bonuses_applied: List[str] = Field(default_factory=list)


class SimulationPrediction(BaseModel):
    """A single predicted next technique."""
    technique_id: str = ""
    technique_name: str = ""
    rationale: str = ""
    likely_tools: List[str] = Field(default_factory=list)
    detection_guidance: str = ""
    urgency: str = "medium"  # critical | high | medium


class GraphNode(BaseModel):
    """Node in the attack graph for Sigma.js rendering."""
    id: str
    label: str
    node_type: str  # host | user | process | file | network | technique | aptgroup
    color: str = "#6b7280"  # gray default
    size: int = 10
    x: float = 0.0
    y: float = 0.0
    metadata: dict = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Edge in the attack graph for Sigma.js rendering."""
    id: str
    source: str
    target: str
    label: str = ""
    edge_type: str = ""
    color: str = "#6b7280"
    size: int = 1
    metadata: dict = Field(default_factory=dict)


class AttackGraph(BaseModel):
    """Full graph structure for Sigma.js."""
    investigation_id: Optional[str] = None
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
