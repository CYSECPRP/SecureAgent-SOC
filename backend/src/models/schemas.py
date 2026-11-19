from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from src.models.enums import (
    AlertSeverity,
    AlertStatus,
    TelemetrySource,
    IncidentStatus,
    AutonomyLevel,
    AgentRole,
    VerdictDecision,
)


# ==============================================================================
# Health Check Schemas
# ==============================================================================
class ServiceHealth(BaseModel):
    status: str
    latency_ms: Optional[float] = None
    details: Optional[str] = None


class HealthCheckResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    environment: str
    services: Dict[str, ServiceHealth]


# ==============================================================================
# Alert Schemas
# ==============================================================================
class AlertCreate(BaseModel):
    source: TelemetrySource
    raw_payload: Dict[str, Any]
    normalized_data: Optional[Dict[str, Any]] = None
    severity: Optional[AlertSeverity] = AlertSeverity.MEDIUM
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_account: Optional[str] = None
    hostname: Optional[str] = None


class AlertIngestResponse(BaseModel):
    id: str
    status: str
    taint_score: float
    is_injection_detected: bool
    is_duplicate: bool
    content_hash: str
    queue_name: Optional[str] = None


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: TelemetrySource
    severity: AlertSeverity
    status: AlertStatus
    taint_score: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_account: Optional[str] = None
    hostname: Optional[str] = None
    content_hash: str
    incident_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AlertIngestBatch(BaseModel):
    alerts: List[AlertCreate]


# ==============================================================================
# Evidence DAG Schemas
# ==============================================================================
class EvidenceNodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    node_type: str
    title: str
    details: Dict[str, Any]
    source_ref: Optional[str] = None
    is_verified: bool
    taint_score: float
    created_at: datetime


class EvidenceDAGRead(BaseModel):
    incident_id: str
    nodes: List[EvidenceNodeRead]
    evidence_grounding_score: float
    is_grounded: bool


# ==============================================================================
# N4: Signed Evidence Ledger Schemas
# ==============================================================================
class LedgerEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sequence_num: int
    incident_id: str
    agent_role: AgentRole
    action_type: str
    action_payload: Dict[str, Any]
    previous_hash: str
    entry_hash: str
    signature: str
    key_id: str
    created_at: datetime


class LedgerAuditResult(BaseModel):
    incident_id: str
    total_entries: int
    is_chain_valid: bool
    is_signature_valid: bool
    verified_at: datetime
    broken_sequence_num: Optional[int] = None


# ==============================================================================
# Incident Schemas
# ==============================================================================
class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    status: IncidentStatus
    verdict: Optional[VerdictDecision] = None
    confidence: float
    entropy_score: float
    asset_criticality: float
    agent_trust_score: float
    aei_score: float
    autonomy_level: AutonomyLevel
    critique_rounds: int
    path_validated: bool
    evidence_grounding_score: float
    ledger_tamper_verified: bool
    analyst_override: bool
    analyst_verdict: Optional[str] = None
    analyst_feedback: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    alerts: List[AlertRead] = []


class AnalystFeedbackCreate(BaseModel):
    verdict: VerdictDecision
    feedback: Optional[str] = None
    approved_action: Optional[str] = None
    analyst_name: str = "SOC Lead Analyst"


# ==============================================================================
# Governance & Trust Schemas
# ==============================================================================
class AgentTrustRead(BaseModel):
    agent_role: AgentRole
    trust_score: float
    total_invocations: int
    successful_triages: int
    analyst_overrides: int
    avg_entropy: float
    is_frozen: bool


# ==============================================================================
# N5: Generated Rule Schemas
# ==============================================================================
class GeneratedRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: Optional[str] = None
    rule_type: str
    rule_title: str
    rule_content: str
    syntax_valid: bool
    backtest_total_events: int
    backtest_false_positives: int
    backtest_fpr: float
    status: str
    approved_by: Optional[str] = None
    created_at: datetime


class RuleDeployRequest(BaseModel):
    rule_id: str
    target_engine: str  # wazuh | suricata
    analyst_name: str
