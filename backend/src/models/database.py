import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Enum as SQLEnum,
    JSON,
)
from sqlalchemy.orm import declarative_base, relationship

from src.models.enums import (
    AlertSeverity,
    AlertStatus,
    TelemetrySource,
    IncidentStatus,
    AutonomyLevel,
    AgentRole,
    VerdictDecision,
)

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source = Column(SQLEnum(TelemetrySource), nullable=False, index=True)
    raw_payload = Column(JSON, nullable=False)
    normalized_data = Column(JSON, nullable=False)
    
    severity = Column(SQLEnum(AlertSeverity), default=AlertSeverity.MEDIUM, index=True)
    status = Column(SQLEnum(AlertStatus), default=AlertStatus.NEW, index=True)
    
    # Quantitative Taint Tracking (tau in [0.0, 1.0])
    taint_score = Column(Float, default=1.0, nullable=False)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    user_account = Column(String(128), nullable=True, index=True)
    hostname = Column(String(128), nullable=True, index=True)
    
    # Hash for deduplication
    content_hash = Column(String(64), nullable=False, index=True)
    
    # Association to parent Incident
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    incident = relationship("IncidentModel", back_populates="alerts")

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.ANALYZING, index=True)
    verdict = Column(SQLEnum(VerdictDecision), nullable=True, index=True)
    
    # Mathematical Governance (AEI & Asymmetric Trust)
    confidence = Column(Float, default=0.0)
    entropy_score = Column(Float, default=0.0)      # Shannon entropy H(V)
    asset_criticality = Column(Float, default=0.5)  # C_asset
    agent_trust_score = Column(Float, default=0.8)  # T_a(t)
    aei_score = Column(Float, default=0.0)          # Autonomy Evaluation Index
    autonomy_level = Column(SQLEnum(AutonomyLevel), default=AutonomyLevel.L4_MANDATORY_GATE)
    
    # Verification & Reflection Flags
    critique_rounds = Column(Integer, default=0)    # N2 Critique Agent debate loops
    path_validated = Column(Boolean, default=False)  # N1 SSE NetworkX attack path check
    evidence_grounding_score = Column(Float, default=1.0) # EGS invariant
    ledger_tamper_verified = Column(Boolean, default=True) # N4 signed ledger audit status
    
    # Human in the Loop & Feedback
    analyst_verdict = Column(String(64), nullable=True)
    analyst_override = Column(Boolean, default=False)
    analyst_feedback = Column(Text, nullable=True)
    reviewed_by = Column(String(128), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    alerts = relationship("AlertModel", back_populates="incident", lazy="selectin")
    evidence_nodes = relationship("EvidenceNodeModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    ledger_entries = relationship("LedgerEntryModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    generated_rules = relationship("GeneratedRuleModel", back_populates="incident", lazy="selectin")

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)


class EvidenceNodeModel(Base):
    """Bipartite DAG node: E -> C -> R for EGS computation"""
    __tablename__ = "evidence_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident = relationship("IncidentModel", back_populates="evidence_nodes")
    
    node_type = Column(String(32), nullable=False) # raw_log, indicator, agent_claim, rule_match
    title = Column(String(255), nullable=False)
    details = Column(JSON, nullable=False)
    source_ref = Column(String(128), nullable=True)
    is_verified = Column(Boolean, default=True)
    taint_score = Column(Float, default=0.0)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class LedgerEntryModel(Base):
    """N4: Signed Evidence Ledger (tamper-evident SHA-256 hash chain & Ed25519)"""
    __tablename__ = "ledger_entries"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    sequence_num = Column(Integer, nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident = relationship("IncidentModel", back_populates="ledger_entries")
    
    agent_role = Column(SQLEnum(AgentRole), nullable=False)
    action_type = Column(String(64), nullable=False)
    action_payload = Column(JSON, nullable=False)
    
    # Cryptographic Chain Invariants
    previous_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False, unique=True, index=True)
    signature = Column(Text, nullable=False) # Ed25519 signature
    key_id = Column(String(32), default="soc-master-key-1")

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class AgentMetricModel(Base):
    """Tracks Trust T_a(t), entropy H, and invocation velocity for N3 Watchdog & AEI"""
    __tablename__ = "agent_metrics"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_role = Column(SQLEnum(AgentRole), nullable=False, unique=True, index=True)
    
    total_invocations = Column(Integer, default=0)
    successful_triages = Column(Integer, default=0)
    analyst_overrides = Column(Integer, default=0)
    
    # Current Trust score T_a(t) governed by asymmetric EMA
    trust_score = Column(Float, default=0.80)
    avg_entropy = Column(Float, default=0.15)
    last_active = Column(DateTime(timezone=True), default=utc_now)
    is_frozen = Column(Boolean, default=False) # Watchdog circuit breaker


class GeneratedRuleModel(Base):
    """N5: Auto Rule Generator (Sigma / YARA / Suricata with historical replay)"""
    __tablename__ = "generated_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    incident = relationship("IncidentModel", back_populates="generated_rules")
    
    rule_type = Column(String(16), nullable=False) # sigma | yara | suricata
    rule_title = Column(String(255), nullable=False)
    rule_content = Column(Text, nullable=False)
    
    syntax_valid = Column(Boolean, default=False)
    backtest_total_events = Column(Integer, default=0)
    backtest_false_positives = Column(Integer, default=0)
    backtest_fpr = Column(Float, default=0.0) # Target <= 0.01
    
    status = Column(String(32), default="generated") # generated | backtested | approved | deployed
    approved_by = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

