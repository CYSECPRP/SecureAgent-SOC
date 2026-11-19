from enum import Enum


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    NEW = "new"
    PROCESSING = "processing"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class TelemetrySource(str, Enum):
    WAZUH = "wazuh"
    SURICATA = "suricata"
    EMAIL = "email"
    LANL = "lanl"
    NETWORK_FLOW = "network_flow"
    MANUAL = "manual"


class IncidentStatus(str, Enum):
    ANALYZING = "analyzing"
    CRITIQUE_REVIEW = "critique_review"
    AWAITING_APPROVAL = "awaiting_approval"
    AUTO_CLOSED = "auto_closed"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONTAINED = "contained"


class AutonomyLevel(str, Enum):
    L0_INFORMATIONAL = "L0"  # Fully auto-logged
    L1_LOW_RISK_AUTO = "L1"  # Auto-close without escalation
    L2_AUGMENTED_TRIAGE = "L2"  # Pre-triaged, sent to analyst
    L3_COLLABORATIVE = "L3"  # Analyst review with recommendations
    L4_MANDATORY_GATE = "L4"  # Explicit analyst sign-off before action


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    PHISHING_AGENT = "phishing_agent"
    TRIAGE_AGENT = "triage_agent"
    MALWARE_AGENT = "malware_agent"
    THREAT_INTEL_AGENT = "threat_intel_agent"
    CRITIQUE_AGENT = "critique_agent"
    WATCHDOG = "watchdog"


class TaintLevel(str, Enum):
    CLEAN = "clean"          # tau = 0.0
    LOW = "low"              # tau <= 0.2
    SUSPICIOUS = "suspicious" # 0.2 < tau <= 0.6
    HOSTILE = "hostile"      # tau > 0.6


class VerdictDecision(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    FALSE_POSITIVE = "false_positive"

