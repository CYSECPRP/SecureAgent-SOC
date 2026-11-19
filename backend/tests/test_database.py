import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.models.database import (
    AlertModel,
    IncidentModel,
    EvidenceNodeModel,
    LedgerEntryModel,
    AgentMetricModel,
    GeneratedRuleModel,
)
from src.models.enums import (
    AlertSeverity,
    AlertStatus,
    TelemetrySource,
    IncidentStatus,
    AutonomyLevel,
    AgentRole,
    VerdictDecision,
)


@pytest.mark.asyncio
async def test_database_crud(db_session: AsyncSession):
    unique_suffix = uuid.uuid4().hex[:8]

    # Create an Incident
    incident = IncidentModel(
        title=f"Suspicious Lateral Movement Attempt {unique_suffix}",
        description="Correlation of failed logins and anomalous SMB connection",
        status=IncidentStatus.ANALYZING,
        verdict=VerdictDecision.SUSPICIOUS,
        confidence=0.88,
        entropy_score=0.12,
        asset_criticality=0.75,
        agent_trust_score=0.85,
        aei_score=0.72,
        autonomy_level=AutonomyLevel.L3_COLLABORATIVE,
    )
    db_session.add(incident)
    await db_session.flush()

    # Create an Alert linked to Incident
    alert = AlertModel(
        incident_id=incident.id,
        source=TelemetrySource.WAZUH,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.PROCESSING,
        taint_score=0.35,
        source_ip="192.168.1.105",
        destination_ip="10.0.0.5",
        user_account="CORP\\svc_backup",
        hostname="DC-PROD-01",
        content_hash=f"hash_{unique_suffix}",
        raw_payload={"event_id": 4625, "reason": "Bad password"},
        normalized_data={"event_type": "auth_failure"},
    )
    db_session.add(alert)

    # Create an Evidence Node
    evidence = EvidenceNodeModel(
        incident_id=incident.id,
        node_type="indicator",
        title="Suspicious IP Source",
        details={"ip": "192.168.1.105", "reputation": "malicious"},
        is_verified=True,
        taint_score=0.20,
    )
    db_session.add(evidence)

    # Create an N4 Ledger Entry
    ledger = LedgerEntryModel(
        sequence_num=1,
        incident_id=incident.id,
        agent_role=AgentRole.TRIAGE_AGENT,
        action_type="claim_lateral_movement",
        action_payload={"claimed_hop": "192.168.1.105 -> 10.0.0.5"},
        previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
        entry_hash=f"ledger_entry_{unique_suffix}",
        signature="ed25519_sig_dummy_stage0",
        key_id="soc-master-key-1",
    )
    db_session.add(ledger)
    await db_session.commit()

    # Query back and verify relations
    result = await db_session.execute(
        select(IncidentModel).where(IncidentModel.id == incident.id)
    )
    fetched_incident = result.scalar_one()

    assert fetched_incident.title == f"Suspicious Lateral Movement Attempt {unique_suffix}"
    assert len(fetched_incident.alerts) == 1
    assert fetched_incident.alerts[0].source == TelemetrySource.WAZUH
    assert len(fetched_incident.evidence_nodes) == 1
    assert fetched_incident.evidence_nodes[0].is_verified is True
    assert len(fetched_incident.ledger_entries) == 1
    assert fetched_incident.ledger_entries[0].sequence_num == 1
