"""Initial schema: alerts, incidents, evidence nodes, ledger entries, agent metrics and generated rules

Revision ID: 0001
Revises:
Create Date: 2026-11-20

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ENUM_TYPES = (
    "agentrole",
    "alertseverity",
    "alertstatus",
    "autonomylevel",
    "incidentstatus",
    "telemetrysource",
    "verdictdecision",
)


def upgrade() -> None:
    op.create_table('agent_metrics',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('agent_role', sa.Enum('ORCHESTRATOR', 'PHISHING_AGENT', 'TRIAGE_AGENT', 'MALWARE_AGENT', 'THREAT_INTEL_AGENT', 'CRITIQUE_AGENT', 'WATCHDOG', name='agentrole'), nullable=False),
    sa.Column('total_invocations', sa.Integer(), nullable=True),
    sa.Column('successful_triages', sa.Integer(), nullable=True),
    sa.Column('analyst_overrides', sa.Integer(), nullable=True),
    sa.Column('trust_score', sa.Float(), nullable=True),
    sa.Column('avg_entropy', sa.Float(), nullable=True),
    sa.Column('last_active', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_frozen', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agent_metrics_agent_role'), 'agent_metrics', ['agent_role'], unique=True)
    op.create_table('incidents',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('ANALYZING', 'CRITIQUE_REVIEW', 'AWAITING_APPROVAL', 'AUTO_CLOSED', 'APPROVED', 'REJECTED', 'CONTAINED', name='incidentstatus'), nullable=True),
    sa.Column('verdict', sa.Enum('BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'FALSE_POSITIVE', name='verdictdecision'), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('entropy_score', sa.Float(), nullable=True),
    sa.Column('asset_criticality', sa.Float(), nullable=True),
    sa.Column('agent_trust_score', sa.Float(), nullable=True),
    sa.Column('aei_score', sa.Float(), nullable=True),
    sa.Column('autonomy_level', sa.Enum('L0_INFORMATIONAL', 'L1_LOW_RISK_AUTO', 'L2_AUGMENTED_TRIAGE', 'L3_COLLABORATIVE', 'L4_MANDATORY_GATE', name='autonomylevel'), nullable=True),
    sa.Column('critique_rounds', sa.Integer(), nullable=True),
    sa.Column('path_validated', sa.Boolean(), nullable=True),
    sa.Column('evidence_grounding_score', sa.Float(), nullable=True),
    sa.Column('ledger_tamper_verified', sa.Boolean(), nullable=True),
    sa.Column('analyst_verdict', sa.String(length=64), nullable=True),
    sa.Column('analyst_override', sa.Boolean(), nullable=True),
    sa.Column('analyst_feedback', sa.Text(), nullable=True),
    sa.Column('reviewed_by', sa.String(length=128), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_verdict'), 'incidents', ['verdict'], unique=False)
    op.create_table('alerts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('source', sa.Enum('WAZUH', 'SURICATA', 'EMAIL', 'LANL', 'NETWORK_FLOW', 'MANUAL', name='telemetrysource'), nullable=False),
    sa.Column('raw_payload', sa.JSON(), nullable=False),
    sa.Column('normalized_data', sa.JSON(), nullable=False),
    sa.Column('severity', sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='alertseverity'), nullable=True),
    sa.Column('status', sa.Enum('NEW', 'PROCESSING', 'TRIAGED', 'RESOLVED', 'CLOSED', 'ESCALATED', name='alertstatus'), nullable=True),
    sa.Column('taint_score', sa.Float(), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=True),
    sa.Column('destination_ip', sa.String(length=45), nullable=True),
    sa.Column('user_account', sa.String(length=128), nullable=True),
    sa.Column('hostname', sa.String(length=128), nullable=True),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_content_hash'), 'alerts', ['content_hash'], unique=False)
    op.create_index(op.f('ix_alerts_destination_ip'), 'alerts', ['destination_ip'], unique=False)
    op.create_index(op.f('ix_alerts_hostname'), 'alerts', ['hostname'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_source'), 'alerts', ['source'], unique=False)
    op.create_index(op.f('ix_alerts_source_ip'), 'alerts', ['source_ip'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('ix_alerts_user_account'), 'alerts', ['user_account'], unique=False)
    op.create_table('evidence_nodes',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=False),
    sa.Column('node_type', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('details', sa.JSON(), nullable=False),
    sa.Column('source_ref', sa.String(length=128), nullable=True),
    sa.Column('is_verified', sa.Boolean(), nullable=True),
    sa.Column('taint_score', sa.Float(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_nodes_incident_id'), 'evidence_nodes', ['incident_id'], unique=False)
    op.create_table('generated_rules',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=True),
    sa.Column('rule_type', sa.String(length=16), nullable=False),
    sa.Column('rule_title', sa.String(length=255), nullable=False),
    sa.Column('rule_content', sa.Text(), nullable=False),
    sa.Column('syntax_valid', sa.Boolean(), nullable=True),
    sa.Column('backtest_total_events', sa.Integer(), nullable=True),
    sa.Column('backtest_false_positives', sa.Integer(), nullable=True),
    sa.Column('backtest_fpr', sa.Float(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=True),
    sa.Column('approved_by', sa.String(length=128), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ledger_entries',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('sequence_num', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=False),
    sa.Column('agent_role', sa.Enum('ORCHESTRATOR', 'PHISHING_AGENT', 'TRIAGE_AGENT', 'MALWARE_AGENT', 'THREAT_INTEL_AGENT', 'CRITIQUE_AGENT', 'WATCHDOG', name='agentrole'), nullable=False),
    sa.Column('action_type', sa.String(length=64), nullable=False),
    sa.Column('action_payload', sa.JSON(), nullable=False),
    sa.Column('previous_hash', sa.String(length=64), nullable=False),
    sa.Column('entry_hash', sa.String(length=64), nullable=False),
    sa.Column('signature', sa.Text(), nullable=False),
    sa.Column('key_id', sa.String(length=32), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ledger_entries_entry_hash'), 'ledger_entries', ['entry_hash'], unique=True)
    op.create_index(op.f('ix_ledger_entries_incident_id'), 'ledger_entries', ['incident_id'], unique=False)
    op.create_index(op.f('ix_ledger_entries_sequence_num'), 'ledger_entries', ['sequence_num'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_ledger_entries_sequence_num'), table_name='ledger_entries')
    op.drop_index(op.f('ix_ledger_entries_incident_id'), table_name='ledger_entries')
    op.drop_index(op.f('ix_ledger_entries_entry_hash'), table_name='ledger_entries')
    op.drop_table('ledger_entries')
    op.drop_table('generated_rules')
    op.drop_index(op.f('ix_evidence_nodes_incident_id'), table_name='evidence_nodes')
    op.drop_table('evidence_nodes')
    op.drop_index(op.f('ix_alerts_user_account'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_status'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source_ip'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_hostname'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_destination_ip'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_content_hash'), table_name='alerts')
    op.drop_table('alerts')
    op.drop_index(op.f('ix_incidents_verdict'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_table('incidents')
    op.drop_index(op.f('ix_agent_metrics_agent_role'), table_name='agent_metrics')
    op.drop_table('agent_metrics')
    # Dropping a table does not drop its PostgreSQL enum types.
    for enum_type in ENUM_TYPES:
        op.execute(f"DROP TYPE IF EXISTS {enum_type}")
