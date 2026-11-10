"""Initial tenant-scoped SOC schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-21
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('tenants',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('deployment_mode', sa.String(length=20), nullable=False),
    sa.Column('automation_level', sa.String(length=30), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('assets',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('kind', sa.String(length=30), nullable=False),
    sa.Column('value', sa.String(length=256), nullable=False),
    sa.Column('owner', sa.String(length=256), nullable=False),
    sa.Column('criticality', sa.String(length=20), nullable=False),
    sa.Column('attributes', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'kind', 'value')
    )
    op.create_index(op.f('ix_assets_tenant_id'), 'assets', ['tenant_id'], unique=False)
    op.create_table('audit',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('actor', sa.String(length=100), nullable=False),
    sa.Column('operation', sa.String(length=100), nullable=False),
    sa.Column('subject_type', sa.String(length=50), nullable=False),
    sa.Column('subject_id', sa.String(length=256), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_tenant_id'), 'audit', ['tenant_id'], unique=False)
    op.create_table('checkpoints',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('source', sa.String(length=60), nullable=False),
    sa.Column('cursor_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'source')
    )
    op.create_index(op.f('ix_checkpoints_tenant_id'), 'checkpoints', ['tenant_id'], unique=False)
    op.create_table('exceptions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('rule', sa.String(length=100), nullable=False),
    sa.Column('entity', sa.String(length=256), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
    sa.Column('approved_by', sa.String(length=100), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_exceptions_tenant_id'), 'exceptions', ['tenant_id'], unique=False)
    op.create_table('integration_states',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=60), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_received_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('detail', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'name')
    )
    op.create_index(op.f('ix_integration_states_tenant_id'), 'integration_states', ['tenant_id'], unique=False)
    op.create_table('investigations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('correlation_key', sa.String(length=256), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('verdict', sa.String(length=30), nullable=True),
    sa.Column('priority', sa.String(length=20), nullable=False),
    sa.Column('playbook_key', sa.String(length=100), nullable=False),
    sa.Column('playbook_version', sa.String(length=30), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('due_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('rationale', sa.Text(), nullable=False),
    sa.Column('missing_data', sa.JSON(), nullable=False),
    sa.Column('recommended_actions', sa.JSON(), nullable=False),
    sa.Column('analyzer', sa.String(length=50), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'correlation_key')
    )
    op.create_index(op.f('ix_investigations_correlation_key'), 'investigations', ['correlation_key'], unique=False)
    op.create_index(op.f('ix_investigations_tenant_id'), 'investigations', ['tenant_id'], unique=False)
    op.create_table('maintenance',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('entity', sa.String(length=256), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
    sa.Column('approved_by', sa.String(length=100), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_maintenance_tenant_id'), 'maintenance', ['tenant_id'], unique=False)
    op.create_table('misp_notices',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('external_id', sa.String(length=256), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('received_status', sa.String(length=30), nullable=False),
    sa.Column('l1_status', sa.String(length=30), nullable=False),
    sa.Column('l2_status', sa.String(length=30), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'external_id')
    )
    op.create_index(op.f('ix_misp_notices_tenant_id'), 'misp_notices', ['tenant_id'], unique=False)
    op.create_table('shifts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('starts_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ends_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('timezone', sa.String(length=80), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('outgoing_name', sa.String(length=100), nullable=True),
    sa.Column('incoming_name', sa.String(length=100), nullable=True),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_shifts_tenant_id'), 'shifts', ['tenant_id'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('password_hash', sa.String(length=256), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_index(op.f('ix_users_tenant_id'), 'users', ['tenant_id'], unique=False)
    op.create_table('actions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('kind', sa.String(length=60), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('idempotency_key', sa.String(length=256), nullable=False),
    sa.Column('target', sa.String(length=256), nullable=False),
    sa.Column('external_id', sa.String(length=256), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('attempted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'idempotency_key')
    )
    op.create_index(op.f('ix_actions_investigation_id'), 'actions', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_actions_tenant_id'), 'actions', ['tenant_id'], unique=False)
    op.create_table('alerts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=True),
    sa.Column('source', sa.String(length=50), nullable=False),
    sa.Column('source_event_id', sa.String(length=256), nullable=False),
    sa.Column('rule', sa.String(length=100), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('event_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('original_timezone', sa.String(length=80), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_dispatched_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('raw', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'source', 'source_event_id')
    )
    op.create_index('ix_alert_tenant_received', 'alerts', ['tenant_id', 'received_at'], unique=False)
    op.create_index(op.f('ix_alerts_investigation_id'), 'alerts', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_alerts_tenant_id'), 'alerts', ['tenant_id'], unique=False)
    op.create_table('cases',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('external_id', sa.String(length=256), nullable=True),
    sa.Column('status', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'investigation_id')
    )
    op.create_index(op.f('ix_cases_investigation_id'), 'cases', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_cases_tenant_id'), 'cases', ['tenant_id'], unique=False)
    op.create_table('decisions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('verdict', sa.String(length=30), nullable=False),
    sa.Column('priority', sa.String(length=20), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('rationale', sa.Text(), nullable=False),
    sa.Column('evidence_ids', sa.JSON(), nullable=False),
    sa.Column('missing_data', sa.JSON(), nullable=False),
    sa.Column('recommended_actions', sa.JSON(), nullable=False),
    sa.Column('actor', sa.String(length=100), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_decisions_investigation_id'), 'decisions', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_decisions_tenant_id'), 'decisions', ['tenant_id'], unique=False)
    op.create_table('evidence',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('kind', sa.String(length=80), nullable=False),
    sa.Column('source', sa.String(length=80), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.Column('event_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_investigation_id'), 'evidence', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_evidence_tenant_id'), 'evidence', ['tenant_id'], unique=False)
    op.create_table('playbook_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('key', sa.String(length=100), nullable=False),
    sa.Column('version', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('steps', sa.JSON(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_playbook_runs_investigation_id'), 'playbook_runs', ['investigation_id'], unique=False)
    op.create_index(op.f('ix_playbook_runs_tenant_id'), 'playbook_runs', ['tenant_id'], unique=False)
    op.create_table('reports',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('shift_id', sa.String(length=36), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('counters', sa.JSON(), nullable=False),
    sa.Column('approved_by', sa.String(length=100), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['shift_id'], ['shifts.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'shift_id', 'version')
    )
    op.create_index(op.f('ix_reports_shift_id'), 'reports', ['shift_id'], unique=False)
    op.create_index(op.f('ix_reports_tenant_id'), 'reports', ['tenant_id'], unique=False)
    op.create_table('dead_letters',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('alert_id', sa.String(length=36), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dead_letters_alert_id'), 'dead_letters', ['alert_id'], unique=False)
    op.create_index(op.f('ix_dead_letters_tenant_id'), 'dead_letters', ['tenant_id'], unique=False)
    op.create_table('embedded_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('alert_id', sa.String(length=36), nullable=False),
    sa.Column('source_event_id', sa.String(length=256), nullable=False),
    sa.Column('event_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('original_timezone', sa.String(length=80), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_embedded_events_alert_id'), 'embedded_events', ['alert_id'], unique=False)
    op.create_index(op.f('ix_embedded_events_tenant_id'), 'embedded_events', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_embedded_events_tenant_id'), table_name='embedded_events')
    op.drop_index(op.f('ix_embedded_events_alert_id'), table_name='embedded_events')
    op.drop_table('embedded_events')
    op.drop_index(op.f('ix_dead_letters_tenant_id'), table_name='dead_letters')
    op.drop_index(op.f('ix_dead_letters_alert_id'), table_name='dead_letters')
    op.drop_table('dead_letters')
    op.drop_index(op.f('ix_reports_tenant_id'), table_name='reports')
    op.drop_index(op.f('ix_reports_shift_id'), table_name='reports')
    op.drop_table('reports')
    op.drop_index(op.f('ix_playbook_runs_tenant_id'), table_name='playbook_runs')
    op.drop_index(op.f('ix_playbook_runs_investigation_id'), table_name='playbook_runs')
    op.drop_table('playbook_runs')
    op.drop_index(op.f('ix_evidence_tenant_id'), table_name='evidence')
    op.drop_index(op.f('ix_evidence_investigation_id'), table_name='evidence')
    op.drop_table('evidence')
    op.drop_index(op.f('ix_decisions_tenant_id'), table_name='decisions')
    op.drop_index(op.f('ix_decisions_investigation_id'), table_name='decisions')
    op.drop_table('decisions')
    op.drop_index(op.f('ix_cases_tenant_id'), table_name='cases')
    op.drop_index(op.f('ix_cases_investigation_id'), table_name='cases')
    op.drop_table('cases')
    op.drop_index(op.f('ix_alerts_tenant_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_investigation_id'), table_name='alerts')
    op.drop_index('ix_alert_tenant_received', table_name='alerts')
    op.drop_table('alerts')
    op.drop_index(op.f('ix_actions_tenant_id'), table_name='actions')
    op.drop_index(op.f('ix_actions_investigation_id'), table_name='actions')
    op.drop_table('actions')
    op.drop_index(op.f('ix_users_tenant_id'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_shifts_tenant_id'), table_name='shifts')
    op.drop_table('shifts')
    op.drop_index(op.f('ix_misp_notices_tenant_id'), table_name='misp_notices')
    op.drop_table('misp_notices')
    op.drop_index(op.f('ix_maintenance_tenant_id'), table_name='maintenance')
    op.drop_table('maintenance')
    op.drop_index(op.f('ix_investigations_tenant_id'), table_name='investigations')
    op.drop_index(op.f('ix_investigations_correlation_key'), table_name='investigations')
    op.drop_table('investigations')
    op.drop_index(op.f('ix_integration_states_tenant_id'), table_name='integration_states')
    op.drop_table('integration_states')
    op.drop_index(op.f('ix_exceptions_tenant_id'), table_name='exceptions')
    op.drop_table('exceptions')
    op.drop_index(op.f('ix_checkpoints_tenant_id'), table_name='checkpoints')
    op.drop_table('checkpoints')
    op.drop_index(op.f('ix_audit_tenant_id'), table_name='audit')
    op.drop_table('audit')
    op.drop_index(op.f('ix_assets_tenant_id'), table_name='assets')
    op.drop_table('assets')
    op.drop_table('tenants')
