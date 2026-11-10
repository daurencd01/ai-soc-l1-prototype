"""Persist five-way classification and validated alert state history."""

from datetime import datetime, timezone
from uuid import uuid4

from alembic import op
import sqlalchemy as sa


revision = "0004_classification_state"
down_revision = "0003_policy_approval"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("pipeline_state", sa.String(length=30), nullable=True))
    with op.batch_alter_table("investigations") as batch:
        batch.add_column(sa.Column("classification", sa.String(length=30), nullable=True))
        batch.add_column(sa.Column("confidence", sa.Float(), nullable=True))
    with op.batch_alter_table("decisions") as batch:
        batch.add_column(sa.Column("classification", sa.String(length=30), nullable=True))
        batch.add_column(sa.Column("confidence", sa.Float(), nullable=True))
        batch.add_column(sa.Column("evidence_for", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("evidence_against", sa.JSON(), nullable=True))

    bind = op.get_bind()
    bind.execute(sa.text("UPDATE alerts SET pipeline_state = CASE status "
                         "WHEN 'running' THEN 'ENRICHING' "
                         "WHEN 'auto_closed' THEN 'CLOSED_FP' "
                         "WHEN 'escalated' THEN 'CASE_CREATED' "
                         "WHEN 'needs_review' THEN 'NEEDS_REVIEW' "
                         "WHEN 'failed' THEN 'FAILED_PERMANENT' "
                         "WHEN 'completed' THEN 'TRIAGED' ELSE 'RECEIVED' END"))
    for table in ("investigations", "decisions"):
        bind.execute(sa.text(f"UPDATE {table} SET classification = CASE verdict "
                             "WHEN 'true_positive' THEN 'TP' ELSE 'INCONCLUSIVE' END"))
    bind.execute(sa.text("UPDATE decisions SET evidence_for = '[]', evidence_against = '[]'"))
    with op.batch_alter_table("alerts") as batch:
        batch.alter_column("pipeline_state", existing_type=sa.String(length=30), nullable=False)
    with op.batch_alter_table("decisions") as batch:
        batch.alter_column("evidence_for", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("evidence_against", existing_type=sa.JSON(), nullable=False)

    op.create_table(
        "pipeline_transitions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("alert_id", sa.String(length=36), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("from_state", sa.String(length=30), nullable=True),
        sa.Column("to_state", sa.String(length=30), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pipeline_transitions_tenant_id", "pipeline_transitions", ["tenant_id"])
    op.create_index("ix_pipeline_transitions_alert_id", "pipeline_transitions", ["alert_id"])
    op.create_index("ix_pipeline_transitions_investigation_id", "pipeline_transitions", ["investigation_id"])
    op.create_index("ix_pipeline_transition_alert_time", "pipeline_transitions",
                    ["tenant_id", "alert_id", "created_at"])
    old_rows = bind.execute(sa.text("SELECT id, tenant_id, investigation_id, pipeline_state, received_at FROM alerts"))
    for row in old_rows:
        bind.execute(sa.text("INSERT INTO pipeline_transitions "
                             "(id, tenant_id, alert_id, investigation_id, from_state, to_state, actor, reason, created_at) "
                             "VALUES (:id, :tenant_id, :alert_id, :investigation_id, NULL, :to_state, :actor, :reason, :created_at)"),
                     {"id": str(uuid4()), "tenant_id": row.tenant_id, "alert_id": row.id,
                      "investigation_id": row.investigation_id, "to_state": row.pipeline_state,
                      "actor": "migration", "reason": "legacy_backfill",
                      "created_at": row.received_at or datetime.now(timezone.utc)})


def downgrade() -> None:
    op.drop_index("ix_pipeline_transition_alert_time", table_name="pipeline_transitions")
    op.drop_index("ix_pipeline_transitions_investigation_id", table_name="pipeline_transitions")
    op.drop_index("ix_pipeline_transitions_alert_id", table_name="pipeline_transitions")
    op.drop_index("ix_pipeline_transitions_tenant_id", table_name="pipeline_transitions")
    op.drop_table("pipeline_transitions")
    with op.batch_alter_table("decisions") as batch:
        for column in ("evidence_against", "evidence_for", "confidence", "classification"):
            batch.drop_column(column)
    with op.batch_alter_table("investigations") as batch:
        batch.drop_column("confidence")
        batch.drop_column("classification")
    with op.batch_alter_table("alerts") as batch:
        batch.drop_column("pipeline_state")
