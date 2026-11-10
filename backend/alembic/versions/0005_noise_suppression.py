"""Separately approved and auditable policies for local NOISE suppression."""

from alembic import op
import sqlalchemy as sa


revision = "0005_noise_suppression"
down_revision = "0004_classification_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("policy_key", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("rule", sa.String(length=100), nullable=False),
        sa.Column("entity", sa.String(length=256), nullable=False),
        sa.Column("owner", sa.String(length=100), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approval_status", sa.String(length=20), nullable=False),
        sa.Column("approved_by", sa.String(length=100), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=100), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("change_reason", sa.Text(), nullable=False),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "policy_key", "version", name="uq_suppression_tenant_policy_version"),
    )
    op.create_index(op.f("ix_suppression_rules_tenant_id"), "suppression_rules", ["tenant_id"])
    op.create_index("uq_suppression_one_approved_version", "suppression_rules", ["tenant_id", "policy_key"],
                    unique=True, sqlite_where=sa.text("approval_status = 'approved'"),
                    postgresql_where=sa.text("approval_status = 'approved'"))
    op.create_table(
        "suppression_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("event_type", sa.String(length=30), nullable=False),
        sa.Column("from_status", sa.String(length=20), nullable=True),
        sa.Column("to_status", sa.String(length=20), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["policy_id"], ["suppression_rules.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_suppression_events_tenant_id"), "suppression_events", ["tenant_id"])
    op.create_index(op.f("ix_suppression_events_policy_id"), "suppression_events", ["policy_id"])
    op.create_index("ix_suppression_events_tenant_policy_time", "suppression_events",
                    ["tenant_id", "policy_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_suppression_events_tenant_policy_time", table_name="suppression_events")
    op.drop_index(op.f("ix_suppression_events_policy_id"), table_name="suppression_events")
    op.drop_index(op.f("ix_suppression_events_tenant_id"), table_name="suppression_events")
    op.drop_table("suppression_events")
    op.drop_index("uq_suppression_one_approved_version", table_name="suppression_rules")
    op.drop_index(op.f("ix_suppression_rules_tenant_id"), table_name="suppression_rules")
    op.drop_table("suppression_rules")
