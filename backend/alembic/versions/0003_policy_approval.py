"""Versioned, separately approved and revocable FP policies.

Existing exception rows become drafts. A legacy approved_by string is not
evidence of a human approval event and must never authorize a close.
"""
from alembic import op
import sqlalchemy as sa


revision = "0003_policy_approval"
down_revision = "0002_case_writes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("exceptions") as batch:
        batch.add_column(sa.Column("policy_key", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("version", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("owner", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("created_by", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("approval_status", sa.String(length=20), nullable=True))
        batch.add_column(sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("revoked_by", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("change_reason", sa.Text(), nullable=True))
        batch.add_column(sa.Column("revocation_reason", sa.Text(), nullable=True))

    op.execute(sa.text("UPDATE exceptions SET policy_key = id, version = 1, "
                       "owner = 'unassigned', created_by = 'legacy_migration', "
                       "approval_status = 'draft', change_reason = 'legacy_import'"))
    with op.batch_alter_table("exceptions") as batch:
        for name, kind in (
            ("policy_key", sa.String(length=36)), ("version", sa.Integer()),
            ("owner", sa.String(length=100)), ("created_by", sa.String(length=100)),
            ("approval_status", sa.String(length=20)), ("change_reason", sa.Text()),
        ):
            batch.alter_column(name, existing_type=kind, nullable=False)
        batch.create_unique_constraint("uq_exceptions_tenant_policy_version",
                                       ["tenant_id", "policy_key", "version"])
        batch.create_index("uq_exceptions_one_approved_version", ["tenant_id", "policy_key"],
                           unique=True, sqlite_where=sa.text("approval_status = 'approved'"),
                           postgresql_where=sa.text("approval_status = 'approved'"))

    op.create_table(
        "policy_events",
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
        sa.ForeignKeyConstraint(["policy_id"], ["exceptions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_policy_events_tenant_id"), "policy_events", ["tenant_id"])
    op.create_index(op.f("ix_policy_events_policy_id"), "policy_events", ["policy_id"])
    op.create_index("ix_policy_events_tenant_policy_time", "policy_events",
                    ["tenant_id", "policy_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_policy_events_tenant_policy_time", table_name="policy_events")
    op.drop_index(op.f("ix_policy_events_policy_id"), table_name="policy_events")
    op.drop_index(op.f("ix_policy_events_tenant_id"), table_name="policy_events")
    op.drop_table("policy_events")
    with op.batch_alter_table("exceptions") as batch:
        batch.drop_index("uq_exceptions_one_approved_version")
        batch.drop_constraint("uq_exceptions_tenant_policy_version", type_="unique")
        for name in ("revocation_reason", "change_reason", "revoked_at", "revoked_by",
                     "approved_at", "approval_status", "created_by", "owner", "version", "policy_key"):
            batch.drop_column(name)
