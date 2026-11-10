"""Durable per-step TheHive case write journal.

Revision ID: 0002_case_writes
Revises: 0001_initial
Create Date: 2026-10-24
"""
from alembic import op
import sqlalchemy as sa


revision = "0002_case_writes"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_writes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=False),
        sa.Column("request_data", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("external_id", sa.String(length=256), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error_type", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key"),
        sa.UniqueConstraint("tenant_id", "case_id", "sequence"),
    )
    op.create_index(op.f("ix_case_writes_tenant_id"), "case_writes", ["tenant_id"])
    op.create_index(op.f("ix_case_writes_investigation_id"), "case_writes", ["investigation_id"])
    op.create_index(op.f("ix_case_writes_case_id"), "case_writes", ["case_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_case_writes_case_id"), table_name="case_writes")
    op.drop_index(op.f("ix_case_writes_investigation_id"), table_name="case_writes")
    op.drop_index(op.f("ix_case_writes_tenant_id"), table_name="case_writes")
    op.drop_table("case_writes")
