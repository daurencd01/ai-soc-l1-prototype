"""Quarantine malformed Splunk rows before advancing the poll checkpoint."""

from alembic import op
import sqlalchemy as sa


revision = "0007_ingestion_quarantine"
down_revision = "0006_ingestion_fingerprint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ingestion_quarantine",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("source_event_id", sa.String(length=256), nullable=False),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("raw_sha256", sa.String(length=64), nullable=False),
        sa.Column("raw_bytes", sa.Integer(), nullable=False),
        sa.Column("raw_truncated", sa.Boolean(), nullable=False),
        sa.Column("error_type", sa.String(length=100), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "source", "source_event_id"),
    )
    op.create_index(op.f("ix_ingestion_quarantine_tenant_id"), "ingestion_quarantine", ["tenant_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_ingestion_quarantine_tenant_id"), table_name="ingestion_quarantine")
    op.drop_table("ingestion_quarantine")
