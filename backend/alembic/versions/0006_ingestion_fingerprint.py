"""Persist normalized alerts and tenant-scoped expiring fingerprint claims."""

from alembic import op
import sqlalchemy as sa


revision = "0006_ingestion_fingerprint"
down_revision = "0005_noise_suppression"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("normalized", sa.JSON(), nullable=True))
    op.add_column("alerts", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.create_table(
        "alert_fingerprints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "fingerprint"),
    )
    op.create_index(op.f("ix_alert_fingerprints_tenant_id"), "alert_fingerprints", ["tenant_id"])
    op.create_index(op.f("ix_alert_fingerprints_alert_id"), "alert_fingerprints", ["alert_id"])
    op.create_index(op.f("ix_alert_fingerprints_expires_at"), "alert_fingerprints", ["expires_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_alert_fingerprints_expires_at"), table_name="alert_fingerprints")
    op.drop_index(op.f("ix_alert_fingerprints_alert_id"), table_name="alert_fingerprints")
    op.drop_index(op.f("ix_alert_fingerprints_tenant_id"), table_name="alert_fingerprints")
    op.drop_table("alert_fingerprints")
    op.drop_column("alerts", "fingerprint")
    op.drop_column("alerts", "normalized")
