"""Persist last successful check and last safe integration error type."""

from alembic import op
import sqlalchemy as sa


revision = "0009_integration_health_history"
down_revision = "0008_llm_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("integration_states") as batch:
        batch.add_column(sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_error", sa.String(length=100), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("integration_states") as batch:
        batch.drop_column("last_error")
        batch.drop_column("last_error_at")
        batch.drop_column("last_success_at")
