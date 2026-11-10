"""Keep validated model references and provenance with every saved decision."""

from alembic import op
import sqlalchemy as sa


revision = "0008_llm_provenance"
down_revision = "0007_ingestion_quarantine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("decisions") as batch:
        batch.add_column(sa.Column("related_event_ids", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("mitre_techniques", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("model_auto_close_candidate", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("model_classification", sa.String(length=30), nullable=True))
        batch.add_column(sa.Column("model_confidence", sa.Float(), nullable=True))
        batch.add_column(sa.Column("model_name", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("model_digest", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("prompt_version", sa.String(length=60), nullable=True))
        batch.add_column(sa.Column("prompt_sha256", sa.String(length=64), nullable=True))
    op.execute("UPDATE decisions SET related_event_ids = '[]', mitre_techniques = '[]'")
    with op.batch_alter_table("decisions") as batch:
        batch.alter_column("related_event_ids", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("mitre_techniques", existing_type=sa.JSON(), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("decisions") as batch:
        for name in ("prompt_sha256", "prompt_version", "model_digest", "model_name",
                     "model_confidence", "model_classification", "model_auto_close_candidate",
                     "mitre_techniques", "related_event_ids"):
            batch.drop_column(name)
