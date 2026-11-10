"""Operational rate counts completed tenant investigations, not UI actions."""

from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.metrics import metric_snapshot
from app.models import Action, Audit, Investigation, Tenant, utcnow


def test_automated_handling_rate_excludes_reviews_manual_actions_and_other_tenants():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        first = Tenant(name="metrics-first", deployment_mode="DEMO")
        second = Tenant(name="metrics-second", deployment_mode="DEMO")
        db.add_all([first, second])
        db.flush()

        def investigation(tenant_id, key, status, finished=True):
            row = Investigation(
                tenant_id=tenant_id, correlation_key=key, playbook_key="generic",
                playbook_version="1", status=status,
                started_at=now - timedelta(seconds=4) if finished else None,
                completed_at=now if finished else None,
            )
            db.add(row)
            db.flush()
            return row

        automated = investigation(first.id, "automatic-case", "escalated")
        investigation(first.id, "awaiting-human", "needs_review")
        reviewed = investigation(first.id, "reviewed-noise", "suppressed")
        manual = investigation(first.id, "manual-close", "auto_closed")
        investigation(first.id, "still-queued", "queued", finished=False)
        investigation(second.id, "other-tenant", "escalated")
        action = Action(tenant_id=first.id, investigation_id=manual.id,
                        kind="close_alert", status="succeeded",
                        idempotency_key="manual-close-action")
        db.add(action)
        db.flush()
        db.add_all([
            Audit(tenant_id=first.id, actor="analyst", operation="review",
                  subject_type="investigation", subject_id=reviewed.id),
            Audit(tenant_id=first.id, actor="admin", operation="manual_action_requested",
                  subject_type="action", subject_id=action.id),
            Audit(tenant_id=first.id, actor="integration", operation="integration_error",
                  subject_type="integration", subject_id="splunk"),
            Audit(tenant_id=second.id, actor="integration", operation="integration_error",
                  subject_type="integration", subject_id="thehive"),
        ])
        db.commit()
        first_id, second_id = first.id, second.id

        snapshot = metric_snapshot(db, first_id)
        assert snapshot["processed_investigations_total"] == 4
        assert snapshot["automated_handling_total"] == 1
        assert snapshot["automated_handling_rate"] == 0.25
        assert snapshot["integration_errors_total"] == 1
        assert snapshot["auto_close_attempts_total"] == 0
        assert snapshot["processing_duration_seconds"]["count"] == 4
        other = metric_snapshot(db, second_id)
        assert other["automated_handling_rate"] == 1.0
        assert other["integration_errors_total"] == 1
        assert automated.id is not None
    engine.dispose()


def test_automated_handling_rate_is_unknown_without_completed_investigations():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="metrics-empty", deployment_mode="DEMO")
        db.add(tenant)
        db.flush()
        snapshot = metric_snapshot(db, tenant.id)
        assert snapshot["automated_handling_rate"] is None
        assert snapshot["processed_investigations_total"] == 0
    engine.dispose()
