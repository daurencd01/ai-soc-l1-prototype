"""A committed terminal action must never be retried as a new write."""
from datetime import timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Alert, Audit, Investigation, Tenant, utcnow
import app.tasks as tasks


def database():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def record(db: Session, tenant_id: str, key: str, state: str, status: str) -> tuple[str, str]:
    old = utcnow() - timedelta(minutes=10)
    inv = Investigation(tenant_id=tenant_id, correlation_key=key, playbook_key="generic",
                        playbook_version="1", status=status, claimed_at=old)
    db.add(inv)
    db.flush()
    alert = Alert(tenant_id=tenant_id, investigation_id=inv.id, source="demo",
                  source_event_id=key, rule="generic", title=key, event_at=old,
                  status=status, pipeline_state=state, claimed_at=old)
    db.add(alert)
    db.commit()
    return alert.id, inv.id


def test_worker_exception_after_committed_case_write_repairs_terminal_state(monkeypatch):
    engine = database()
    with Session(engine) as db:
        tenant = Tenant(name="terminal-worker", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.commit()
        tenant_id = tenant.id
        alert_id, inv_id = record(db, tenant_id, "terminal-case", "TRIAGED", "running")

    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))

    def interrupted_after_write(db: Session, target: str) -> None:
        alert = db.get(Alert, target)
        alert.pipeline_state = "CASE_CREATED"
        db.commit()
        raise RuntimeError("worker stopped after external result was committed")

    monkeypatch.setattr(tasks, "process_alert", interrupted_after_write)
    tasks.process_alert_task(alert_id)

    with Session(engine) as db:
        alert, inv = db.get(Alert, alert_id), db.get(Investigation, inv_id)
        assert alert.pipeline_state == "CASE_CREATED" and alert.status == "escalated"
        assert inv.status == "escalated"
        assert alert.claimed_at is None and inv.claimed_at is None
        assert alert.processed_at is not None
        receipt = db.scalar(select(Audit).where(Audit.tenant_id == tenant_id,
            Audit.operation == "terminal_state_reconciled", Audit.subject_id == alert_id))
        assert receipt is not None
    engine.dispose()


def test_recovery_repairs_queued_terminal_rows_without_redispatch(monkeypatch):
    engine = database()
    with Session(engine) as db:
        tenant = Tenant(name="terminal-recover", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.commit()
        case_id, case_inv = record(db, tenant.id, "case", "CASE_CREATED", "queued")
        close_id, close_inv = record(db, tenant.id, "close", "CLOSED_FP", "queued")
        queued_id, _ = record(db, tenant.id, "ordinary", "RECEIVED", "queued")
        db.add(Audit(tenant_id=tenant.id, actor="admin", operation="manual_close_granted",
                     subject_type="investigation", subject_id=close_inv))
        db.commit()

    seen: list[str] = []
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    monkeypatch.setattr(tasks, "dispatch", lambda item_id: seen.append(item_id) or True)
    assert tasks.recover() == 1
    assert seen == [queued_id]
    with Session(engine) as db:
        assert db.get(Alert, case_id).status == "escalated"
        assert db.get(Investigation, case_inv).status == "escalated"
        assert db.get(Alert, close_id).status == "closed"
        assert db.get(Investigation, close_inv).status == "closed"
    engine.dispose()
