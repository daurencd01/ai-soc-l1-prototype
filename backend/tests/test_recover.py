from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Alert, Investigation, PlaybookRun, Tenant, utcnow
import app.tasks as tasks


def test_stale_worker_claim_is_requeued_and_run_is_marked_interrupted(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    old = utcnow() - timedelta(minutes=4)
    with Session(engine) as db:
        tenant = Tenant(name="recover", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        inv = Investigation(tenant_id=tenant.id, correlation_key="recover-1", playbook_key="generic",
                            playbook_version="1", status="running", claimed_at=old)
        db.add(inv)
        db.flush()
        alert = Alert(tenant_id=tenant.id, investigation_id=inv.id, source="demo", source_event_id="recover-1",
                      rule="generic", title="Worker restart", event_at=old, status="running", claimed_at=old)
        run = PlaybookRun(tenant_id=tenant.id, investigation_id=inv.id, key="generic", version="1", status="running")
        db.add_all([alert, run])
        db.commit()
        alert_id, inv_id, run_id = alert.id, inv.id, run.id

    seen = []
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    monkeypatch.setattr(tasks, "dispatch", lambda item_id: seen.append(item_id) or True)
    assert tasks.recover() == 1
    assert seen == [alert_id]
    with Session(engine) as db:
        assert db.get(Alert, alert_id).status == "queued"
        assert db.get(Alert, alert_id).claimed_at is None
        assert db.get(Investigation, inv_id).status == "queued"
        assert db.get(PlaybookRun, run_id).status == "interrupted"
        assert db.get(PlaybookRun, run_id).completed_at is not None
