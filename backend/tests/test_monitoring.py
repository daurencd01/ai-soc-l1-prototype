from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import IntegrationState, Investigation, Tenant, User, utcnow
from app.security import hash_password, token_for
import app.tasks as tasks


def test_stale_worker_and_sla_are_displayed_with_sqlite_timestamps():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="monitor", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        user = User(tenant_id=tenant.id, username="monitor-user", password_hash=hash_password("pw"), role="analyst")
        db.add_all([user,
            IntegrationState(tenant_id=tenant.id, name="worker", status="healthy",
                             last_checked_at=utcnow() - timedelta(minutes=5)),
            Investigation(tenant_id=tenant.id, correlation_key="old", playbook_key="generic",
                          playbook_version="1", status="needs_review", due_at=utcnow() - timedelta(minutes=1))])
        db.commit()
        token = token_for(user)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {token}"}
        integrations = client.get("/api/integrations", headers=headers)
        assert integrations.status_code == 200
        worker = next(item for item in integrations.json()["items"] if item["name"] == "worker")
        assert worker["status"] == "stale"
        sla = client.get("/api/sla", headers=headers)
        assert sla.status_code == 200
        assert sla.json()["items"][0]["overdue"] is True
    finally:
        app.dependency_overrides.clear()


def test_log_arrival_gap_does_not_raise_on_sqlite_timestamp(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="log-gap", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        db.add(IntegrationState(tenant_id=tenant.id, name="splunk", status="healthy",
                                last_received_at=utcnow() - timedelta(minutes=20)))
        db.commit()
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    tasks.check_integrations()
    with Session(engine) as db:
        state = db.scalar(select(IntegrationState).where(IntegrationState.name == "splunk"))
        assert state.status == "stale"
