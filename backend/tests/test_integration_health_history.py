"""Health checks retain the last success and safe error across transitions."""

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.tasks as tasks
from app.db import Base
from app.models import IntegrationState, Tenant
from app.workflow import _integration


def test_last_success_and_error_survive_later_health_changes(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="integration-history", deployment_mode="DEMO")
        db.add(tenant)
        db.flush()
        tenant_id = tenant.id
        _integration(db, tenant.id, "thehive", "healthy", "API 5.7.3")
        db.commit()
        first = db.scalar(select(IntegrationState).where(IntegrationState.name == "thehive"))
        assert first.last_success_at is not None
        first_success = first.last_success_at
        _integration(db, tenant.id, "thehive", "unavailable", "TimeoutException")
        db.commit()
        assert first.last_success_at == first_success
        assert first.last_error == "TimeoutException"
        assert first.last_error_at is not None
        _integration(db, tenant.id, "thehive", "healthy", "API 5.7.3")
        db.commit()
        assert first.status == "healthy"
        assert first.last_error == "TimeoutException"
        assert first.last_success_at is not None
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    tasks.check_integrations()
    with Session(engine) as db:
        rows = {item.name: item for item in db.scalars(select(IntegrationState).where(
            IntegrationState.tenant_id == tenant_id)).all()}
        assert rows["database"].status == "healthy"
        assert rows["redis"].status == "not_applicable"
        assert rows["ollama"].status == "not_configured"
        assert rows["worker"].status == "not_applicable"
    engine.dispose()
