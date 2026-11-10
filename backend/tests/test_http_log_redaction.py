"""HTTP telemetry stores a route template, never a webhook secret value."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.db import Base, get_db


def test_webhook_secret_is_absent_from_request_log(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    records = []
    monkeypatch.setattr(main_module, "log_event", lambda name, **fields: records.append((name, fields)))

    def override_db():
        with Session(engine) as db:
            yield db

    main_module.app.dependency_overrides[get_db] = override_db
    try:
        secret = "sensitive-test-token"
        response = TestClient(main_module.app).post(
            f"/api/ingest/webhook/missing/{secret}", json={"source": "test"})
        assert response.status_code == 401
        assert len(response.headers["X-Request-ID"]) == 32
        assert records[-1][0] == "http_request"
        assert records[-1][1]["route"] == "/api/ingest/webhook/{tenant_id}/{secret}"
        assert secret not in str(records)
    finally:
        main_module.app.dependency_overrides.clear()
        engine.dispose()
