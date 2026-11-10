"""Quarantined source rows are visible only to their tenant administrator."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import IngestionQuarantine, Tenant, User
from app.security import hash_password, token_for


def test_quarantine_list_and_detail_are_tenant_scoped():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = Tenant(name="first-q", deployment_mode="DEMO")
        second = Tenant(name="second-q", deployment_mode="DEMO")
        db.add_all([first, second])
        db.flush()
        admin = User(tenant_id=first.id, username="q-admin", password_hash=hash_password("password"), role="admin")
        analyst = User(tenant_id=first.id, username="q-analyst", password_hash=hash_password("password"), role="analyst")
        foreign_admin = User(tenant_id=second.id, username="other-q-admin",
                             password_hash=hash_password("password"), role="admin")
        row = IngestionQuarantine(tenant_id=first.id, source="splunk", source_event_id="bad-1",
                                  raw_json='{"secret":"source data"}', raw_sha256="a" * 64,
                                  raw_bytes=24, raw_truncated=False, error_type="ValueError",
                                  reason="event_at missing")
        db.add_all([admin, analyst, foreign_admin, row])
        db.commit()
        row_id = row.id
        admin_token, analyst_token, foreign_token = (
            token_for(admin), token_for(analyst), token_for(foreign_admin))

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        base = "/api/ingestion-quarantine"
        ah = {"Authorization": f"Bearer {admin_token}"}
        lh = {"Authorization": f"Bearer {analyst_token}"}
        oh = {"Authorization": f"Bearer {foreign_token}"}
        assert client.get(base, headers=lh).status_code == 403
        assert client.get(base, headers=oh).json() == {"items": []}
        listed = client.get(base, headers=ah)
        assert listed.status_code == 200
        assert len(listed.json()["items"]) == 1
        assert "raw_json" not in listed.json()["items"][0]
        assert client.get(f"{base}/{row_id}", headers=oh).status_code == 404
        detail = client.get(f"{base}/{row_id}", headers=ah)
        assert detail.status_code == 200
        assert detail.json()["raw_json"] == '{"secret":"source data"}'
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
