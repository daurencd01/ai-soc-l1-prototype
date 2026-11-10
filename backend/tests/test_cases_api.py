"""Case list shows tenant-scoped, confirmed facts and uncertain writes honestly."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Action, Alert, Case, CaseWrite, Investigation, Tenant, User, utcnow
from app.security import hash_password, token_for


def test_case_list_scopes_tenant_and_reports_last_confirmed_fields():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = Tenant(name="cases-first", deployment_mode="DEMO")
        second = Tenant(name="cases-second", deployment_mode="DEMO")
        db.add_all([first, second])
        db.flush()
        user = User(tenant_id=first.id, username="case-reader", password_hash=hash_password("password"), role="viewer")
        own_inv = Investigation(tenant_id=first.id, correlation_key="own-case", playbook_key="generic",
                                playbook_version="1", classification="TP", summary="Escalation",
                                rationale="Investigate source")
        other_inv = Investigation(tenant_id=second.id, correlation_key="foreign-case", playbook_key="generic",
                                  playbook_version="1", classification="TP")
        db.add_all([user, own_inv, other_inv])
        db.flush()
        own = Case(tenant_id=first.id, investigation_id=own_inv.id, external_id="hive-case-1",
                   status="open", title="Updated", data={"classification": "TP",
                       "source_references": ["https://splunk.example.test/event/1",
                                             "https://splunk.example.test/event/2?token=unsafe"],
                       "remote_field_values": {"description": "New description", "severity": 4}})
        foreign = Case(tenant_id=second.id, investigation_id=other_inv.id, external_id="hive-case-other",
                       status="open", title="Foreign")
        db.add_all([own, foreign])
        db.flush()
        create = CaseWrite(tenant_id=first.id, investigation_id=own_inv.id, case_id=own.id,
                           sequence=0, kind="create_case", idempotency_key="create-own",
                           request_data={"description": "Original", "severity": 2}, status="succeeded",
                           completed_at=utcnow())
        observable = CaseWrite(tenant_id=first.id, investigation_id=own_inv.id, case_id=own.id,
                               sequence=1, kind="observable", idempotency_key="observable-own",
                               request_data={"dataType": "ip", "data": "203.0.113.1"}, status="succeeded",
                               completed_at=utcnow())
        mutation = Action(tenant_id=first.id, investigation_id=own_inv.id, kind="update_case_fields",
                          idempotency_key="update-own", target=own.id, status="unknown")
        alert = Alert(tenant_id=first.id, investigation_id=own_inv.id, source="splunk",
                      source_event_id="case-alert", rule="root_ssh", title="Source alert", severity="high",
                      event_at=utcnow(), raw={"splunk_url": "https://splunk.example.test/event/3?token=private"})
        db.add_all([create, observable, mutation, alert])
        db.commit()
        own_id, own_inv_id, mutation_id, user_token = own.id, own_inv.id, mutation.id, token_for(user)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.get("/api/cases", headers=headers)
        assert response.status_code == 200
        items = response.json()["items"]
        assert len(items) == 1 and items[0]["id"] == own_id
        assert items[0]["description"] == "New description"
        assert items[0]["severity"] == "critical"
        assert items[0]["sync_status"] == "unknown"
        assert items[0]["observables"] == [{"dataType": "ip", "data": "203.0.113.1"}]
        assert items[0]["source_references"] == ["https://splunk.example.test/event/1"]
        queued = client.get("/api/alerts", headers=headers).json()["items"]
        assert queued[0]["case_sync_status"] == "unknown"
        assert queued[0]["source_reference"] == "https://splunk.example.test/event/3"
        assert "private" not in str(queued)
        with Session(engine) as db:
            db.get(Action, mutation_id).status = "succeeded"
            db.commit()
        confirmed = client.get("/api/cases", headers=headers).json()["items"]
        assert confirmed[0]["sync_status"] == "confirmed"
        assert client.get("/api/alerts", headers=headers).json()["items"][0]["case_sync_status"] == "confirmed"
        detail_case = client.get(f"/api/investigations/{own_inv_id}", headers=headers).json()["cases"][0]
        assert detail_case["sync_status"] == "confirmed"
        assert detail_case["case_reference"] is None  # DEMO has no external TheHive UI.
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
