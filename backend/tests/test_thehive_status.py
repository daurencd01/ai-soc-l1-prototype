from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.adapters import AdapterError, RealTheHive
from app.db import Base, get_db
import app.main as main_module
from app.models import Action, Alert, Case, Tenant, User
from app.scenarios import instantiate_scenario
from app.security import hash_password, token_for
from app.workflow import ingest, process_alert


def test_thehive_find_case_uses_tag_membership_filter(monkeypatch):
    adapter = object.__new__(RealTheHive)
    calls = []
    monkeypatch.setattr(adapter, "_request", lambda method, path, body: calls.append((method, path, body)) or [])
    assert adapter.find_case("key-1") is None
    method, path, body = calls[0]
    assert (method, path) == ("POST", "/api/v1/query")
    assert body["query"][1] == {"_name": "filter", "_in": {"_field": "tags", "_values": ["soc-key:key-1"]}}
    monkeypatch.setattr(adapter, "_request", lambda *_: [{"_id": "a"}, {"_id": "b"}])
    try:
        adapter.find_case("key-1")
    except AdapterError:
        pass
    else:
        raise AssertionError("Duplicate idempotency tags must be investigated")


def test_case_status_update_is_admin_policy_gated_and_idempotent(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="hive", deployment_mode="DEMO", automation_level="auto_close")
        db.add(tenant)
        db.flush()
        admin = User(tenant_id=tenant.id, username="hive-admin", password_hash=hash_password("pw"), role="admin")
        analyst = User(tenant_id=tenant.id, username="hive-analyst", password_hash=hash_password("pw"), role="analyst")
        db.add_all([admin, analyst])
        db.commit()
        admin_token, analyst_token = token_for(admin), token_for(analyst)
        alert, _ = ingest(db, tenant.id, instantiate_scenario("root_unapproved")[0])
        process_alert(db, alert.id)
        case = db.scalar(select(Case).where(Case.tenant_id == tenant.id))
        case_id, investigation_id, tenant_id, case_external_id = case.id, case.investigation_id, tenant.id, case.external_id
        assert case.external_id

    def override_db():
        with Session(engine) as db:
            yield db

    main_module.app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(main_module.app)
        ah = {"Authorization": f"Bearer {admin_token}"}
        lh = {"Authorization": f"Bearer {analyst_token}"}
        statuses = client.get(f"/api/cases/{case_id}/statuses", headers=ah)
        assert statuses.status_code == 200
        assert {item["value"] for item in statuses.json()["items"]} == {"Open", "Resolved"}
        assert client.post(f"/api/cases/{case_id}/status", json={"status": "Resolved"}, headers=ah).status_code == 403
        assert client.patch("/api/settings", json={"automation_level": "approved_response"}, headers=ah).status_code == 200
        assert client.post(f"/api/cases/{case_id}/status", json={"status": "Resolved"}, headers=lh).status_code == 403
        assert client.post(f"/api/cases/{case_id}/status", json={"status": "Invalid"}, headers=ah).status_code == 422
        result = client.post(f"/api/cases/{case_id}/status", json={"status": "Resolved"}, headers=ah)
        assert result.status_code == 200, result.text
        assert result.json()["status"] == "succeeded"
        repeated = client.post(f"/api/cases/{case_id}/status", json={"status": "Resolved"}, headers=ah)
        assert repeated.status_code == 200
        assert repeated.json()["id"] == result.json()["id"]
        reopened = client.post(f"/api/cases/{case_id}/status", json={"status": "Open"}, headers=ah)
        assert reopened.status_code == 200
        assert reopened.json()["status"] == "succeeded"
        resolved_again = client.post(f"/api/cases/{case_id}/status", json={"status": "Resolved"}, headers=ah)
        assert resolved_again.status_code == 200
        assert resolved_again.json()["status"] == "succeeded"
        assert resolved_again.json()["id"] != result.json()["id"]
        with Session(engine) as db:
            assert db.get(Case, case_id).status == "Resolved"
            assert db.scalar(select(func.count()).select_from(Action).where(Action.kind == "update_case")) == 3
            ambiguous = Action(tenant_id=tenant_id, investigation_id=investigation_id,
                               kind="update_case", idempotency_key=f"{case_id}:status:Open",
                               target=case_id, status="unknown", detail={"requested_status": "Open"})
            db.add(ambiguous)
            db.commit()
            ambiguous_id = ambiguous.id
        pending = client.post(f"/api/actions/{ambiguous_id}/reconcile", headers=ah)
        assert pending.status_code == 200
        assert pending.json()["status"] == "unknown"

        class HiveReadback:
            def find_case(self, key):
                return case_external_id

            def case_status(self, external_id):
                return "Open"

        import app.workflow as workflow
        monkeypatch.setattr(workflow, "thehive_adapter", lambda: HiveReadback())
        resolved = client.post(f"/api/actions/{ambiguous_id}/reconcile", headers=ah)
        assert resolved.status_code == 200
        assert resolved.json()["status"] == "succeeded"
        with Session(engine) as db:
            assert db.get(Case, case_id).status == "Open"
    finally:
        main_module.app.dependency_overrides.clear()
