"""Case field updates require a scoped administrator and an allowlisted body."""

from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.db import Base, get_db
from app.models import Case, Investigation, Tenant, User
from app.security import hash_password, token_for


def test_case_fields_route_rejects_unknown_fields_and_checks_policy(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="case-fields", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        admin = User(tenant_id=tenant.id, username="case-fields-admin",
                     password_hash=hash_password("password"), role="admin")
        analyst = User(tenant_id=tenant.id, username="case-fields-analyst",
                       password_hash=hash_password("password"), role="analyst")
        inv = Investigation(tenant_id=tenant.id, correlation_key="case-fields", playbook_key="generic",
                            playbook_version="1")
        db.add_all([admin, analyst, inv])
        db.flush()
        case = Case(tenant_id=tenant.id, investigation_id=inv.id, external_id="demo-case-1",
                    title="Original", status="open")
        db.add(case)
        db.commit()
        tenant_id, case_id = tenant.id, case.id
        admin_token, analyst_token = token_for(admin), token_for(analyst)

    def override_db():
        with Session(engine) as db:
            yield db

    calls = []
    monkeypatch.setattr(main_module, "update_case_fields", lambda db, tenant, case, changes, actor: (
        calls.append((tenant.id, case.id, changes, actor)) or
        SimpleNamespace(id="field-action", status="succeeded", external_id=case.external_id, detail={})))
    main_module.app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(main_module.app)
        url = f"/api/cases/{case_id}/fields"
        ah = {"Authorization": f"Bearer {admin_token}"}
        lh = {"Authorization": f"Bearer {analyst_token}"}
        assert client.patch(url, json={"title": "New"}, headers=lh).status_code == 403
        assert client.patch(url, json={"title": "New"}, headers=ah).status_code == 403
        with Session(engine) as db:
            db.get(Tenant, tenant_id).automation_level = "approved_response"
            db.commit()
        assert client.patch(url, json={"tags": ["unsafe"]}, headers=ah).status_code == 422
        assert client.patch(url, json={"severity": True}, headers=ah).status_code == 422
        assert client.patch(url, json={}, headers=ah).status_code == 422
        assert client.patch(url, json={"title": "   "}, headers=ah).status_code == 422
        response = client.patch(url, json={"title": "New"}, headers=ah)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "succeeded"
        assert calls == [(tenant_id, case_id, {"title": "New"}, "case-fields-admin")]
    finally:
        main_module.app.dependency_overrides.clear()
        engine.dispose()
