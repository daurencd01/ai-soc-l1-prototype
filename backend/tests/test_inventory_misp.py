from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Asset, MispNotice, Tenant, User
from app.security import hash_password, token_for
import app.tasks as tasks


def test_demo_misp_notice_is_ingested_once(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Tenant(name="demo-misp", deployment_mode="DEMO", automation_level="observe"))
        db.commit()
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    tasks.check_integrations()
    tasks.check_integrations()
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(MispNotice)) == 1
        notice = db.scalar(select(MispNotice))
        assert notice.l1_status == "pending"
        assert notice.l2_status == "not_transferred"


def test_inventory_and_misp_tracking_are_tenant_scoped_and_audited():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first = Tenant(name="one", deployment_mode="DEMO", automation_level="observe")
        second = Tenant(name="two", deployment_mode="DEMO", automation_level="observe")
        db.add_all([first, second])
        db.flush()
        first_admin = User(tenant_id=first.id, username="inventory-admin", password_hash=hash_password("pw"), role="admin")
        first_analyst = User(tenant_id=first.id, username="inventory-analyst", password_hash=hash_password("pw"), role="analyst")
        second_analyst = User(tenant_id=second.id, username="other-analyst", password_hash=hash_password("pw"), role="analyst")
        notice = MispNotice(tenant_id=first.id, external_id="demo-notice", title="Учебное сообщение", data={"Event": {"id": "1"}})
        db.add_all([first_admin, first_analyst, second_analyst, notice])
        db.commit()
        admin_token = token_for(first_admin)
        analyst_token = token_for(first_analyst)
        other_token = token_for(second_analyst)
        notice_id = notice.id

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        ah = {"Authorization": f"Bearer {admin_token}"}
        lh = {"Authorization": f"Bearer {analyst_token}"}
        oh = {"Authorization": f"Bearer {other_token}"}
        peer = {"kind": "vpn_peer", "value": "branch-peer", "owner": "Сеть", "criticality": "high",
                "attributes": {"allowed": True, "tunnel": "branch", "device": "gw-01"}}
        assert client.post("/api/assets", json={**peer, "attributes": {"allowed": True}}, headers=ah).status_code == 422
        assert client.post("/api/assets", json=peer, headers=lh).status_code == 403
        created = client.post("/api/assets", json=peer, headers=ah)
        assert created.status_code == 200
        asset_id = created.json()["id"]
        assert client.post("/api/assets", json=peer, headers=ah).status_code == 409
        assert len(client.get("/api/assets", headers=ah).json()["items"]) == 1
        assert client.get("/api/assets", headers=oh).json()["items"] == []
        assert client.put(f"/api/assets/{asset_id}", json=peer, headers=oh).status_code == 403

        assert client.get("/api/misp/notices", headers=oh).json()["items"] == []
        assert client.patch(f"/api/misp/notices/{notice_id}", json={"l1_status": "reviewed"}, headers=oh).status_code == 404
        reviewed = client.patch(f"/api/misp/notices/{notice_id}", json={"l1_status": "reviewed"}, headers=lh)
        assert reviewed.status_code == 200
        assert reviewed.json()["l2_status"] == "not_transferred"
        assert client.patch(f"/api/misp/notices/{notice_id}", json={"l2_status": "handoff_recorded",
                            "handoff_reference": "CASE-10"}, headers=lh).status_code == 403
        assert client.patch(f"/api/misp/notices/{notice_id}", json={"l2_status": "handoff_recorded"}, headers=ah).status_code == 422
        recorded = client.patch(f"/api/misp/notices/{notice_id}", json={"l2_status": "handoff_recorded",
                                "handoff_reference": "CASE-10"}, headers=ah)
        assert recorded.status_code == 200
        assert recorded.json()["l2_status"] == "handoff_recorded"
        with Session(engine) as db:
            assert db.get(MispNotice, notice_id).data["soc_tracking"]["handoff_reference"] == "CASE-10"
            assert db.get(Asset, asset_id).attributes["allowed"] is True
    finally:
        app.dependency_overrides.clear()
