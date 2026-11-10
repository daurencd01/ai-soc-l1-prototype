import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
import app.main as main_module
from app.models import Alert, Investigation, Tenant, User
from app.scenarios import SCENARIOS
from app.security import hash_password, token_for
from app.workflow import process_alert


@pytest.mark.parametrize("key", list(SCENARIOS))
def test_demo_scenario_verdict_matches_catalogue(key, monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        owner = Tenant(name="demo", deployment_mode="DEMO", automation_level="auto_close")
        db.add(owner)
        db.flush()
        user = User(tenant_id=owner.id, username="admin", password_hash=hash_password("pw"), role="admin")
        db.add(user)
        db.commit()
        owner_id = owner.id
        token = token_for(user)

    def override_db():
        with Session(engine) as db:
            yield db

    main_module.app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(main_module, "dispatch", lambda alert_id: True)
    try:
        client = TestClient(main_module.app)
        response = client.post(f"/api/scenarios/{key}/run", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200, response.text
        with Session(engine) as db:
            alerts = db.scalars(select(Alert).where(Alert.tenant_id == owner_id)).all()
            assert len(alerts) == (1 if key == "duplicate_delivery" else SCENARIOS[key]["pair_type"] and 2 or 1)
            for alert in alerts:
                process_alert(db, alert.id)
            inv = db.get(Investigation, alerts[0].investigation_id)
            assert inv.verdict == SCENARIOS[key]["expected_verdict"], (key, inv.rationale)
    finally:
        main_module.app.dependency_overrides.clear()
