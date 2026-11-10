from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.db import Base, get_db
from app.models import Action, Alert, Investigation, Tenant, User
from app.security import hash_password, token_for
from app.workflow import process_alert


def test_bundled_wazuh_dataset_import_keeps_reference_labels_out_of_analysis(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="fixture", deployment_mode="DEMO", automation_level="auto_close")
        db.add(tenant)
        db.flush()
        user = User(tenant_id=tenant.id, username="fixture-admin", password_hash=hash_password("pw"), role="admin")
        db.add(user)
        db.commit()
        token = token_for(user)

    def override_db():
        with Session(engine) as db:
            yield db

    main_module.app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(main_module, "dispatch", lambda _: True)
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "wazuh_merged_178.jsonl"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        client = TestClient(main_module.app)
        with fixture.open("rb") as stream:
            result = client.post("/api/dataset/import", headers=headers,
                                 files={"file": (fixture.name, stream, "application/x-ndjson")})
        assert result.status_code == 200, result.text
        assert result.json()["records"] == 178
        assert result.json()["created_count"] == 178
        assert result.json()["reference_labels"] == {"TP": 104, "FP": 74}
        with fixture.open("rb") as stream:
            again = client.post("/api/dataset/import", headers=headers,
                                files={"file": (fixture.name, stream, "application/x-ndjson")})
        assert again.status_code == 200
        assert again.json()["created_count"] == 0
        with Session(engine) as db:
            assert db.scalar(select(func.count()).select_from(Alert)) == 178
            alert = db.scalar(select(Alert).order_by(Alert.source_event_id).limit(1))
            assert alert.rule.startswith("wazuh:")
            assert "label" not in alert.raw
            process_alert(db, alert.id)
            inv = db.get(Investigation, alert.investigation_id)
            assert inv.verdict == "needs_review"
            assert db.scalar(select(func.count()).select_from(Action)) == 0
    finally:
        main_module.app.dependency_overrides.clear()
