from datetime import timedelta, datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.config import settings
from app.db import Base, get_db
from app.main import app
from app.models import Action, Alert, Case, Decision, Evidence, Investigation, Maintenance, Tenant, User, utcnow
from app.scenarios import instantiate_scenario
from app.security import hash_password, token_for
from app.workflow import can_act, ingest, perform_action, process_alert


def database():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def tenant(db: Session, name: str = "a", level: str = "auto_close") -> Tenant:
    item = Tenant(name=name, deployment_mode="DEMO", automation_level=level)
    db.add(item)
    db.commit()
    return item


def approved_maintenance(db: Session, tenant_id: str, payload: dict):
    raw = payload["raw"]
    when = __import__("datetime").datetime.fromisoformat(payload["event_at"])
    scope = {k: raw[k] for k in ("host", "src_ip", "auth_method")}
    db.add(Maintenance(tenant_id=tenant_id, title="Проверенный доступ", entity=raw["host"],
                       reason="Заявка на доступ", scope=scope, valid_from=when - timedelta(hours=1),
                       valid_until=when + timedelta(hours=1), approved_by="admin"))
    db.commit()


def test_full_demo_decisions_actions_and_deduplication(monkeypatch):
    monkeypatch.setattr(settings(), "auto_close_enabled", True)
    with Session(database()) as db:
        owner = tenant(db)
        approved = instantiate_scenario("root_approved")[0]
        approved_maintenance(db, owner.id, approved)
        alert, created = ingest(db, owner.id, approved)
        assert created
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        assert inv.classification == "BENIGN_TRUE_POSITIVE"
        assert inv.verdict == "needs_review" and inv.status == "needs_review"
        assert db.scalar(select(func.count()).select_from(Evidence).where(Evidence.tenant_id == owner.id)) >= 2
        assert db.scalar(select(func.count()).select_from(Decision).where(Decision.tenant_id == owner.id)) == 1
        again, created = ingest(db, owner.id, approved)
        assert not created and again.id == alert.id
        process_alert(db, again.id)
        assert db.scalar(select(func.count()).select_from(Action).where(Action.tenant_id == owner.id)) == 0

        suspicious = instantiate_scenario("root_unapproved")[0]
        bad, _ = ingest(db, owner.id, suspicious)
        process_alert(db, bad.id)
        bad_inv = db.get(Investigation, bad.investigation_id)
        assert bad_inv.classification == "TP"
        assert bad_inv.verdict == "true_positive" and bad_inv.status == "escalated"
        assert db.scalar(select(func.count()).select_from(Case).where(Case.tenant_id == owner.id)) == 1
        process_alert(db, bad.id)
        assert db.scalar(select(func.count()).select_from(Case).where(Case.tenant_id == owner.id)) == 1

        unknown = instantiate_scenario("unknown_rule")[0]
        item, _ = ingest(db, owner.id, unknown)
        process_alert(db, item.id)
        assert db.get(Investigation, item.investigation_id).verdict == "needs_review"


def test_auto_close_is_disabled_by_default_and_benign_event_is_not_fp():
    assert settings().auto_close_enabled is False
    with Session(database()) as db:
        owner = tenant(db)
        payload = instantiate_scenario("root_approved")[0]
        approved_maintenance(db, owner.id, payload)
        alert, _ = ingest(db, owner.id, payload)
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        assert inv.classification == "BENIGN_TRUE_POSITIVE"
        assert inv.verdict == "needs_review"
        assert inv.status == "needs_review"
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.tenant_id == owner.id, Action.kind == "close_alert")) == 0


def test_approval_scope_and_expiry_are_required_for_auto_close():
    with Session(database()) as db:
        owner = tenant(db)
        payload = instantiate_scenario("root_approved")[0]
        approved_maintenance(db, owner.id, payload)
        payload["raw"]["src_ip"] = "10.10.9.99"
        alert, _ = ingest(db, owner.id, payload)
        process_alert(db, alert.id)
        assert db.get(Investigation, alert.investigation_id).verdict == "needs_review"
        assert db.scalar(select(func.count()).select_from(Action)) == 0


def test_time_budget_sends_approved_alert_to_review_without_action(monkeypatch):
    import app.workflow as workflow
    with Session(database()) as db:
        owner = tenant(db)
        payload = instantiate_scenario("root_approved")[0]
        approved_maintenance(db, owner.id, payload)
        alert, _ = ingest(db, owner.id, payload)
        ticks = iter([0.0, 100.0])
        monkeypatch.setattr(workflow, "monotonic", lambda: next(ticks))
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        assert inv.verdict == "needs_review"
        assert inv.status == "needs_review"
        assert inv.analyzer == "timeout"
        assert db.scalar(select(func.count()).select_from(Action)) == 0


def test_model_disagreement_cannot_trigger_automatic_case(monkeypatch):
    import app.workflow as workflow
    from app.playbooks import Verdict
    with Session(database()) as db:
        owner = tenant(db)
        alert, _ = ingest(db, owner.id, instantiate_scenario("unknown_rule")[0])

        def conflicting_model(records, baseline):
            return Verdict(verdict="true_positive", priority="high", summary="Предложение модели",
                           rationale="Предположение", evidence_ids=[records[0]["id"]],
                           recommended_actions=["create_case"]), "external_model"

        monkeypatch.setattr(workflow, "model_analyze", conflicting_model)
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        assert inv.verdict == "needs_review"
        assert inv.status == "needs_review"
        assert db.scalar(select(func.count()).select_from(Action)) == 0


def test_ingest_rejects_timestamp_without_offset():
    with Session(database()) as db:
        owner = tenant(db)
        payload = instantiate_scenario("root_unapproved")[0]
        payload["event_at"] = "2026-10-21T12:00:00"
        with pytest.raises(ValueError, match="часовое смещение"):
            ingest(db, owner.id, payload)


def test_linked_alerts_are_preserved_without_duplicate_case():
    with Session(database()) as db:
        owner = tenant(db)
        pair = instantiate_scenario("linked_alerts")
        assert len(pair) == 2
        alerts = [ingest(db, owner.id, payload)[0] for payload in pair]
        assert alerts[0].id != alerts[1].id
        assert alerts[0].investigation_id == alerts[1].investigation_id
        assert db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == owner.id)) == 2
        for item in alerts:
            process_alert(db, item.id)
        assert db.scalar(select(func.count()).select_from(Case).where(Case.tenant_id == owner.id)) <= 1


def test_unknown_case_action_reconciles_before_completion_without_duplicate_case():
    with Session(database()) as db:
        owner = tenant(db)
        payload = instantiate_scenario("uncertain_action")[0]
        alert, _ = ingest(db, owner.id, payload)
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        action = db.scalar(select(Action).where(Action.tenant_id == owner.id))
        assert inv.status == "needs_review"
        assert action.status == "unknown"
        first_id = action.id
        evidence = db.scalars(select(Evidence).where(Evidence.tenant_id == owner.id,
            Evidence.investigation_id == inv.id)).all()
        resolved = perform_action(db, owner, inv, alert, "create_case", evidence)
        assert resolved.id == first_id
        assert resolved.status == "succeeded"
        assert db.scalar(select(func.count()).select_from(Action).where(Action.tenant_id == owner.id)) == 1
        assert db.scalar(select(func.count()).select_from(Case).where(Case.tenant_id == owner.id)) == 1
        case = db.scalar(select(Case).where(Case.tenant_id == owner.id))
        assert case.status == "open"
        assert case.data["evidence_ids"]
        assert case.data["tasks"]


def test_tenant_api_isolation_and_admin_policy():
    engine = database()
    with Session(engine) as db:
        first, second = tenant(db, "first"), tenant(db, "second")
        admin_user = User(tenant_id=first.id, username="first-admin", password_hash=hash_password("pw"), role="admin")
        analyst_user = User(tenant_id=second.id, username="second-analyst", password_hash=hash_password("pw"), role="analyst")
        db.add_all([admin_user, analyst_user])
        db.commit()
        payload = instantiate_scenario("root_unapproved")[0]
        alert, _ = ingest(db, first.id, payload)
        process_alert(db, alert.id)
        inv_id = alert.investigation_id
        admin_token, analyst_token = token_for(admin_user), token_for(analyst_user)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        assert client.get(f"/api/investigations/{inv_id}", headers=analyst_headers).status_code == 404
        assert client.get("/api/alerts", headers=analyst_headers).json()["items"] == []
        assert client.get("/api/alerts", headers=admin_headers).json()["total"] == 1
        assert client.patch("/api/settings", json={"automation_level": "observe"}, headers=analyst_headers).status_code == 403
        assert client.post("/api/exceptions", json={"entity": "x", "reason": "test",
            "valid_from": utcnow().isoformat(), "valid_until": (utcnow() + timedelta(hours=1)).isoformat()},
            headers=analyst_headers).status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_shift_requires_offset_and_stores_utc():
    engine = database()
    with Session(engine) as db:
        owner = tenant(db)
        user = User(tenant_id=owner.id, username="shift-analyst", password_hash=hash_password("pw"), role="analyst")
        db.add(user)
        db.commit()
        token = token_for(user)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {token}"}
        naive = {"starts_at": "2026-10-21T10:00:00", "ends_at": "2026-10-21T20:00:00",
                 "timezone": "Asia/Qyzylorda"}
        assert client.post("/api/shifts", json=naive, headers=headers).status_code == 422
        zoned = {"starts_at": "2026-10-21T10:00:00+05:00", "ends_at": "2026-10-21T20:00:00+05:00",
                 "timezone": "Asia/Qyzylorda"}
        result = client.post("/api/shifts", json=zoned, headers=headers)
        assert result.status_code == 200
        rows = client.get("/api/shifts", headers=headers).json()["items"]
        assert datetime.fromisoformat(rows[0]["starts_at"]).replace(tzinfo=timezone.utc).hour == 5
    finally:
        app.dependency_overrides.clear()


def test_connected_policy_is_read_only_without_explicit_write_enable(monkeypatch):
    from types import SimpleNamespace
    import app.workflow as workflow
    monkeypatch.setattr(workflow, "settings", lambda: SimpleNamespace(mode="CONNECTED", connected_writes_enabled=False,
                                                                      connected_allowed_actions="create_case,close_alert"))
    owner = Tenant(name="connected", deployment_mode="CONNECTED", automation_level="approved_response")
    assert not can_act(owner, "create_case")
    assert not can_act(owner, "close_alert")
