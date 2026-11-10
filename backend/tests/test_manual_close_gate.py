"""A corrected analyst verdict cannot bypass a current FP close policy."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
import app.main as main_module
from app.metrics import metric_snapshot
from app.models import (Action, Alert, Audit, Case, Decision, ExceptionRule, Investigation,
                        Maintenance, PolicyEvent, Tenant, User, utcnow)
from app.scenarios import instantiate_scenario
from app.security import hash_password, token_for
from app.workflow import ingest, process_alert
import app.workflow as workflow


@pytest.fixture
def site():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="manual-close-test", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        admin = User(tenant_id=tenant.id, username="manual-close-admin", password_hash=hash_password("pw"), role="admin")
        analyst = User(tenant_id=tenant.id, username="manual-close-analyst", password_hash=hash_password("pw"), role="analyst")
        db.add_all([admin, analyst])
        db.commit()
        ids = {"tenant": tenant.id, "admin": token_for(admin), "analyst": token_for(analyst)}

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield engine, TestClient(app), ids
    finally:
        app.dependency_overrides.clear()


def prepare(engine, tenant_id: str, *, scenario: str = "root_approved", policy: bool = True) -> str:
    payload = instantiate_scenario(scenario)[0]
    raw = payload["raw"]
    with Session(engine) as db:
        scope = {key: raw[key] for key in ("host", "src_ip", "auth_method")}
        window = {"valid_from": utcnow() - timedelta(hours=1),
                  "valid_until": utcnow() + timedelta(hours=1)}
        if policy:
            row = ExceptionRule(tenant_id=tenant_id, rule="root_ssh", entity=raw["host"],
                                owner="SOC", created_by="policy-admin", reason="Проверенное исключение FP",
                                scope=scope, approval_status="approved", approved_by="policy-approver",
                                approved_at=utcnow(), **window)
            db.add(row)
            db.flush()
            db.add(PolicyEvent(tenant_id=tenant_id, policy_id=row.id, actor="policy-approver",
                               event_type="approved", from_status="draft", to_status="approved"))
            db.add(Audit(tenant_id=tenant_id, actor="policy-approver", operation="exception_approved",
                         subject_type="exception", subject_id=row.id))
        else:
            # The playbook can still classify the event as FP from maintenance.
            # Manual closing additionally requires a current FP exception.
            db.add(Maintenance(tenant_id=tenant_id, title="Согласованная работа", entity=raw["host"],
                               reason="Администрирование", scope=scope, approved_by="admin", **window))
        db.commit()
        alert, _ = ingest(db, tenant_id, payload)
        tenant = db.get(Tenant, tenant_id)
        tenant.automation_level = "approved_response"
        db.commit()
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        return inv.id


def close(client: TestClient, token: str, investigation_id: str):
    return client.post(f"/api/investigations/{investigation_id}/actions/close_alert",
                       headers={"Authorization": f"Bearer {token}"})


def assert_denied(engine, tenant_id: str, result, expected_code: str):
    assert result.status_code == 409, result.text
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.tenant_id == tenant_id, Action.kind == "close_alert")) == 0
        audit = db.scalar(select(Audit).where(Audit.tenant_id == tenant_id,
            Audit.operation == "manual_close_denied").order_by(Audit.created_at.desc()).limit(1))
        assert audit and audit.detail["reason"] == expected_code


def test_manual_close_requires_current_approved_fp_policy(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive", policy=False)
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id),
                  "no_current_approved_policy")


def test_manual_close_blocks_critical_alert_even_with_policy(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        alert = db.scalar(select(Alert).where(Alert.investigation_id == inv_id))
        alert.severity = "critical"
        db.commit()
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id),
                  "critical_or_unknown_severity")


def test_manual_close_blocks_linked_case_even_after_verdict_correction(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"])
    review = client.post(f"/api/investigations/{inv_id}/review",
        headers={"Authorization": f"Bearer {ids['analyst']}"},
        json={"verdict": "false_positive", "note": "Проверено аналитиком"})
    assert review.status_code == 200
    with Session(engine) as db:
        db.add(Case(tenant_id=ids["tenant"], investigation_id=inv_id,
                    title="Активный инцидент", external_id="demo-case:active", status="Open"))
        db.commit()
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id), "case_exists")


def test_manual_close_blocks_missing_decision_evidence(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        decision = db.scalar(select(Decision).where(Decision.investigation_id == inv_id)
                             .order_by(Decision.created_at.desc(), Decision.id.desc()).limit(1))
        decision.evidence_ids = []
        db.commit()
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id), "insufficient_evidence")


def test_verdict_correction_cannot_override_inconclusive_playbook(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_missing_context")
    review = client.post(f"/api/investigations/{inv_id}/review",
        headers={"Authorization": f"Bearer {ids['analyst']}"},
        json={"verdict": "false_positive", "note": "Считаю ложным срабатыванием"})
    assert review.status_code == 200
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id), "deterministic_rule")


def test_manual_close_policy_must_still_be_valid_and_success_is_idempotent(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        policy = db.scalar(select(ExceptionRule).where(ExceptionRule.tenant_id == ids["tenant"]))
        policy.valid_until = utcnow() - timedelta(minutes=1)
        db.commit()
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id),
                  "no_current_approved_policy")
    with Session(engine) as db:
        policy = db.scalar(select(ExceptionRule).where(ExceptionRule.tenant_id == ids["tenant"]))
        policy.valid_until = utcnow() + timedelta(hours=1)
        db.commit()
    first = close(client, ids["admin"], inv_id)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "succeeded"
    second = close(client, ids["admin"], inv_id)
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.tenant_id == ids["tenant"], Action.kind == "close_alert")) == 1
        grant = db.scalar(select(Audit).where(Audit.operation == "manual_close_granted").limit(1))
        assert grant and grant.detail["policy_ids"] and grant.detail["decision_id"]


def test_real_fp_detection_can_close_with_current_approved_policy(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        inv = db.get(Investigation, inv_id)
        assert inv.classification == "FP"
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.investigation_id == inv_id, Action.kind == "close_alert")) == 0
        decision = db.scalar(select(Decision).where(Decision.investigation_id == inv_id))
        assert decision.evidence_against and decision.evidence_against[0]["evidence_id"]
    result = close(client, ids["admin"], inv_id)
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "succeeded"
    with Session(engine) as db:
        inv = db.get(Investigation, inv_id)
        alert = db.scalar(select(Alert).where(Alert.investigation_id == inv_id))
        assert inv.status == "closed" and alert.status == "closed"
        assert alert.pipeline_state == "CLOSED_FP"
        assert metric_snapshot(db, ids["tenant"])["auto_close_attempts_total"] == 0


def test_multiple_linked_alerts_cannot_be_closed_as_one(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        original = db.scalar(select(Alert).where(Alert.investigation_id == inv_id))
        db.add(Alert(tenant_id=ids["tenant"], investigation_id=inv_id,
                     source=original.source, source_event_id="another-linked-event",
                     rule=original.rule, title=original.title, severity=original.severity,
                     status="needs_review", pipeline_state="NEEDS_REVIEW",
                     event_at=original.event_at, raw=original.raw))
        db.commit()
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id),
                  "multiple_linked_alerts")


def test_unknown_close_reconciliation_uses_original_alert(site, monkeypatch):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        original = db.scalar(select(Alert).where(Alert.investigation_id == inv_id))
        linked = Alert(tenant_id=ids["tenant"], investigation_id=inv_id,
                       source=original.source, source_event_id="second-source-event",
                       rule=original.rule, title=original.title, severity=original.severity,
                       status="needs_review", pipeline_state="NEEDS_REVIEW",
                       event_at=original.event_at, raw=original.raw)
        db.add(linked)
        db.flush()
        action = Action(tenant_id=ids["tenant"], investigation_id=inv_id,
                        kind="close_alert", status="unknown", target=linked.source_event_id,
                        idempotency_key=f"{inv_id}:close_alert:{linked.id}")
        db.add(action)
        db.commit()
        action_id, linked_id = action.id, linked.id
    seen = []

    def capture_action(db, tenant, investigation, alert, kind, evidence):
        seen.append(alert.id)
        return db.get(Action, action_id)

    monkeypatch.setattr(main_module, "perform_action", capture_action)
    headers = {"Authorization": f"Bearer {ids['admin']}"}
    response = client.post(f"/api/actions/{action_id}/reconcile", headers=headers)
    assert response.status_code == 200, response.text
    assert seen == [linked_id]
    with Session(engine) as db:
        action = db.get(Action, action_id)
        action.target = "mismatched-source-event"
        db.commit()
    rejected = client.post(f"/api/actions/{action_id}/reconcile", headers=headers)
    assert rejected.status_code == 409
    assert seen == [linked_id]


def test_real_fp_auto_close_requires_global_flag(site, monkeypatch):
    engine, _, ids = site
    monkeypatch.setattr(workflow.settings(), "auto_close_enabled", True)
    inv_id = prepare(engine, ids["tenant"], scenario="root_parser_false_positive")
    with Session(engine) as db:
        inv = db.get(Investigation, inv_id)
        alert = db.scalar(select(Alert).where(Alert.investigation_id == inv_id))
        assert inv.classification == "FP" and alert.pipeline_state == "CLOSED_FP"
        actions = db.scalars(select(Action).where(Action.investigation_id == inv_id,
                                                  Action.kind == "close_alert")).all()
        assert len(actions) == 1 and actions[0].status == "succeeded"
        markers = db.scalars(select(Audit).where(Audit.tenant_id == ids["tenant"],
            Audit.operation == "auto_close_attempted", Audit.subject_id == actions[0].id)).all()
        assert len(markers) == 1
        assert metric_snapshot(db, ids["tenant"])["auto_close_attempts_total"] == 1
