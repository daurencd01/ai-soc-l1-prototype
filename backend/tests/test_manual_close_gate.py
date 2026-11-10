"""A corrected analyst verdict cannot bypass a current FP close policy."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import (Action, Alert, Audit, Case, Decision, ExceptionRule, Investigation,
                        Maintenance, Tenant, User, utcnow)
from app.scenarios import instantiate_scenario
from app.security import hash_password, token_for
from app.workflow import ingest, process_alert


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
            db.add(ExceptionRule(tenant_id=tenant_id, rule="root_ssh", entity=raw["host"],
                                 reason="Проверенное исключение FP", scope=scope,
                                 approved_by="policy-approver", **window))
        else:
            # The playbook can still classify the event as FP from maintenance.
            # Manual closing additionally requires a current FP exception.
            db.add(Maintenance(tenant_id=tenant_id, title="Согласованная работа", entity=raw["host"],
                               reason="Администрирование", scope=scope, approved_by="admin", **window))
        db.commit()
        alert, _ = ingest(db, tenant_id, payload)
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        tenant = db.get(Tenant, tenant_id)
        tenant.automation_level = "approved_response"
        db.commit()
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
    inv_id = prepare(engine, ids["tenant"], policy=False)
    assert_denied(engine, ids["tenant"], close(client, ids["admin"], inv_id),
                  "no_current_approved_policy")


def test_manual_close_blocks_critical_alert_even_with_policy(site):
    engine, client, ids = site
    inv_id = prepare(engine, ids["tenant"])
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
    inv_id = prepare(engine, ids["tenant"])
    with Session(engine) as db:
        decision = db.scalar(select(Decision).where(Decision.investigation_id == inv_id))
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
    inv_id = prepare(engine, ids["tenant"])
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
