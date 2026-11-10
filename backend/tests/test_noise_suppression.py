"""A separate approved policy can group confirmed NOISE without an external close."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import (Action, Alert, Asset, Audit, Case, Investigation, Maintenance,
                        PipelineTransition, SuppressionEvent, SuppressionRule, Tenant, User, utcnow)
from app.scenarios import instantiate_scenario
from app.security import hash_password, token_for
from app.suppression import is_effective
from app.workflow import ingest, process_alert


@pytest.fixture
def site():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="noise-test", deployment_mode="DEMO", automation_level="controlled_automation")
        other = Tenant(name="other-noise-test", deployment_mode="DEMO", automation_level="observe")
        db.add_all([tenant, other])
        db.flush()
        users = {
            "admin": User(tenant_id=tenant.id, username="noise-admin", password_hash=hash_password("password-1234"), role="admin"),
            "approver": User(tenant_id=tenant.id, username="noise-approver", password_hash=hash_password("password-1234"), role="policy_approver"),
            "analyst": User(tenant_id=tenant.id, username="noise-analyst", password_hash=hash_password("password-1234"), role="analyst"),
            "viewer": User(tenant_id=tenant.id, username="noise-viewer", password_hash=hash_password("password-1234"), role="viewer"),
            "other": User(tenant_id=other.id, username="noise-other", password_hash=hash_password("password-1234"), role="policy_approver"),
        }
        db.add_all(users.values())
        db.commit()
        tokens = {name: token_for(row) for name, row in users.items()}
        tenant_id = tenant.id

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield engine, TestClient(app), tenant_id, tokens
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def proposal() -> dict:
    return {"rule": "ipsec_failure", "entity": "192.0.2.11", "owner": "Network SOC",
            "reason": "Repeated proposal mismatch during approved peer maintenance",
            "scope": {"peer": "192.0.2.11", "device": "demo-vpn-gw-02",
                      "tunnel": "demo-s2s-backup", "failure_reason": "proposal_mismatch"},
            "valid_from": (utcnow() - timedelta(hours=1)).isoformat(),
            "valid_until": (utcnow() + timedelta(hours=1)).isoformat()}


def approved_policy(client: TestClient, tokens: dict) -> dict:
    draft = client.post("/api/suppression-policies", json=proposal(), headers=headers(tokens["admin"]))
    assert draft.status_code == 200, draft.text
    policy = client.post(f"/api/suppression-policies/{draft.json()['id']}/approve",
                         headers=headers(tokens["approver"]))
    assert policy.status_code == 200, policy.text
    return policy.json()


def prepare_alert(engine, tenant_id: str, *, severity: str = "medium", signal: str | None = None) -> str:
    payload = instantiate_scenario("ipsec_configuration_failure")[0]
    payload["severity"] = severity
    if signal:
        payload["raw"]["scenario_signal"] = signal
    raw = payload["raw"]
    with Session(engine) as db:
        if not db.scalar(select(Asset).where(Asset.tenant_id == tenant_id,
                                              Asset.kind == "vpn_peer", Asset.value == raw["peer"])):
            db.add(Asset(tenant_id=tenant_id, kind="vpn_peer", value=raw["peer"], owner="Network SOC",
                         criticality="medium", attributes={"allowed": True, "tunnel": raw["tunnel"],
                                                           "device": raw["device"]}))
        db.add(Maintenance(tenant_id=tenant_id, title="Peer proposal test", entity=raw["peer"],
                           reason="Approved configuration check",
                           scope={key: raw[key] for key in ("peer", "device", "tunnel")},
                           valid_from=utcnow() - timedelta(hours=1),
                           valid_until=utcnow() + timedelta(hours=1), approved_by="network-admin"))
        db.commit()
        alert, _ = ingest(db, tenant_id, payload)
        return alert.id


def test_noise_suppression_requires_approved_policy_and_never_closes_external_alert(site):
    engine, client, tenant_id, tokens = site
    policy = approved_policy(client, tokens)
    alert_id = prepare_alert(engine, tenant_id)
    with Session(engine) as db:
        process_alert(db, alert_id)
        alert = db.get(Alert, alert_id)
        inv = db.get(Investigation, alert.investigation_id)
        assert inv.classification == "NOISE" and inv.verdict == "needs_review"
        assert alert.pipeline_state == "SUPPRESSED" and alert.status == "suppressed"
        actions = db.scalars(select(Action).where(Action.tenant_id == tenant_id)).all()
        assert len(actions) == 1 and actions[0].kind == "suppress_noise"
        assert actions[0].status == "succeeded" and actions[0].detail["policy_id"] == policy["id"]
        assert actions[0].external_id is None
        assert db.scalar(select(func.count()).select_from(Case).where(Case.tenant_id == tenant_id)) == 0
        assert db.scalar(select(Audit).where(Audit.operation == "noise_suppressed",
                                             Audit.subject_id == actions[0].id))
        assert db.scalar(select(PipelineTransition).where(PipelineTransition.alert_id == alert_id,
            PipelineTransition.to_state == "SUPPRESSED"))
        process_alert(db, alert_id)
        assert db.scalar(select(func.count()).select_from(Action).where(Action.tenant_id == tenant_id)) == 1
    metrics = client.get("/api/metrics", headers=headers(tokens["admin"]))
    assert metrics.status_code == 200 and metrics.json()["cases_suppressed_total"] == 1


def test_noise_without_policy_stays_reviewable_and_audits_denial(site):
    engine, _, tenant_id, _ = site
    alert_id = prepare_alert(engine, tenant_id)
    with Session(engine) as db:
        process_alert(db, alert_id)
        alert = db.get(Alert, alert_id)
        assert db.get(Investigation, alert.investigation_id).classification == "NOISE"
        assert alert.pipeline_state == "NEEDS_REVIEW"
        assert db.scalar(select(func.count()).select_from(Action).where(Action.tenant_id == tenant_id)) == 0
        denied = db.scalar(select(Audit).where(Audit.operation == "noise_suppression_denied"))
        assert denied and denied.detail["reason"] == "no_current_approved_policy"


def test_repeated_noise_uses_one_stable_group_key_without_cases(site):
    engine, client, tenant_id, tokens = site
    approved_policy(client, tokens)
    first_id = prepare_alert(engine, tenant_id)
    second_id = prepare_alert(engine, tenant_id)
    with Session(engine) as db:
        process_alert(db, first_id)
        process_alert(db, second_id)
        actions = db.scalars(select(Action).where(Action.tenant_id == tenant_id,
            Action.kind == "suppress_noise").order_by(Action.target)).all()
        assert len(actions) == 2
        assert actions[0].detail["group_key"] == actions[1].detail["group_key"]
        assert actions[0].idempotency_key != actions[1].idempotency_key
        assert db.scalar(select(func.count()).select_from(Case).where(Case.tenant_id == tenant_id)) == 0


def test_unavailable_splunk_cannot_suppress_noise(site):
    engine, client, tenant_id, tokens = site
    approved_policy(client, tokens)
    alert_id = prepare_alert(engine, tenant_id, signal="splunk_unavailable")
    with Session(engine) as db:
        process_alert(db, alert_id)
        alert = db.get(Alert, alert_id)
        assert alert.pipeline_state == "NEEDS_REVIEW"
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.tenant_id == tenant_id, Action.kind == "suppress_noise")) == 0
        assert db.scalar(select(Audit).where(Audit.tenant_id == tenant_id,
                                             Audit.operation == "integration_error"))


def test_linked_alert_with_different_failure_reason_blocks_grouping(site):
    engine, client, tenant_id, tokens = site
    approved_policy(client, tokens)
    first_id = prepare_alert(engine, tenant_id)
    with Session(engine) as db:
        first = db.get(Alert, first_id)
        inv = db.get(Investigation, first.investigation_id)
        # Simulate a legacy linked record created before the ingest guard existed.
        # New ingestion correctly refuses to merge this conflicting alert.
        raw = dict(first.raw, failure_reason="timeout")
        second = Alert(tenant_id=tenant_id, investigation_id=inv.id,
                       source=first.source, source_event_id="legacy-conflicting-alert",
                       rule=first.rule, title=first.title, severity=first.severity,
                       event_at=first.event_at, original_timezone=first.original_timezone,
                       raw=raw)
        db.add(second)
        db.commit()
        assert second.investigation_id == inv.id
        process_alert(db, first_id)
        assert db.get(Alert, first_id).pipeline_state == "NEEDS_REVIEW"
        denied = db.scalar(select(Audit).where(Audit.operation == "noise_suppression_denied"))
        assert denied and denied.detail["reason"] == "linked_alert_conflict"


@pytest.mark.parametrize("blocker,reason", [
    ("critical", "critical_or_unknown_severity"),
    ("case", "case_exists"),
    ("revoke", "no_current_approved_policy"),
    ("missing_receipt", "no_current_approved_policy"),
])
def test_noise_gate_denies_unsafe_state(site, blocker, reason):
    engine, client, tenant_id, tokens = site
    policy = approved_policy(client, tokens)
    alert_id = prepare_alert(engine, tenant_id, severity="critical" if blocker == "critical" else "medium")
    with Session(engine) as db:
        alert = db.get(Alert, alert_id)
        if blocker == "case":
            db.add(Case(tenant_id=tenant_id, investigation_id=alert.investigation_id,
                        title="Active incident", external_id="hive-case:existing", status="Open"))
        elif blocker == "missing_receipt":
            receipt = db.scalar(select(Audit).where(Audit.operation == "suppression_approved",
                                                    Audit.subject_id == policy["id"]))
            db.delete(receipt)
        db.commit()
    if blocker == "revoke":
        result = client.post(f"/api/suppression-policies/{policy['id']}/revoke",
                             json={"reason": "Configuration changed, stop grouping"},
                             headers=headers(tokens["admin"]))
        assert result.status_code == 200
    with Session(engine) as db:
        process_alert(db, alert_id)
        alert = db.get(Alert, alert_id)
        assert alert.pipeline_state == "NEEDS_REVIEW"
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.tenant_id == tenant_id, Action.kind == "suppress_noise")) == 0
        denied = db.scalar(select(Audit).where(Audit.operation == "noise_suppression_denied"))
        assert denied and denied.detail["reason"] == reason


def test_noise_suppression_policy_versions_roles_and_revocation(site):
    engine, client, _, tokens = site
    create = client.post("/api/suppression-policies", json=proposal(), headers=headers(tokens["admin"]))
    assert create.status_code == 200 and create.json()["approval_status"] == "draft"
    first = create.json()
    assert client.post(f"/api/suppression-policies/{first['id']}/approve",
                       headers=headers(tokens["admin"])).status_code == 403
    assert client.post(f"/api/suppression-policies/{first['id']}/approve",
                       headers=headers(tokens["analyst"])).status_code == 403
    assert client.post(f"/api/suppression-policies/{first['id']}/approve",
                       headers=headers(tokens["other"])).status_code == 404
    assert client.post("/api/suppression-policies", json=proposal(),
                       headers=headers(tokens["viewer"])).status_code == 403
    bad = client.post("/api/suppression-policies", json={**proposal(), "scope": {"peer": "192.0.2.11"}},
                      headers=headers(tokens["admin"])).json()
    rejected = client.post(f"/api/suppression-policies/{bad['id']}/approve",
                           headers=headers(tokens["approver"]))
    assert rejected.status_code == 409 and "invalid_scope" in rejected.text
    assert client.post(f"/api/suppression-policies/{first['id']}/approve",
                       headers=headers(tokens["approver"])).status_code == 200
    with Session(engine) as db:
        row = db.get(SuppressionRule, first["id"])
        assert is_effective(db, row, proposal()["scope"], utcnow())
        assert not is_effective(db, row, proposal()["scope"], row.approved_at - timedelta(seconds=1))
    changed = {**proposal(), "scope": {**proposal()["scope"], "failure_reason": "timeout"},
               "change_reason": "New failure pattern after maintenance"}
    second = client.post(f"/api/suppression-policies/{first['id']}/versions", json=changed,
                         headers=headers(tokens["admin"]))
    assert second.status_code == 200 and second.json()["version"] == 2
    assert client.post(f"/api/suppression-policies/{second.json()['id']}/approve",
                       headers=headers(tokens["approver"])).status_code == 200
    with Session(engine) as db:
        old, new = db.get(SuppressionRule, first["id"]), db.get(SuppressionRule, second.json()["id"])
        assert old.approval_status == "superseded" and not is_effective(db, old, proposal()["scope"], utcnow())
        assert is_effective(db, new, changed["scope"], utcnow())
        assert db.scalar(select(SuppressionEvent).where(SuppressionEvent.policy_id == new.id,
                                                       SuppressionEvent.event_type == "approved"))
    history = client.get(f"/api/suppression-policies/{first['id']}/history",
                         headers=headers(tokens["viewer"]))
    assert history.status_code == 200 and len(history.json()["versions"]) == 2
    assert "superseded" in [item["event_type"] for item in history.json()["events"]]
    revoked = client.post(f"/api/suppression-policies/{second.json()['id']}/revoke",
                          json={"reason": "Peer maintenance has ended"}, headers=headers(tokens["admin"]))
    assert revoked.status_code == 200
    with Session(engine) as db:
        assert not is_effective(db, db.get(SuppressionRule, second.json()["id"]), changed["scope"], utcnow())


def test_analyst_can_reverse_local_suppression_without_external_close(site):
    engine, client, tenant_id, tokens = site
    approved_policy(client, tokens)
    alert_id = prepare_alert(engine, tenant_id)
    with Session(engine) as db:
        process_alert(db, alert_id)
        inv_id = db.get(Alert, alert_id).investigation_id
    corrected = client.post(f"/api/investigations/{inv_id}/review",
                            json={"classification": "INCONCLUSIVE", "note": "Проверить новый контекст"},
                            headers=headers(tokens["analyst"]))
    assert corrected.status_code == 200
    with Session(engine) as db:
        alert = db.get(Alert, alert_id)
        assert alert.pipeline_state == "NEEDS_REVIEW" and alert.status == "needs_review"
        assert db.scalar(select(func.count()).select_from(Action).where(
            Action.investigation_id == inv_id, Action.kind == "close_alert")) == 0
