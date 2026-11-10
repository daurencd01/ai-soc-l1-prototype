"""FP policies need independent human approval, version history and revocation."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Audit, ExceptionRule, PolicyEvent, Tenant, User, utcnow
from app.policy import is_effective
from app.security import hash_password, token_for


@pytest.fixture
def site():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="policy-test", deployment_mode="DEMO", automation_level="observe")
        other = Tenant(name="other-policy-test", deployment_mode="DEMO", automation_level="observe")
        db.add_all([tenant, other])
        db.flush()
        users = {
            "admin": User(tenant_id=tenant.id, username="policy-admin", password_hash=hash_password("password-1234"), role="admin"),
            "analyst": User(tenant_id=tenant.id, username="policy-analyst", password_hash=hash_password("password-1234"), role="analyst"),
            "viewer": User(tenant_id=tenant.id, username="policy-viewer", password_hash=hash_password("password-1234"), role="viewer"),
            "approver": User(tenant_id=tenant.id, username="policy-approver", password_hash=hash_password("password-1234"), role="policy_approver"),
            "other": User(tenant_id=other.id, username="other-approver", password_hash=hash_password("password-1234"), role="policy_approver"),
        }
        db.add_all(users.values())
        db.commit()
        tokens = {name: token_for(row) for name, row in users.items()}

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield engine, TestClient(app), tokens
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def proposal(*, src_ip: str = "198.51.100.10", rule: str = "root_ssh") -> dict:
    return {"rule": rule, "entity": "srv01", "owner": "SOC Operations",
            "reason": "Approved maintenance fingerprint for a bounded host and source",
            "scope": {"host": "srv01", "src_ip": src_ip, "auth_method": "publickey"},
            "valid_from": (utcnow() - timedelta(hours=1)).isoformat(),
            "valid_until": (utcnow() + timedelta(hours=2)).isoformat()}


def test_draft_requires_distinct_approver_and_receipt_then_revocation(site):
    engine, client, tokens = site
    create = client.post("/api/exceptions", json=proposal(), headers=headers(tokens["admin"]))
    assert create.status_code == 200, create.text
    row = create.json()
    assert row["approval_status"] == "draft" and row["version"] == 1
    assert row["approved_by"] == ""
    policy_id = row["id"]
    assert client.post(f"/api/exceptions/{policy_id}/approve", headers=headers(tokens["analyst"])).status_code == 403
    assert client.post(f"/api/exceptions/{policy_id}/approve", headers=headers(tokens["admin"])).status_code == 403
    assert client.post(f"/api/exceptions/{policy_id}/approve", headers=headers(tokens["other"])).status_code == 404
    with Session(engine) as db:
        policy = db.get(ExceptionRule, policy_id)
        raw = {"host": "srv01", "src_ip": "198.51.100.10", "auth_method": "publickey"}
        assert not is_effective(db, policy, raw, utcnow())
    approval = client.post(f"/api/exceptions/{policy_id}/approve", headers=headers(tokens["approver"]))
    assert approval.status_code == 200, approval.text
    assert approval.json()["approval_status"] == "approved"
    with Session(engine) as db:
        policy = db.get(ExceptionRule, policy_id)
        assert is_effective(db, policy, raw, utcnow())
        assert not is_effective(db, policy, {**raw, "src_ip": "198.51.100.11"}, utcnow())
        assert db.scalar(select(PolicyEvent).where(PolicyEvent.policy_id == policy_id,
                                                PolicyEvent.event_type == "approved"))
        assert db.scalar(select(Audit).where(Audit.operation == "exception_approved",
                                          Audit.subject_id == policy_id))
    assert client.post(f"/api/exceptions/{policy_id}/revoke", json={"reason": "            "},
                       headers=headers(tokens["admin"])).status_code == 422
    revoked = client.post(f"/api/exceptions/{policy_id}/revoke",
                          json={"reason": "Source is no longer permitted"}, headers=headers(tokens["admin"]))
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["approval_status"] == "revoked"
    with Session(engine) as db:
        assert not is_effective(db, db.get(ExceptionRule, policy_id), raw, utcnow())
    history = client.get(f"/api/exceptions/{policy_id}/history", headers=headers(tokens["viewer"]))
    assert history.status_code == 200
    assert [x["event_type"] for x in history.json()["events"]] == ["proposed", "approved", "revoked"]
    assert client.post(f"/api/exceptions/{policy_id}/approve", headers=headers(tokens["approver"])).status_code == 409


def test_approving_new_version_supersedes_old_version(site):
    engine, client, tokens = site
    first = client.post("/api/exceptions", json=proposal(), headers=headers(tokens["admin"])).json()
    assert client.post(f"/api/exceptions/{first['id']}/approve", headers=headers(tokens["approver"])).status_code == 200
    changed = {**proposal(src_ip="198.51.100.12"), "change_reason": "Source moved after approved maintenance"}
    second = client.post(f"/api/exceptions/{first['id']}/versions", json=changed,
                         headers=headers(tokens["admin"]))
    assert second.status_code == 200, second.text
    assert second.json()["policy_key"] == first["policy_key"] and second.json()["version"] == 2
    assert client.post(f"/api/exceptions/{second.json()['id']}/approve",
                       headers=headers(tokens["approver"])).status_code == 200
    with Session(engine) as db:
        old, new = db.get(ExceptionRule, first["id"]), db.get(ExceptionRule, second.json()["id"])
        assert old.approval_status == "superseded" and new.approval_status == "approved"
        assert not is_effective(db, old, proposal()["scope"], utcnow())
        assert is_effective(db, new, changed["scope"], utcnow())
    history = client.get(f"/api/exceptions/{first['id']}/history", headers=headers(tokens["viewer"])).json()
    assert [x["version"] for x in history["versions"]] == [1, 2]
    assert "superseded" in [x["event_type"] for x in history["events"]]


def test_policy_approver_cannot_approve_own_policy_or_invalid_contract(site):
    engine, client, tokens = site
    draft = client.post("/api/exceptions", json=proposal(rule="*"), headers=headers(tokens["admin"])).json()
    denied = client.post(f"/api/exceptions/{draft['id']}/approve", headers=headers(tokens["approver"]))
    assert denied.status_code == 409 and "rule_not_allowlisted" in denied.text
    proper = client.post("/api/exceptions", json=proposal(), headers=headers(tokens["admin"])).json()
    with Session(engine) as db:
        row = db.get(ExceptionRule, proper["id"])
        row.created_by = "policy-approver"
        db.commit()
    assert client.post(f"/api/exceptions/{proper['id']}/approve",
                       headers=headers(tokens["approver"])).status_code == 403
    with Session(engine) as db:
        row = db.get(ExceptionRule, proper["id"])
        row.approval_status = "approved"
        row.approved_by = "policy-approver"
        row.approved_at = utcnow()
        db.commit()
        assert not is_effective(db, row, proposal()["scope"], utcnow())


def test_missing_approval_audit_receipt_denies_policy(site):
    engine, client, tokens = site
    draft = client.post("/api/exceptions", json=proposal(), headers=headers(tokens["admin"])).json()
    assert client.post(f"/api/exceptions/{draft['id']}/approve",
                       headers=headers(tokens["approver"])).status_code == 200
    with Session(engine) as db:
        row = db.get(ExceptionRule, draft["id"])
        receipt = db.scalar(select(Audit).where(Audit.operation == "exception_approved",
                                                Audit.subject_id == row.id))
        assert receipt is not None
        db.delete(receipt)
        db.commit()
        assert not is_effective(db, row, proposal()["scope"], utcnow())


def test_viewer_is_read_only_and_admin_can_provision_approver(site):
    _, client, tokens = site
    viewer = headers(tokens["viewer"])
    assert client.get("/api/dashboard", headers=viewer).status_code == 200
    assert client.post("/api/exceptions", json=proposal(), headers=viewer).status_code == 403
    assert client.post("/api/shifts", json={}, headers=viewer).status_code == 403
    assert client.post("/api/scenarios/root_unapproved/run", headers=viewer).status_code == 403
    assert client.post("/api/users", json={"username": "new-approver", "password": "long-password-123",
                                                 "role": "policy_approver"}, headers=viewer).status_code == 403
    created = client.post("/api/users", json={"username": "new-approver", "password": "long-password-123",
                                            "role": "policy_approver"}, headers=headers(tokens["admin"]))
    assert created.status_code == 200, created.text
    assert "password" not in created.json()
    assert client.get("/api/users", headers=headers(tokens["analyst"])).status_code == 403
    assert client.post(f"/api/users/{created.json()['id']}/deactivate",
                       headers=headers(tokens["admin"])).json()["active"] is False
