"""Durable and policy-gated updates of allowlisted TheHive case fields."""

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.workflow as workflow
from app.adapters import DemoTheHive
from app.db import Base
from app.models import Action, Case, Tenant
from app.scenarios import instantiate_scenario
from app.workflow import ingest, process_alert, reconcile_case_fields, update_case_fields


def setup_case():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="case-fields", deployment_mode="DEMO",
                        automation_level="approved_response")
        db.add(tenant)
        db.commit()
        alert, _ = ingest(db, tenant.id, instantiate_scenario("root_unapproved")[0])
        process_alert(db, alert.id)
        case = db.scalar(select(Case).where(Case.tenant_id == tenant.id))
        assert case and case.external_id and case.status == "open"
        return engine, tenant.id, case.id


def test_case_field_update_is_journaled_idempotent_and_scoped():
    engine, tenant_id, case_id = setup_case()
    with Session(engine) as db:
        tenant, case = db.get(Tenant, tenant_id), db.get(Case, case_id)
        first = update_case_fields(db, tenant, case, {"title": "SOC confirmed case"}, "admin")
        assert first.status == "succeeded"
        assert first.kind == "update_case_fields"
        assert first.detail["requested_fields"] == {"title": "SOC confirmed case"}
        assert case.title == "SOC confirmed case"
        assert DemoTheHive().case_fields(case.external_id, ["title"]) == {"title": "SOC confirmed case"}
        repeated = update_case_fields(db, tenant, case, {"title": "SOC confirmed case"}, "admin")
        assert repeated.id == first.id
        assert db.scalars(select(Action).where(Action.tenant_id == tenant_id,
            Action.kind == "update_case_fields")).all() == [first]
        DemoTheHive().update_case_fields(case.external_id, {"title": "changed externally"})
        with pytest.raises(ValueError, match="сверка"):
            update_case_fields(db, tenant, case, {"title": "SOC confirmed case again"}, "admin")


def test_case_field_timeout_after_write_reconciles_without_replaying_patch(monkeypatch):
    engine, tenant_id, case_id = setup_case()

    class LostResponseHive(DemoTheHive):
        def __init__(self):
            self.write_calls = 0

        def update_case_fields(self, external_id, changes):
            self.write_calls += 1
            super().update_case_fields(external_id, changes)
            raise httpx.ReadTimeout("response lost after PATCH")

    hive = LostResponseHive()
    monkeypatch.setattr(workflow, "thehive_adapter", lambda: hive)
    with Session(engine) as db:
        tenant, case = db.get(Tenant, tenant_id), db.get(Case, case_id)
        action = update_case_fields(db, tenant, case, {"title": "Pending readback"}, "admin")
        assert action.status == "unknown"
        assert hive.write_calls == 1
        assert update_case_fields(db, tenant, case, {"title": "Pending readback"}, "admin").id == action.id
        assert hive.write_calls == 1
        reconciled = reconcile_case_fields(db, tenant, action, case, "admin")
        assert reconciled.status == "succeeded"
        assert case.title == "Pending readback"
        assert case.data["fields_revision"] == 1
        assert hive.write_calls == 1


def test_negative_field_readback_leaves_unknown_and_blocks_next_update(monkeypatch):
    engine, tenant_id, case_id = setup_case()

    class TimeoutBeforeWriteHive(DemoTheHive):
        def __init__(self):
            self.write_calls = 0

        def update_case_fields(self, external_id, changes):
            self.write_calls += 1
            raise httpx.ReadTimeout("PATCH not confirmed")

    hive = TimeoutBeforeWriteHive()
    monkeypatch.setattr(workflow, "thehive_adapter", lambda: hive)
    with Session(engine) as db:
        tenant, case = db.get(Tenant, tenant_id), db.get(Case, case_id)
        action = update_case_fields(db, tenant, case, {"title": "Unconfirmed"}, "admin")
        assert action.status == "unknown"
        assert reconcile_case_fields(db, tenant, action, case, "admin").status == "unknown"
        with pytest.raises(ValueError, match="предыдущее действие"):
            update_case_fields(db, tenant, case, {"title": "Another"}, "admin")
        assert hive.write_calls == 1


def test_case_field_update_requires_policy_and_exact_case_link(monkeypatch):
    engine, tenant_id, case_id = setup_case()
    with Session(engine) as db:
        tenant, case = db.get(Tenant, tenant_id), db.get(Case, case_id)
        tenant.automation_level = "observe"
        db.commit()
        assert update_case_fields(db, tenant, case, {"title": "Denied"}, "admin") is None
        tenant.automation_level = "approved_response"
        db.commit()

        class WrongLinkHive(DemoTheHive):
            def find_case(self, key):
                return "~unrelated-case"

        monkeypatch.setattr(workflow, "thehive_adapter", WrongLinkHive)
        with pytest.raises(ValueError, match="Связь кейса"):
            update_case_fields(db, tenant, case, {"title": "Denied"}, "admin")
        assert not db.scalars(select(Action).where(Action.kind == "update_case_fields")).all()
