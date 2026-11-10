"""TheHive mutations have a durable journal and ambiguous outcomes never replay blindly."""
import httpx
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Action, Alert, Audit, Case, CaseWrite, Decision, Evidence, Investigation, Tenant
from app.scenarios import instantiate_scenario
from app.workflow import ingest, perform_action, process_alert
import app.workflow as workflow


class HiveDouble:
    def __init__(self, fail_kind: str | None = None, fail_mode: str | None = None):
        self.fail_kind, self.fail_mode = fail_kind, fail_mode
        self.created: dict[str, str] = {}
        self.steps: dict[str, str] = {}
        self.create_calls = 0
        self.write_calls: list[str] = []
        self.read_calls: list[str] = []

    def create_case(self, title, description, key, **metadata):
        self.create_calls += 1
        assert metadata["severity"] in {1, 2, 3, 4}
        assert metadata["tags"] and metadata["start_date"] <= metadata["end_date"]
        self.created[key] = "hive-case-1"
        if self.fail_kind == "create_case" and self.fail_mode == "ambiguous":
            self.fail_kind = None
            raise httpx.ReadTimeout("response lost after case creation")
        return self.created[key]

    def find_case(self, key):
        return self.created.get(key)

    def write_case_step(self, case_id, kind, payload, key):
        self.write_calls.append(kind)
        if self.fail_kind == kind and self.fail_mode == "timeout_after_write":
            self.fail_kind = None
            self.steps[key] = f"hive-{kind}-1"
            raise httpx.ReadTimeout("response lost after mutation")
        if self.fail_kind == kind and self.fail_mode == "timeout_before_write":
            self.fail_kind = None
            raise httpx.ReadTimeout("request outcome unconfirmed")
        if self.fail_kind == kind and self.fail_mode == "rejected":
            self.fail_kind = None
            request = httpx.Request("POST", "https://thehive.invalid/api/v1/case/step")
            response = httpx.Response(400, request=request)
            raise httpx.HTTPStatusError("rejected", request=request, response=response)
        self.steps[key] = f"hive-{kind}-{len(self.steps) + 1}"
        return self.steps[key]

    def find_case_step(self, case_id, kind, payload, key):
        self.read_calls.append(kind)
        return self.steps.get(key)


def setup(monkeypatch, hive, *, observable: bool = False):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(workflow, "thehive_adapter", lambda: hive)
    with Session(engine) as db:
        tenant = Tenant(name="case-write-test", deployment_mode="DEMO", automation_level="auto_close")
        db.add(tenant)
        db.commit()
        alert, _ = ingest(db, tenant.id, instantiate_scenario("root_unapproved")[0])
        if observable:
            db.add(Evidence(tenant_id=tenant.id, investigation_id=alert.investigation_id,
                            kind="observable", source="test", summary="IP источника",
                            data={"observable_type": "ip", "observable": "203.0.113.41"}))
            db.commit()
        process_alert(db, alert.id)
        return engine, tenant.id, alert.id, alert.investigation_id


def rows(engine, tenant_id):
    with Session(engine) as db:
        action = db.scalar(select(Action).where(Action.tenant_id == tenant_id, Action.kind == "create_case"))
        case = db.scalar(select(Case).where(Case.tenant_id == tenant_id))
        writes = db.scalars(select(CaseWrite).where(CaseWrite.tenant_id == tenant_id).order_by(CaseWrite.sequence)).all()
        return action, case, writes


def reconcile(engine, tenant_id, alert_id, inv_id):
    with Session(engine) as db:
        tenant = db.get(Tenant, tenant_id)
        alert = db.get(Alert, alert_id)
        inv = db.get(Investigation, inv_id)
        evidence = db.scalars(select(Evidence).where(Evidence.tenant_id == tenant_id,
            Evidence.investigation_id == inv_id)).all()
        return perform_action(db, tenant, inv, alert, "create_case", evidence).status


def test_step_timeout_after_write_reconciles_without_duplicate(monkeypatch):
    hive = HiveDouble("evidence_page", "timeout_after_write")
    engine, tenant_id, alert_id, inv_id = setup(monkeypatch, hive)
    action, case, writes = rows(engine, tenant_id)
    assert action.status == "unknown" and case.status == "enrichment_unknown"
    assert [row.kind for row in writes] == ["create_case", "evidence_page", "comment", "observable", "task"]
    assert [row.status for row in writes] == ["succeeded", "unknown", "pending", "pending", "pending"]
    assert all(row.idempotency_key and row.request_data for row in writes)
    assert all(row.attempts == 1 for row in writes[:2]) and writes[2].attempts == 0
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Audit).where(
            Audit.tenant_id == tenant_id, Audit.operation == "case_write_attempted")) == 2
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "succeeded"
    action, case, writes = rows(engine, tenant_id)
    assert case.status == "open" and all(row.status == "succeeded" for row in writes)
    assert hive.create_calls == 1
    assert hive.write_calls.count("evidence_page") == 1
    assert hive.write_calls.count("comment") == 1
    assert hive.write_calls.count("observable") == 1
    assert hive.write_calls.count("task") == 1
    assert hive.read_calls == ["evidence_page"]
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "succeeded"
    assert hive.create_calls == 1 and hive.write_calls.count("task") == 1


def test_negative_step_readback_keeps_unknown_and_never_rewrites(monkeypatch):
    hive = HiveDouble("evidence_page", "timeout_before_write")
    engine, tenant_id, alert_id, inv_id = setup(monkeypatch, hive)
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "unknown"
    action, case, writes = rows(engine, tenant_id)
    assert action.status == "unknown" and case.status == "enrichment_unknown"
    assert writes[1].status == "unknown" and writes[1].attempts == 1
    assert hive.write_calls == ["evidence_page"]
    assert hive.read_calls == ["evidence_page"]


def test_comment_timeout_reconciles_without_second_comment(monkeypatch):
    hive = HiveDouble("comment", "timeout_after_write")
    engine, tenant_id, alert_id, inv_id = setup(monkeypatch, hive)
    action, _, writes = rows(engine, tenant_id)
    assert action.status == "unknown"
    assert [item.kind for item in writes] == ["create_case", "evidence_page", "comment", "observable", "task"]
    assert writes[2].status == "unknown"
    assert writes[2].request_data["external"] is False
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "succeeded"
    assert hive.write_calls.count("comment") == 1
    assert hive.read_calls == ["comment"]


def test_definite_step_rejection_never_marks_overall_case_succeeded(monkeypatch):
    hive = HiveDouble("task", "rejected")
    engine, tenant_id, alert_id, inv_id = setup(monkeypatch, hive)
    action, case, writes = rows(engine, tenant_id)
    assert action.status == "failed" and case.status == "enrichment_failed"
    assert [row.status for row in writes] == ["succeeded", "succeeded", "succeeded", "succeeded", "failed"]
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "failed"
    assert hive.write_calls.count("task") == 1


def test_ambiguous_case_creation_reconciles_before_enrichment(monkeypatch):
    hive = HiveDouble("create_case", "ambiguous")
    engine, tenant_id, alert_id, inv_id = setup(monkeypatch, hive)
    action, case, writes = rows(engine, tenant_id)
    assert action.status == "unknown" and writes[0].status == "unknown"
    assert not case.external_id
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "succeeded"
    action, case, writes = rows(engine, tenant_id)
    assert case.external_id == "hive-case-1" and all(row.status == "succeeded" for row in writes)
    assert hive.create_calls == 1


def test_external_case_link_mismatch_stops_enrichment(monkeypatch):
    class MismatchedHive(HiveDouble):
        def find_case(self, key):
            return "another-case" if self.created else None

    hive = MismatchedHive()
    engine, tenant_id, _, _ = setup(monkeypatch, hive)
    action, case, writes = rows(engine, tenant_id)
    assert action.status == "unknown" and case.status == "enrichment_unknown"
    assert writes[0].status == "succeeded" and writes[1].status == "unknown"
    assert hive.write_calls == []


def test_observable_write_has_own_key_and_reconciles(monkeypatch):
    hive = HiveDouble("observable", "timeout_after_write")
    engine, tenant_id, alert_id, inv_id = setup(monkeypatch, hive, observable=True)
    action, case, writes = rows(engine, tenant_id)
    assert [item.kind for item in writes] == ["create_case", "evidence_page", "comment", "observable", "task"]
    assert [item.status for item in writes] == ["succeeded", "succeeded", "succeeded", "unknown", "pending"]
    assert writes[3].request_data["data"] == "203.0.113.41"
    assert len({item.idempotency_key for item in writes}) == len(writes)
    assert reconcile(engine, tenant_id, alert_id, inv_id) == "succeeded"
    assert hive.write_calls.count("observable") == 1
    assert hive.read_calls == ["observable"]


def test_case_plan_uses_persisted_decision_claims(monkeypatch):
    hive = HiveDouble()
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(workflow, "thehive_adapter", lambda: hive)
    with Session(engine) as db:
        tenant = Tenant(name="claims-test", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.commit()
        alert, _ = ingest(db, tenant.id, instantiate_scenario("root_unapproved")[0])
        process_alert(db, alert.id)
        inv = db.get(Investigation, alert.investigation_id)
        evidence = db.scalars(select(Evidence).where(Evidence.investigation_id == inv.id)).all()
        raw_id = next(item.id for item in evidence if item.kind == "raw_alert")
        decision = db.scalar(select(Decision).where(Decision.investigation_id == inv.id))
        decision.evidence_for = [{"evidence_id": raw_id, "reason": "Исходный алерт"}]
        tenant.automation_level = "controlled_automation"
        db.commit()
        action = perform_action(db, tenant, inv, alert, "create_case", evidence)
        assert action and action.status == "succeeded"
        case = db.scalar(select(Case).where(Case.investigation_id == inv.id))
        assert case.data["evidence_for_ids"] == [raw_id]
        create = db.scalar(select(CaseWrite).where(CaseWrite.case_id == case.id,
            CaseWrite.kind == "create_case"))
        assert f"[{raw_id}]" in create.request_data["description"]
