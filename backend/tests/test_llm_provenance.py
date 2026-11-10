"""A validated local-model proposal remains auditable after policy decisions."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.workflow as workflow
from app.analyzer import _source_event_ids
from app.db import Base, get_db
from app.main import app
from app.models import Action, Decision, Tenant, User
from app.playbooks import Verdict
from app.scenarios import instantiate_scenario
from app.security import hash_password, token_for


def database():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def test_decision_and_api_expose_structured_local_model_provenance(monkeypatch):
    engine = database()
    with Session(engine) as db:
        tenant = Tenant(name="llm-provenance", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        user = User(tenant_id=tenant.id, username="llm-viewer",
                    password_hash=hash_password("password"), role="viewer")
        db.add(user)
        db.commit()
        token = token_for(user)
        alert, _ = workflow.ingest(db, tenant.id, instantiate_scenario("root_unapproved")[0])
        investigation_id = alert.investigation_id

        observed_ids = []

        def local_model(records, baseline):
            observed_ids.extend(sorted(_source_event_ids(records))[:1])
            return baseline.model_copy(update={
                "model_name": "local:7b", "model_digest": "a" * 64,
                "prompt_version": "soc-triage-v3", "prompt_sha256": "b" * 64,
                "model_classification": "TP", "model_confidence": 0.82,
                "model_auto_close_candidate": False,
                "related_event_ids": observed_ids[:], "mitre_techniques": ["T1078"],
            }), "local_model"

        monkeypatch.setattr(workflow, "model_analyze", local_model)
        workflow.process_alert(db, alert.id)
        row = db.scalar(select(Decision).where(Decision.investigation_id == investigation_id))
        assert row.classification == "TP" and row.model_classification == "TP"
        assert row.model_confidence == 0.82 and row.model_auto_close_candidate is False
        assert observed_ids and row.related_event_ids == observed_ids
        assert row.mitre_techniques == ["T1078"]
        assert row.model_digest == "a" * 64 and row.prompt_sha256 == "b" * 64

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        response = TestClient(app).get(f"/api/investigations/{investigation_id}",
                                       headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        decision = response.json()["decisions"][0]
        assert decision["related_event_ids"] == observed_ids
        assert decision["mitre_techniques"] == ["T1078"]
        assert decision["prompt_version"] == "soc-triage-v3"
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_model_disagreement_preserves_proposal_but_blocks_action(monkeypatch):
    engine = database()
    try:
        with Session(engine) as db:
            tenant = Tenant(name="llm-disagreement", deployment_mode="DEMO", automation_level="auto_close")
            db.add(tenant)
            db.commit()
            alert, _ = workflow.ingest(db, tenant.id, instantiate_scenario("unknown_rule")[0])

            def conflicting_model(records, _baseline):
                return Verdict(verdict="true_positive", priority="high", summary="Модель считает инцидентом",
                               rationale="Предположение", evidence_ids=[records[0]["id"]],
                               recommended_actions=["create_case"],
                               model_classification="TP", model_confidence=0.74,
                               model_auto_close_candidate=False, model_name="local:7b",
                               model_digest="a" * 64, prompt_version="soc-triage-v3",
                               prompt_sha256="b" * 64, mitre_techniques=["T1078"]), "local_model"

            monkeypatch.setattr(workflow, "model_analyze", conflicting_model)
            workflow.process_alert(db, alert.id)
            decision = db.scalar(select(Decision).where(Decision.investigation_id == alert.investigation_id))
            assert decision.classification == "INCONCLUSIVE"
            assert decision.model_classification == "TP" and decision.model_confidence == 0.74
            assert decision.prompt_version == "soc-triage-v3"
            assert db.scalar(select(func.count()).select_from(Action)) == 0
    finally:
        engine.dispose()
