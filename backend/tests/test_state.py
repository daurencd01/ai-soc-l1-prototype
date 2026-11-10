import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Alert, PipelineTransition, Tenant
from app.scenarios import instantiate_scenario
from app.state import InvalidTransition, PipelineState, validate_transition
from app.workflow import ingest, process_alert


def test_confirmed_case_and_close_require_triage_and_pending_action():
    with pytest.raises(InvalidTransition):
        validate_transition(PipelineState.RECEIVED, PipelineState.CASE_CREATED)
    with pytest.raises(InvalidTransition):
        validate_transition(PipelineState.TRIAGED, PipelineState.CLOSED_FP)
    assert validate_transition(PipelineState.TRIAGED, PipelineState.CASE_PENDING)
    assert validate_transition(PipelineState.CASE_PENDING, PipelineState.CASE_CREATED)


def test_retry_and_manual_review_are_explicit_but_terminal_close_cannot_reopen():
    assert validate_transition(PipelineState.CASE_PENDING, PipelineState.FAILED_RETRYABLE)
    assert validate_transition(PipelineState.FAILED_RETRYABLE, PipelineState.CASE_PENDING)
    assert validate_transition(PipelineState.NEEDS_REVIEW, PipelineState.CLOSE_PENDING)
    assert validate_transition(PipelineState.CLOSED_FP, PipelineState.CLOSED_FP) is False
    with pytest.raises(InvalidTransition):
        validate_transition(PipelineState.CLOSED_FP, PipelineState.TRIAGING)


def test_unknown_state_fails_closed():
    with pytest.raises(InvalidTransition):
        validate_transition("closed", PipelineState.CLOSED_FP)


def test_pipeline_records_atomic_ordered_history_for_review_route():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="state-history", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.commit()
        alert, _ = ingest(db, tenant.id, instantiate_scenario("root_unapproved")[0])
        process_alert(db, alert.id)
        states = db.scalars(select(PipelineTransition).where(
            PipelineTransition.alert_id == alert.id).order_by(PipelineTransition.created_at,
                                                             PipelineTransition.id)).all()
        assert [row.to_state for row in states] == [
            "RECEIVED", "VALIDATED", "ENRICHING", "TRIAGING", "TRIAGED", "NEEDS_REVIEW"]
        assert all(current.from_state == previous.to_state for previous, current in zip(states, states[1:]))
        assert db.get(Alert, alert.id).pipeline_state == "NEEDS_REVIEW"
