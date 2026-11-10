"""Validated SOC pipeline states shared by workers and the API."""

from enum import StrEnum

from sqlalchemy.orm import Session

from .models import Alert, PipelineTransition


class PipelineState(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    ENRICHING = "ENRICHING"
    TRIAGING = "TRIAGING"
    TRIAGED = "TRIAGED"
    CASE_PENDING = "CASE_PENDING"
    CASE_CREATED = "CASE_CREATED"
    SUPPRESSED = "SUPPRESSED"
    CLOSE_PENDING = "CLOSE_PENDING"
    CLOSED_FP = "CLOSED_FP"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_PERMANENT = "FAILED_PERMANENT"


_ALLOWED: dict[PipelineState, frozenset[PipelineState]] = {
    PipelineState.RECEIVED: frozenset({PipelineState.VALIDATED, PipelineState.FAILED_RETRYABLE,
                                       PipelineState.FAILED_PERMANENT}),
    PipelineState.VALIDATED: frozenset({PipelineState.ENRICHING, PipelineState.FAILED_RETRYABLE,
                                        PipelineState.FAILED_PERMANENT}),
    PipelineState.ENRICHING: frozenset({PipelineState.TRIAGING, PipelineState.FAILED_RETRYABLE,
                                        PipelineState.FAILED_PERMANENT}),
    PipelineState.TRIAGING: frozenset({PipelineState.TRIAGED, PipelineState.FAILED_RETRYABLE,
                                       PipelineState.FAILED_PERMANENT}),
    PipelineState.TRIAGED: frozenset({PipelineState.CASE_PENDING, PipelineState.CLOSE_PENDING,
                                      PipelineState.SUPPRESSED, PipelineState.NEEDS_REVIEW,
                                      PipelineState.FAILED_RETRYABLE}),
    PipelineState.CASE_PENDING: frozenset({PipelineState.CASE_CREATED, PipelineState.NEEDS_REVIEW,
                                           PipelineState.FAILED_RETRYABLE}),
    PipelineState.CLOSE_PENDING: frozenset({PipelineState.CLOSED_FP, PipelineState.NEEDS_REVIEW,
                                            PipelineState.FAILED_RETRYABLE}),
    PipelineState.NEEDS_REVIEW: frozenset({PipelineState.VALIDATED, PipelineState.TRIAGING, PipelineState.CASE_PENDING,
                                           PipelineState.CLOSE_PENDING, PipelineState.FAILED_PERMANENT}),
    PipelineState.FAILED_RETRYABLE: frozenset({PipelineState.VALIDATED, PipelineState.CASE_PENDING,
                                               PipelineState.CLOSE_PENDING, PipelineState.NEEDS_REVIEW,
                                               PipelineState.FAILED_PERMANENT}),
    PipelineState.CASE_CREATED: frozenset(),
    PipelineState.SUPPRESSED: frozenset(),
    PipelineState.CLOSED_FP: frozenset(),
    PipelineState.FAILED_PERMANENT: frozenset({PipelineState.FAILED_RETRYABLE}),
}


class InvalidTransition(ValueError):
    pass


def validate_transition(current: str | PipelineState, target: str | PipelineState) -> bool:
    """Return False for an idempotent repeat; reject skipping or reversing stages."""
    try:
        previous = PipelineState(current)
        following = PipelineState(target)
    except ValueError as exc:
        raise InvalidTransition("Неизвестное состояние конвейера") from exc
    if previous == following:
        return False
    if following not in _ALLOWED[previous]:
        raise InvalidTransition(f"Недопустимый переход {previous.value} → {following.value}")
    return True


def record_initial(db: Session, alert: Alert) -> None:
    """Add the first history row in the same transaction as the new alert."""
    if alert.pipeline_state != PipelineState.RECEIVED or not alert.investigation_id:
        raise InvalidTransition("Новый алерт не находится в состоянии RECEIVED")
    db.add(PipelineTransition(tenant_id=alert.tenant_id, alert_id=alert.id,
                              investigation_id=alert.investigation_id,
                              from_state=None, to_state=PipelineState.RECEIVED,
                              actor="ingest", reason="alert_received"))


def move_alert(db: Session, alert: Alert, target: PipelineState, actor: str, reason: str = "") -> bool:
    """Validate and append an atomic state change; caller commits with its work."""
    previous = PipelineState(alert.pipeline_state)
    if not validate_transition(previous, target):
        return False
    alert.pipeline_state = target.value
    db.add(PipelineTransition(tenant_id=alert.tenant_id, alert_id=alert.id,
                              investigation_id=alert.investigation_id,
                              from_state=previous.value, to_state=target.value,
                              actor=actor[:100], reason=reason[:200]))
    return True
