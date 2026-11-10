"""Tenant-scoped operational counters derived from durable records."""

from datetime import timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Action, Alert, Audit, Decision, Investigation


CLASSES = ("TP", "FP", "BENIGN_TRUE_POSITIVE", "NOISE", "INCONCLUSIVE")


def _count(db: Session, model: type, tenant_id: str, *conditions: object) -> int:
    return int(db.scalar(select(func.count()).select_from(model).where(model.tenant_id == tenant_id, *conditions)) or 0)


def metric_snapshot(db: Session, tenant_id: str) -> dict:
    """Return tenant aggregates without event payloads.

    The handling rate denominator is investigations with completed_at set.
    Its numerator is current automated terminal outcomes (case created,
    suppressed or FP closed) with no analyst review or manual action recorded.
    It measures workflow handling, not accuracy or analyst time saved.
    An automatic close attempt is counted only after its action is durably
    created with a distinct audit marker; manual closes are excluded.
    """
    triage = {classification: int(count) for classification, count in db.execute(
        select(Decision.classification, func.count()).where(Decision.tenant_id == tenant_id)
        .group_by(Decision.classification)
    ) if classification in CLASSES}
    completed = db.execute(select(Investigation.started_at, Investigation.completed_at).where(
        Investigation.tenant_id == tenant_id,
        Investigation.started_at.is_not(None),
        Investigation.completed_at.is_not(None),
    ).execution_options(yield_per=500))
    duration_count = 0
    total_duration = 0.0
    for start, end in completed:
        if start is None or end is None:
            continue
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        duration = (end - start).total_seconds()
        if duration >= 0:
            duration_count += 1
            total_duration += duration
    processed = _count(db, Investigation, tenant_id, Investigation.completed_at.is_not(None))
    reviewed = select(Audit.subject_id).where(
        Audit.tenant_id == tenant_id, Audit.operation == "review",
        Audit.subject_type == "investigation")
    manually_acted = select(Action.investigation_id).join(
        Audit, Audit.subject_id == Action.id).where(
        Action.tenant_id == tenant_id, Audit.tenant_id == tenant_id,
        Audit.subject_type == "action", Audit.operation == "manual_action_requested")
    automated = _count(
        db, Investigation, tenant_id,
        Investigation.completed_at.is_not(None),
        Investigation.status.in_(("escalated", "suppressed", "auto_closed")),
        ~Investigation.id.in_(reviewed),
        ~Investigation.id.in_(manually_acted),
    )
    return {
        "alert_ingestion_total": _count(db, Alert, tenant_id),
        "alert_deduplicated_total": _count(db, Audit, tenant_id, Audit.operation == "alert_deduplicated"),
        "triage_results_total": {key: triage.get(key, 0) for key in CLASSES},
        "cases_created_total": _count(db, Action, tenant_id, Action.kind == "create_case", Action.status == "succeeded"),
        "cases_suppressed_total": _count(db, Alert, tenant_id, Alert.pipeline_state == "SUPPRESSED"),
        "auto_close_attempts_total": _count(db, Audit, tenant_id, Audit.operation == "auto_close_attempted"),
        "auto_close_denied_total": _count(db, Audit, tenant_id, Audit.operation == "auto_close_denied"),
        "processing_duration_seconds": {
            "count": duration_count,
            "sum": round(total_duration, 3),
            "avg": round(total_duration / duration_count, 3) if duration_count else None,
        },
        "integration_errors_total": _count(db, Audit, tenant_id, Audit.operation == "integration_error"),
        "queue_depth": _count(db, Alert, tenant_id, Alert.status.in_(("queued", "running"))),
        "automated_handling_rate": round(automated / processed, 4) if processed else None,
        "automated_handling_total": automated,
        "processed_investigations_total": processed,
    }
