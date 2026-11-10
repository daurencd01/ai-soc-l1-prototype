"""Tenant-scoped operational counters derived from durable records."""

from datetime import timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Action, Alert, Audit, Decision, Investigation


CLASSES = ("TP", "FP", "BENIGN_TRUE_POSITIVE", "NOISE", "INCONCLUSIVE")


def _count(db: Session, model: type, tenant_id: str, *conditions: object) -> int:
    return int(db.scalar(select(func.count()).select_from(model).where(model.tenant_id == tenant_id, *conditions)) or 0)


def metric_snapshot(db: Session, tenant_id: str) -> dict:
    """Return only aggregates; never place event fields in metric labels."""
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
    return {
        "alert_ingestion_total": _count(db, Alert, tenant_id),
        "alert_deduplicated_total": _count(db, Audit, tenant_id, Audit.operation == "alert_deduplicated"),
        "triage_results_total": {key: triage.get(key, 0) for key in CLASSES},
        "cases_created_total": _count(db, Action, tenant_id, Action.kind == "create_case", Action.status == "succeeded"),
        "cases_suppressed_total": _count(db, Alert, tenant_id, Alert.pipeline_state == "SUPPRESSED"),
        "auto_close_attempts_total": _count(db, Action, tenant_id, Action.kind == "close_alert"),
        "auto_close_denied_total": _count(db, Audit, tenant_id, Audit.operation == "auto_close_denied"),
        "processing_duration_seconds": {
            "count": duration_count,
            "sum": round(total_duration, 3),
            "avg": round(total_duration / duration_count, 3) if duration_count else None,
        },
        "integration_errors_total": _count(db, Audit, tenant_id, Audit.operation == "integration_error"),
        "queue_depth": _count(db, Alert, tenant_id, Alert.status.in_(("queued", "running"))),
    }
