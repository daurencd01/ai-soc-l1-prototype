"""Deny-by-default policies for grouping confirmed low-value NOISE locally."""

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Audit, SuppressionEvent, SuppressionRule, utcnow
from .policy import aware


SUPPRESSIBLE_SCOPE: dict[str, frozenset[str]] = {
    "ipsec_failure": frozenset({"peer", "device", "tunnel", "failure_reason"}),
}
MAX_DURATION = timedelta(days=30)


def validate_contract(row: SuppressionRule) -> str | None:
    required = SUPPRESSIBLE_SCOPE.get(row.rule)
    if required is None:
        return "rule_not_allowlisted"
    if not row.owner or not row.owner.strip() or not row.reason or len(row.reason.strip()) < 10:
        return "missing_owner_or_reason"
    if not isinstance(row.scope, dict) or set(row.scope) != required:
        return "invalid_scope"
    if any(not isinstance(value, str) or not value.strip() or len(value) > 256 or "*" in value
           for value in row.scope.values()):
        return "invalid_scope"
    if not row.entity or row.entity != row.scope["peer"] or "*" in row.entity:
        return "invalid_entity"
    if (not row.valid_from or not row.valid_until
            or aware(row.valid_until) <= aware(row.valid_from)
            or aware(row.valid_until) - aware(row.valid_from) > MAX_DURATION):
        return "invalid_window"
    return None


def snapshot(row: SuppressionRule) -> dict:
    return {"policy_key": row.policy_key, "version": row.version, "rule_id": row.rule,
            "entity": row.entity, "owner": row.owner, "reason": row.reason,
            "scope": row.scope, "valid_from": row.valid_from.isoformat(),
            "valid_until": row.valid_until.isoformat()}


def record_event(db: Session, row: SuppressionRule, actor: str, event_type: str,
                 from_status: str | None, to_status: str, detail: dict | None = None) -> None:
    db.add(SuppressionEvent(tenant_id=row.tenant_id, policy_id=row.id, actor=actor,
                            event_type=event_type, from_status=from_status, to_status=to_status,
                            detail={"policy": snapshot(row), **(detail or {})}))


def is_effective(db: Session, row: SuppressionRule, raw: dict, event_at: datetime,
                 now: datetime | None = None) -> bool:
    now = now or utcnow()
    if (row.approval_status != "approved" or row.revoked_at is not None
            or not row.approved_at or not row.approved_by or row.approved_by == row.created_by
            or validate_contract(row) is not None):
        return False
    if (not aware(row.valid_from) <= aware(event_at) < aware(row.valid_until)
            or not aware(row.valid_from) <= aware(now) < aware(row.valid_until)
            or aware(row.approved_at) > aware(now)
            or aware(row.approved_at) > aware(event_at)):
        return False
    if not isinstance(raw, dict) or any(raw.get(key) != value for key, value in row.scope.items()):
        return False
    receipt = db.scalar(select(SuppressionEvent.id).where(
        SuppressionEvent.tenant_id == row.tenant_id, SuppressionEvent.policy_id == row.id,
        SuppressionEvent.event_type == "approved", SuppressionEvent.actor == row.approved_by,
        SuppressionEvent.to_status == "approved").limit(1))
    audit_receipt = db.scalar(select(Audit.id).where(
        Audit.tenant_id == row.tenant_id, Audit.operation == "suppression_approved",
        Audit.subject_type == "suppression_policy", Audit.subject_id == row.id,
        Audit.actor == row.approved_by).limit(1))
    return receipt is not None and audit_receipt is not None
