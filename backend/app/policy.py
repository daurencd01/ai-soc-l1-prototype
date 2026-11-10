"""Independent, deny-by-default policy checks for FP exception versions."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Audit, ExceptionRule, PolicyEvent, utcnow


# A policy may be approved only for a rule with a reviewed evidence contract.
FP_CLOSE_SCOPE: dict[str, tuple[str, ...]] = {
    "root_ssh": ("host", "src_ip", "auth_method"),
    "vpn_country": ("peer", "device", "tunnel"),
    "ipsec_failure": ("peer", "device", "tunnel"),
    "brute_force": ("user", "src_ip"),
    "powershell": ("host", "user", "command_line"),
}
SCOPE_FIELDS = frozenset({"host", "src_ip", "dst_ip", "user", "peer", "device", "tunnel",
                          "auth_method", "command_line", "vpn_type", "stage"})
MAX_POLICY_DURATION = timedelta(days=90)


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def validate_contract(row: ExceptionRule) -> str | None:
    """Return a stable denial code; never make an invalid draft actionable."""
    required = FP_CLOSE_SCOPE.get(row.rule)
    if not required:
        return "rule_not_allowlisted"
    if not row.owner or not row.owner.strip() or not row.reason or len(row.reason.strip()) < 10:
        return "missing_owner_or_reason"
    if not isinstance(row.scope, dict) or not row.scope or len(row.scope) > 12:
        return "invalid_scope"
    if any(key not in SCOPE_FIELDS or not isinstance(value, str) or not value.strip()
           or len(value) > 1024 or "*" in value for key, value in row.scope.items()):
        return "invalid_scope"
    if not set(required).issubset(row.scope):
        return "missing_required_scope"
    if not row.entity or row.entity not in row.scope.values() or "*" in row.entity:
        return "invalid_entity"
    if (not row.valid_from or not row.valid_until or
            aware(row.valid_until) <= aware(row.valid_from) or
            aware(row.valid_until) - aware(row.valid_from) > MAX_POLICY_DURATION):
        return "invalid_window"
    return None


def snapshot(row: ExceptionRule) -> dict:
    return {"policy_key": row.policy_key, "version": row.version, "rule_id": row.rule,
            "entity": row.entity, "owner": row.owner, "reason": row.reason,
            "scope": row.scope, "valid_from": row.valid_from.isoformat(),
            "valid_until": row.valid_until.isoformat()}


def record_event(db: Session, row: ExceptionRule, actor: str, event_type: str,
                 from_status: str | None, to_status: str, detail: dict | None = None) -> None:
    db.add(PolicyEvent(tenant_id=row.tenant_id, policy_id=row.id, actor=actor,
                       event_type=event_type, from_status=from_status, to_status=to_status,
                       detail={"policy": snapshot(row), **(detail or {})}))


def is_effective(db: Session, row: ExceptionRule, raw: dict, event_at: datetime,
                 now: datetime | None = None) -> bool:
    """Require current approval, an approval receipt, exact scope and both time windows."""
    now = now or utcnow()
    if (row.approval_status != "approved" or row.revoked_at is not None
            or not row.approved_at or not row.approved_by or row.approved_by == row.created_by
            or validate_contract(row) is not None):
        return False
    if (not aware(row.valid_from) <= aware(event_at) < aware(row.valid_until)
            or not aware(row.valid_from) <= aware(now) < aware(row.valid_until)
            or aware(row.approved_at) > aware(now)):
        return False
    if not isinstance(raw, dict) or any(raw.get(key) != value for key, value in row.scope.items()):
        return False
    receipt = db.scalar(select(PolicyEvent.id).where(
        PolicyEvent.tenant_id == row.tenant_id, PolicyEvent.policy_id == row.id,
        PolicyEvent.event_type == "approved", PolicyEvent.actor == row.approved_by,
        PolicyEvent.to_status == "approved").limit(1))
    audit_receipt = db.scalar(select(Audit.id).where(
        Audit.tenant_id == row.tenant_id, Audit.operation == "exception_approved",
        Audit.subject_type == "exception", Audit.subject_id == row.id,
        Audit.actor == row.approved_by).limit(1))
    return receipt is not None and audit_receipt is not None
