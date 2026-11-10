"""Bounded tenant-scoped case read models from confirmed local writes."""

from collections import defaultdict
from urllib.parse import quote, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, settings
from .models import Action, Case, CaseWrite, Investigation


def _source_references(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    refs = []
    for item in value[:20]:
        if not isinstance(item, str) or len(item) > 1000:
            continue
        try:
            parsed = urlsplit(item)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.hostname and not (
                parsed.username or parsed.password or parsed.query or parsed.fragment):
            refs.append(item)
    return refs


def _sync_status(external_id: str | None, states: list[str]) -> str:
    if not external_id:
        return "pending"
    if not states or "unknown" in states:
        return "unknown"
    if "failed" in states:
        return "failed"
    if "pending" in states:
        return "pending"
    return "confirmed"


def case_reference(external_id: str | None, sync_status: str, config: Settings | None = None) -> str | None:
    """Build a case UI link only from an operator-verified same-origin template."""
    config = config or settings()
    if config.mode.upper() != "CONNECTED" or sync_status != "confirmed" or not external_id:
        return None
    template = config.thehive_case_url_template
    if (not template or len(template) > 2048 or not config.thehive_base_url
            or len(external_id) > 200 or "\\" in template
            or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in template)):
        return None
    if template.count("{case_id}") != 1 or "{" in template.replace("{case_id}", "") or "}" in template.replace("{case_id}", ""):
        return None
    try:
        base = urlsplit(config.thehive_base_url)
        target = urlsplit(template)
        if (base.scheme not in {"http", "https"} or base.scheme != target.scheme
                or not base.hostname or base.hostname != target.hostname
                or base.username or base.password or target.username or target.password
                or base.query or base.fragment or target.query or target.fragment
                or "{case_id}" not in target.path):
            return None
        base_port = base.port or (443 if base.scheme == "https" else 80)
        target_port = target.port or (443 if target.scheme == "https" else 80)
        if base_port != target_port:
            return None
        if target.scheme == "http" and target.hostname not in {"localhost", "127.0.0.1", "::1"}:
            return None
        encoded_id = quote(external_id, safe="")
        if encoded_id in {".", ".."}:
            return None
        return template.replace("{case_id}", encoded_id)
    except ValueError:
        return None


def case_sync_statuses(db: Session, tenant_id: str, external_ids: dict[str, str | None]) -> dict[str, str]:
    """Summarize durable write outcomes for a bounded set of tenant case IDs."""
    if not external_ids:
        return {}
    ids = list(external_ids)
    states: dict[str, list[str]] = defaultdict(list)
    for case_id, status in db.execute(select(CaseWrite.case_id, CaseWrite.status).where(
            CaseWrite.tenant_id == tenant_id, CaseWrite.case_id.in_(ids))):
        states[case_id].append(status)
    for case_id, status in db.execute(select(Action.target, Action.status).where(
            Action.tenant_id == tenant_id, Action.target.in_(ids),
            Action.kind.in_(("update_case", "update_case_fields")))):
        states[case_id].append(status)
    return {case_id: _sync_status(external_id, states[case_id])
            for case_id, external_id in external_ids.items()}


def list_case_views(db: Session, tenant_id: str, limit: int = 100) -> list[dict]:
    """Return locally confirmed case facts; no remote state is inferred or fetched."""
    rows = db.execute(select(Case, Investigation).join(
        Investigation, Case.investigation_id == Investigation.id).where(
        Case.tenant_id == tenant_id, Investigation.tenant_id == tenant_id
    ).order_by(Case.created_at.desc(), Case.id).limit(min(max(limit, 1), 100))).all()
    ids = [case.id for case, _ in rows]
    if not ids:
        return []
    writes: dict[str, list[CaseWrite]] = defaultdict(list)
    for item in db.scalars(select(CaseWrite).where(
            CaseWrite.tenant_id == tenant_id, CaseWrite.case_id.in_(ids))
            .order_by(CaseWrite.case_id, CaseWrite.sequence)).all():
        writes[item.case_id].append(item)
    mutations: dict[str, list[Action]] = defaultdict(list)
    for item in db.scalars(select(Action).where(
            Action.tenant_id == tenant_id, Action.target.in_(ids),
            Action.kind.in_(("update_case", "update_case_fields")))).all():
        mutations[item.target].append(item)

    result = []
    for case, inv in rows:
        history = writes[case.id]
        create = next((item.request_data for item in history if item.kind == "create_case"
                       and isinstance(item.request_data, dict)), {})
        metadata = case.data if isinstance(case.data, dict) else {}
        updated = metadata.get("remote_field_values")
        updated = updated if isinstance(updated, dict) else {}
        description = updated.get("description", create.get("description", ""))
        description = description if isinstance(description, str) else ""
        severity = updated.get("severity", create.get("severity", metadata.get("severity")))
        if isinstance(severity, int) and not isinstance(severity, bool):
            severity = {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(severity)
        if severity not in {"low", "medium", "high", "critical"}:
            severity = "unknown"
        observables = [item.request_data for item in history if item.kind == "observable"
                       and item.status == "succeeded" and isinstance(item.request_data, dict)]
        states = [item.status for item in history] + [item.status for item in mutations[case.id]]
        sync_status = _sync_status(case.external_id, states)
        confirmed_times = [item.completed_at for item in [*history, *mutations[case.id]]
                           if item.status == "succeeded" and item.completed_at is not None]
        summary = updated.get("summary", inv.summary)
        result.append({
            "id": case.id, "investigation_id": inv.id, "external_id": case.external_id,
            "status": case.status, "sync_status": sync_status,
            "case_reference": case_reference(case.external_id, sync_status),
            "last_confirmed_at": max(confirmed_times) if confirmed_times else None,
            "title": case.title, "severity": severity,
            "description": description[:10_000], "description_truncated": len(description) > 10_000,
            "summary": summary if isinstance(summary, str) else inv.summary,
            "classification": metadata.get("classification") or inv.classification,
            "observables": [{"dataType": row.get("dataType"), "data": row.get("data")}
                            for row in observables[:20]],
            "handoff_reason": (inv.rationale or "")[:2500],
            "source_references": _source_references(metadata.get("source_references")),
            "created_at": case.created_at,
        })
    return result
