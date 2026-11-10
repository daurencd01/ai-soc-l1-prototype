"""Durable ingest, evidence collection, decision and policy-gated action pipeline."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
from time import monotonic
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .adapters import AdapterError, splunk_adapter, thehive_adapter, misp_adapter
from .analyzer import model_analyze
from .config import settings
from .models import (Action, Alert, Asset, Audit, Case, CaseWrite, Decision, EmbeddedEvent, Evidence,
                     ExceptionRule, IntegrationState, Investigation, Maintenance, PlaybookRun, Tenant, utcnow)
from .playbooks import select_playbook
from .security import audit


def aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def ingest(db: Session, tenant_id: str, payload: dict, _attempt: int = 0) -> tuple[Alert, bool]:
    source = str(payload.get("source") or "demo")[:50]
    source_id = str(payload.get("source_event_id") or "")[:256]
    if not source_id:
        raise ValueError("source_event_id обязателен")
    existing = db.scalar(select(Alert).where(Alert.tenant_id == tenant_id, Alert.source == source, Alert.source_event_id == source_id))
    if existing:
        return existing, False
    raw_time = payload["event_at"]
    source_time = (datetime.fromtimestamp(float(raw_time), timezone.utc) if isinstance(raw_time, (int, float)) or
                   (isinstance(raw_time, str) and raw_time.replace(".", "", 1).isdigit())
                   else datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")))
    if source_time.tzinfo is None or source_time.utcoffset() is None:
        raise ValueError("event_at должен содержать часовое смещение")
    event_at = source_time.astimezone(timezone.utc)
    rule = str(payload.get("rule") or "generic")[:100]
    playbook = select_playbook(rule)
    raw = payload.get("raw") or {}
    if not isinstance(raw, dict):
        raise ValueError("raw должен быть объектом")
    entity = str(raw.get("user") or raw.get("host") or raw.get("peer") or raw.get("src_ip") or source_id)[:100]
    correlation_key = str(payload.get("correlation_key") or f"{rule}:{entity}:{event_at.strftime('%Y%m%d%H')}")[:256]
    inv = db.scalar(select(Investigation).where(Investigation.tenant_id == tenant_id, Investigation.correlation_key == correlation_key).with_for_update())
    if not inv:
        inv = Investigation(tenant_id=tenant_id, correlation_key=correlation_key, playbook_key=playbook.key,
                            playbook_version=playbook.version, due_at=utcnow() + timedelta(minutes=15))
        db.add(inv)
        db.flush()
    alert = Alert(tenant_id=tenant_id, investigation_id=inv.id, source=source, source_event_id=source_id,
                  rule=rule, title=str(payload.get("title") or rule)[:300], severity=str(payload.get("severity") or "medium")[:20],
                  event_at=event_at, original_timezone=str(payload.get("original_timezone") or source_time.tzinfo)[:80], raw=raw)
    db.add(alert)
    db.flush()
    for idx, event in enumerate((payload.get("events") or [])[:100]):
        if isinstance(event, dict):
            dt = event.get("event_at")
            if dt:
                source_event_time = datetime.fromisoformat(str(dt).replace("Z", "+00:00"))
                if source_event_time.tzinfo is None or source_event_time.utcoffset() is None:
                    raise ValueError("Вложенное event_at должно содержать часовое смещение")
                when = source_event_time.astimezone(timezone.utc)
            else:
                when = event_at
            db.add(EmbeddedEvent(tenant_id=tenant_id, alert_id=alert.id,
                                 source_event_id=str(event.get("source_event_id") or f"{source_id}:{idx}")[:256],
                                 event_at=when, original_timezone=str(event.get("original_timezone") or alert.original_timezone)[:80], data=event))
    audit(db, tenant_id, "ingest", "alert_received", "alert", alert.id,
          {"source": source, "source_event_id": source_id, "investigation_id": inv.id})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(Alert).where(Alert.tenant_id == tenant_id, Alert.source == source, Alert.source_event_id == source_id))
        if existing:
            return existing, False
        if _attempt == 0:
            return ingest(db, tenant_id, payload, _attempt=1)
        raise
    return alert, True


def _ev(db: Session, inv: Investigation, kind: str, source: str, summary: str, data: dict,
        event_at: datetime | None = None) -> Evidence:
    existing = db.scalar(select(Evidence).where(Evidence.tenant_id == inv.tenant_id,
        Evidence.investigation_id == inv.id, Evidence.kind == kind, Evidence.source == source, Evidence.summary == summary))
    if existing:
        return existing
    item = Evidence(tenant_id=inv.tenant_id, investigation_id=inv.id, kind=kind, source=source,
                    summary=summary[:2000], data=data, event_at=event_at)
    db.add(item)
    db.flush()
    return item


def _integration(db: Session, tenant_id: str, name: str, status: str, detail: str = "", received: bool = False) -> None:
    row = db.scalar(select(IntegrationState).where(IntegrationState.tenant_id == tenant_id, IntegrationState.name == name))
    if not row:
        row = IntegrationState(tenant_id=tenant_id, name=name)
        db.add(row)
    row.status = status
    row.detail = detail[:500]
    row.last_checked_at = utcnow()
    if received:
        row.last_received_at = utcnow()


def collect(db: Session, alert: Alert, inv: Investigation) -> tuple[list[Evidence], bool, list[dict]]:
    raw = alert.raw
    steps: list[dict] = []
    context_ok = True
    _ev(db, inv, "raw_alert", alert.source, f"Исходный алерт {alert.source_event_id}",
        {"alert_id": alert.id, "fields": raw}, alert.event_at)
    steps.append({"step": "normalize", "status": "succeeded"})
    for event in db.scalars(select(EmbeddedEvent).where(EmbeddedEvent.tenant_id == inv.tenant_id, EmbeddedEvent.alert_id == alert.id)).all():
        _ev(db, inv, "embedded_event", alert.source, f"Вложенное событие {event.source_event_id}", event.data, event.event_at)
    steps.append({"step": "embedded_events", "status": "succeeded"})
    entity_fields = [(key, str(raw[key])) for key in ("host", "src_ip", "dst_ip", "user", "peer", "device", "tunnel") if raw.get(key)]
    entities = [value for _, value in entity_fields]
    asset_kinds = {"host": "host", "src_ip": "ip", "dst_ip": "ip", "user": "user",
                   "peer": "vpn_peer", "device": "device"}
    for field, entity in entity_fields[:10]:
        kind = asset_kinds.get(field)
        asset = db.scalar(select(Asset).where(Asset.tenant_id == inv.tenant_id,
                                             Asset.value == entity, Asset.kind == kind)) if kind else None
        if asset:
            _ev(db, inv, "asset", "inventory", f"Актив {entity}: критичность {asset.criticality}",
                {"kind": asset.kind, "value": asset.value, "owner": asset.owner, "criticality": asset.criticality, "attributes": asset.attributes})
    steps.append({"step": "inventory", "status": "succeeded"})
    for entity in entities[:10]:
        for exc in db.scalars(select(ExceptionRule).where(ExceptionRule.tenant_id == inv.tenant_id,
                      ExceptionRule.entity == entity, ExceptionRule.rule.in_([alert.rule, "*"]))).all():
            scope_matches = bool(exc.scope) and all(raw.get(k) == v for k, v in exc.scope.items())
            active = aware(exc.valid_from) <= aware(alert.event_at) < aware(exc.valid_until) and scope_matches
            _ev(db, inv, "active_exception" if active else "expired_exception", "local_policy",
                f"Исключение {exc.id}: {'действует' if active else 'не действует или не совпадает область'}", {"entity": entity, "reason": exc.reason, "scope": exc.scope,
                "valid_from": exc.valid_from.isoformat(), "valid_until": exc.valid_until.isoformat(), "approved_by": exc.approved_by})
        for work in db.scalars(select(Maintenance).where(Maintenance.tenant_id == inv.tenant_id,
                       Maintenance.entity == entity)).all():
            if aware(work.valid_from) <= aware(alert.event_at) < aware(work.valid_until) and work.scope and all(raw.get(k) == v for k, v in work.scope.items()):
                _ev(db, inv, "approved_maintenance", "local_policy", f"Согласованные работы {work.id}",
                    {"entity": entity, "reason": work.reason, "approved_by": work.approved_by, "scope": work.scope,
                     "valid_from": work.valid_from.isoformat(), "valid_until": work.valid_until.isoformat()})
    steps.append({"step": "approval_window", "status": "succeeded"})
    try:
        splunk = splunk_adapter()
        if raw.get("scenario_signal") == "splunk_unavailable" and settings().mode.upper() == "DEMO":
            raise AdapterError("Симулированная недоступность Splunk")
        if entities:
            related = splunk.related_events(entities[0], alert.event_at - timedelta(hours=1), alert.event_at + timedelta(hours=1))
            for idx, event in enumerate(related[:20]):
                _ev(db, inv, "related_event", "splunk", f"Связанное событие Splunk {idx + 1}", event)
        _integration(db, inv.tenant_id, "splunk", "healthy", received=True)
        steps.append({"step": "related_events", "status": "succeeded"})
    except Exception as exc:
        context_ok = False
        _integration(db, inv.tenant_id, "splunk", "unavailable", type(exc).__name__)
        _ev(db, inv, "integration_error", "splunk", "Splunk недоступен для обогащения", {"error_type": type(exc).__name__})
        steps.append({"step": "related_events", "status": "failed"})
    indicator = raw.get("src_ip") or raw.get("dst_ip")
    try:
        misp = misp_adapter()
        if raw.get("scenario_signal") == "misp_unavailable" and settings().mode.upper() == "DEMO":
            raise AdapterError("Симулированная недоступность MISP")
        if indicator:
            try:
                public = ip_address(str(indicator)).is_global
            except ValueError:
                public = False
            if public:
                for idx, hit in enumerate(misp.search_indicator(str(indicator))[:20]):
                    _ev(db, inv, "misp_hit", "misp", f"Совпадение MISP {idx + 1}", hit)
        _integration(db, inv.tenant_id, "misp", "healthy")
        steps.append({"step": "misp", "status": "succeeded"})
    except Exception as exc:
        context_ok = False
        _integration(db, inv.tenant_id, "misp", "unavailable", type(exc).__name__)
        _ev(db, inv, "integration_error", "misp", "MISP недоступен", {"error_type": type(exc).__name__})
        steps.append({"step": "misp", "status": "failed"})
    return db.scalars(select(Evidence).where(Evidence.tenant_id == inv.tenant_id, Evidence.investigation_id == inv.id)).all(), context_ok, steps


def can_act(tenant: Tenant, kind: str) -> bool:
    mode = settings().mode.upper()
    if tenant.deployment_mode != mode:
        return False
    level = tenant.automation_level
    if level == "observe":
        return False
    if kind == "close_alert" and level not in {"auto_close", "approved_response"}:
        return False
    if kind == "create_case" and level not in {"auto_close", "approved_response"}:
        return False
    if kind in {"update_case", "disable_account_demo", "isolate_host_demo"} and level != "approved_response":
        return False
    if mode == "DEMO":
        return kind in {"close_alert", "create_case", "update_case", "disable_account_demo", "isolate_host_demo"}
    return settings().connected_writes_enabled and kind in set(settings().connected_allowed_actions.split(","))


@dataclass(frozen=True)
class ManualCloseDenied(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


_MANUAL_CLOSE_SCOPE: dict[str, tuple[str, ...]] = {
    "root_ssh": ("host", "src_ip", "auth_method"),
    "vpn_country": ("peer", "device", "tunnel"),
    "ipsec_failure": ("peer", "device", "tunnel"),
    "brute_force": ("user", "src_ip"),
    "powershell": ("host", "user", "command_line"),
}


def manual_close_gate(db: Session, tenant: Tenant, inv: Investigation, evidence: list[Evidence]) -> dict:
    """Authorize one human-requested close from current policy and stored evidence.

    The analyst's corrected verdict is never sufficient on its own. A rule not
    explicitly listed here has no manual close path until its evidence contract
    has been reviewed and added to the policy.
    """
    def deny(code: str, message: str) -> None:
        raise ManualCloseDenied(code, message)

    if inv.verdict != "false_positive":
        deny("verdict", "Закрытие требует подтверждённого вердикта false_positive")
    linked = db.scalars(select(Alert).where(Alert.tenant_id == tenant.id,
        Alert.investigation_id == inv.id).with_for_update()).all()
    if not linked:
        deny("no_alert", "В расследовании нет алерта")
    if any(a.status == "escalated" for a in linked):
        deny("escalated", "Эскалированный алерт нельзя закрыть по правилу FP")
    if any(str(a.severity).lower() not in {"low", "medium", "high"} for a in linked) or \
            str(inv.priority).lower() not in {"low", "medium", "high"}:
        deny("critical_or_unknown_severity", "Критичность или неизвестный уровень запрещает закрытие")
    if db.scalar(select(Case.id).where(Case.tenant_id == tenant.id,
        Case.investigation_id == inv.id).limit(1)) or db.scalar(select(Action.id).where(
            Action.tenant_id == tenant.id, Action.investigation_id == inv.id,
            Action.kind == "create_case").limit(1)):
        deny("case_exists", "Связанный кейс или попытка его создания требует отдельной сверки")
    if not evidence or any(e.kind == "integration_error" for e in evidence):
        deny("insufficient_evidence", "Доказательств недостаточно или источник недоступен")
    evidence_by_id = {e.id: e for e in evidence if e.tenant_id == tenant.id and e.investigation_id == inv.id}
    scoped_evidence = list(evidence_by_id.values())
    if not any(e.kind == "raw_alert" for e in evidence_by_id.values()):
        deny("insufficient_evidence", "Исходное событие отсутствует в доказательствах")
    decision = db.scalar(select(Decision).where(Decision.tenant_id == tenant.id,
        Decision.investigation_id == inv.id).order_by(Decision.created_at.desc(), Decision.id.desc()).limit(1))
    if (not decision or decision.verdict != "false_positive" or decision.missing_data
            or not isinstance(decision.evidence_ids, list) or not decision.evidence_ids
            or any(not isinstance(item, str) for item in decision.evidence_ids)
            or not set(decision.evidence_ids).issubset(evidence_by_id)):
        deny("insufficient_evidence", "Решение FP не подтверждено сохранёнными доказательствами")
    policy_ids: list[str] = []
    now = utcnow()
    for alert in linked:
        playbook = select_playbook(alert.rule)
        required_scope = _MANUAL_CLOSE_SCOPE.get(playbook.key)
        if (not required_scope or playbook.key != alert.rule or alert.rule != inv.playbook_key
                or playbook.version != inv.playbook_version):
            deny("rule_not_allowed", "Для правила нет утверждённого маршрута закрытия")
        if not db.scalar(select(PlaybookRun.id).where(PlaybookRun.tenant_id == tenant.id,
                PlaybookRun.investigation_id == inv.id, PlaybookRun.key == playbook.key,
                PlaybookRun.version == playbook.version, PlaybookRun.status == "completed").limit(1)):
            deny("incomplete_playbook", "Нет завершённого актуального плейбука")
        raw = alert.raw if isinstance(alert.raw, dict) else {}
        if playbook.key == "vpn_country" and raw.get("vpn_type") != "ipsec":
            deny("rule_not_allowed", "Пользовательский VPN не разрешён для закрытия по этому правилу")
        if any(not isinstance(raw.get(k), str) or not raw[k] for k in required_scope):
            deny("insufficient_evidence", "Обязательные поля области исключения отсутствуют")
        records = [{"id": e.id, "kind": e.kind, "source": e.source,
                    "summary": e.summary, "data": e.data} for e in scoped_evidence]
        try:
            baseline = playbook.decision_rule(raw, records, True)
        except (TypeError, ValueError, KeyError, AttributeError):
            deny("deterministic_rule", "Плейбук не смог проверить доказательства")
        if (baseline.verdict != "false_positive" or not baseline.auto_close_eligible
                or baseline.missing_data or not baseline.evidence_ids
                or not set(baseline.evidence_ids).issubset(evidence_by_id)):
            deny("deterministic_rule", "Детерминированный плейбук не разрешает закрытие")
        entities = {str(raw[k]) for k in ("host", "src_ip", "dst_ip", "user", "peer", "device") if raw.get(k)}
        candidates = db.scalars(select(ExceptionRule).where(ExceptionRule.tenant_id == tenant.id,
            ExceptionRule.rule == alert.rule, ExceptionRule.entity.in_(entities))).all() if entities else []
        matched = next((rule for rule in candidates
            if rule.reason and rule.reason.strip() and rule.approved_by and rule.approved_by.strip()
            and aware(rule.valid_from) <= aware(alert.event_at) < aware(rule.valid_until)
            and aware(rule.valid_from) <= now < aware(rule.valid_until)
            and isinstance(rule.scope, dict) and rule.scope
            and all(isinstance(key, str) and isinstance(value, str) and value
                    for key, value in rule.scope.items())
            and all(raw.get(key) == value for key, value in rule.scope.items())
            and all(rule.scope.get(key) == raw[key] for key in required_scope)
            and any(e.kind == "active_exception" and isinstance(e.data, dict)
                    and e.data.get("entity") == rule.entity
                    and e.data.get("approved_by") == rule.approved_by
                    and e.data.get("scope") == rule.scope for e in scoped_evidence)), None)
        if not matched:
            deny("no_current_approved_policy", "Нет действующего утверждённого FP-исключения с совпадающей областью")
        policy_ids.append(matched.id)
    return {"decision_id": decision.id, "policy_ids": policy_ids,
            "evidence_ids": list(decision.evidence_ids), "playbook_version": inv.playbook_version,
            "alert_ids": [a.id for a in linked]}


def update_case_status(db: Session, tenant: Tenant, case: Case, requested_status: str, actor: str) -> Action | None:
    """Persist an idempotent, policy-gated TheHive status change."""
    if not can_act(tenant, "update_case"):
        return None
    if not case.external_id:
        raise ValueError("Кейс не имеет внешнего ID")
    revision = int((case.data or {}).get("status_revision", 0))
    if case.status == requested_status:
        completed = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
            Action.idempotency_key == f"{case.id}:status:{revision}:{requested_status}",
            Action.status == "succeeded"))
        if completed:
            return completed
    key = f"{case.id}:status:{revision + 1}:{requested_status}"
    action = db.scalar(select(Action).where(Action.tenant_id == tenant.id, Action.idempotency_key == key))
    if action and action.status in {"succeeded", "unknown"}:
        return action
    if action and action.status == "pending":
        if action.attempted_at and utcnow() - aware(action.attempted_at) < timedelta(minutes=2):
            return action
        action.status = "unknown"
        db.commit()
        return action
    unresolved = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
        Action.kind == "update_case", Action.target == case.id,
        Action.status.in_(["pending", "unknown"]), Action.id != (action.id if action else "")))
    if unresolved:
        raise ValueError("Сначала сверьте предыдущее действие с неопределённым результатом")
    hive = thehive_adapter()
    creation = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
        Action.investigation_id == case.investigation_id, Action.kind == "create_case").limit(1))
    if not creation or hive.find_case(creation.idempotency_key) != case.external_id:
        raise ValueError("Связь кейса с расследованием не подтверждена в TheHive")
    allowed = {item["value"] for item in hive.case_statuses() if not item.get("hidden")}
    if requested_status not in allowed:
        raise ValueError("Статус недоступен в TheHive")
    if not action:
        action = Action(tenant_id=tenant.id, investigation_id=case.investigation_id,
                        kind="update_case", idempotency_key=key, target=case.id,
                        status="pending", detail={"requested_status": requested_status, "revision": revision + 1},
                        attempted_at=utcnow())
        db.add(action)
    else:
        action.status = "pending"
        action.attempted_at = utcnow()
        action.detail = {"requested_status": requested_status, "revision": revision + 1}
    db.commit()
    try:
        hive.update_status(case.external_id, requested_status)
        action.status = "succeeded"
        action.external_id = case.external_id
        action.detail = {"requested_status": requested_status, "revision": revision + 1,
                         "stage": "completed"}
        action.completed_at = utcnow()
        case.status = requested_status
        case.data = {**(case.data or {}), "last_status_update": requested_status,
                     "status_revision": revision + 1}
        audit(db, tenant.id, actor, "case_status_updated", "case", case.id,
              {"status": requested_status, "action_id": action.id})
    except Exception as exc:
        import httpx
        action.status = "unknown" if isinstance(exc, (TimeoutError, ConnectionError, httpx.RequestError)) else "failed"
        action.detail = {"requested_status": requested_status, "revision": revision + 1,
                         "error_type": type(exc).__name__}
        _integration(db, tenant.id, "thehive", "unavailable", type(exc).__name__)
        audit(db, tenant.id, actor, "case_status_update_unconfirmed", "case", case.id,
              {"status": requested_status, "action_id": action.id, "outcome": action.status})
    db.commit()
    return action


def reconcile_case_status(db: Session, tenant: Tenant, action: Action, case: Case, actor: str) -> Action:
    """Read external state before marking an ambiguous update as successful."""
    if action.status != "unknown" or action.kind != "update_case":
        return action
    requested = (action.detail or {}).get("requested_status")
    if not requested or not case.external_id:
        return action
    try:
        hive = thehive_adapter()
        creation = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
            Action.investigation_id == case.investigation_id, Action.kind == "create_case").limit(1))
        if not creation or hive.find_case(creation.idempotency_key) != case.external_id:
            raise AdapterError("Связь кейса с расследованием не подтверждена в TheHive")
        actual = hive.case_status(case.external_id)
    except Exception as exc:
        _integration(db, tenant.id, "thehive", "unavailable", type(exc).__name__)
        db.commit()
        return action
    if actual == requested:
        revision = max(int((case.data or {}).get("status_revision", 0)),
                       int((action.detail or {}).get("revision", 0)))
        action.status = "succeeded"
        action.external_id = case.external_id
        action.detail = {**(action.detail or {}), "stage": "completed"}
        action.completed_at = utcnow()
        case.status = requested
        case.data = {**(case.data or {}), "last_status_update": requested,
                     "status_revision": revision}
        audit(db, tenant.id, actor, "case_status_reconciled", "case", case.id,
              {"status": requested, "action_id": action.id})
        db.commit()
    return action


def _case_step_key(case_id: str, kind: str, payload: dict) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{case_id}:{kind}:{sha256(canonical.encode('utf-8')).hexdigest()[:20]}"


def _case_write_plan(db: Session, tenant: Tenant, inv: Investigation, case: Case,
                     action: Action, evidence: list[Evidence]) -> list[CaseWrite]:
    """Freeze every intended remote mutation before sending the first request."""
    existing = db.scalars(select(CaseWrite).where(CaseWrite.tenant_id == tenant.id,
        CaseWrite.case_id == case.id).order_by(CaseWrite.sequence)).all()
    if existing:
        return existing
    alerts = db.scalars(select(Alert).where(Alert.tenant_id == tenant.id,
        Alert.investigation_id == inv.id).order_by(Alert.event_at, Alert.id)).all()
    alert_lines = [f"{item.source}:{item.source_event_id} | {aware(item.event_at).isoformat()} | {item.rule}"
                   for item in alerts[:50]]
    description = "\n".join([
        "SOC L1: создано по подтверждённой эскалации.",
        f"Расследование: {inv.id}",
        f"Плейбук: {inv.playbook_key} {inv.playbook_version}",
        f"Вердикт: {inv.verdict or 'не определён'}; приоритет: {inv.priority}",
        f"Анализатор: {inv.analyzer}",
        f"Вывод: {inv.rationale[:3000]}",
        "Исходные алерты:", *alert_lines,
        f"Недостающие данные: {', '.join(str(x) for x in inv.missing_data[:20]) or 'не указаны'}",
        f"Рекомендации: {', '.join(str(x) for x in inv.recommended_actions[:20]) or 'проверить аналитиком'}",
    ])[:10_000]
    page_content = "\n".join(
        f"{item.id} | {item.kind} | {item.source} | {aware(item.event_at).isoformat() if item.event_at else 'время неизвестно'} | {item.summary[:300]}"
        for item in evidence[:50]
    )[:20_000]
    steps: list[tuple[str, dict, str]] = [
        ("create_case", {"title": inv.summary[:300], "description": description}, action.idempotency_key),
        ("evidence_page", {"title": "Доказательства SOC L1", "category": "SOC L1",
                           "content": page_content or "Доказательства пока не представлены."}, ""),
    ]
    seen_observables: set[tuple[str, str]] = set()
    for item in evidence[:20]:
        data = item.data if isinstance(item.data, dict) else {}
        value = data.get("observable")
        if value is None or not str(value).strip():
            continue
        data_type = str(data.get("observable_type") or "ip")[:60]
        value_text = str(value)[:1000]
        signature = (data_type, value_text)
        if signature in seen_observables:
            continue
        seen_observables.add(signature)
        steps.append(("observable", {"dataType": data_type, "data": value_text,
                                     "message": item.summary[:500]}, ""))
    steps.append(("task", {"title": "Проверить и принять эскалацию SOC L1"}, ""))
    writes = [CaseWrite(tenant_id=tenant.id, investigation_id=inv.id, case_id=case.id,
                        sequence=index, kind=kind, idempotency_key=key or _case_step_key(case.id, kind, payload),
                        request_data=payload, status="pending", attempts=0)
              for index, (kind, payload, key) in enumerate(steps)]
    if action.status in {"unknown", "failed"} or action.detail:
        # Older unfinished actions have no step journal. Assume every previously
        # possible remote write may have happened and require readback first.
        for write in writes:
            write.status = "unknown"
            write.attempted_at = action.attempted_at or utcnow()
        if action.external_id:
            writes[0].status = "succeeded"
            writes[0].external_id = action.external_id
            writes[0].completed_at = utcnow()
    db.add_all(writes)
    db.flush()
    audit(db, tenant.id, "worker", "case_write_plan_created", "case", case.id,
          {"write_ids": [item.id for item in writes], "kinds": [item.kind for item in writes]})
    db.commit()
    return writes


def _case_write_uncertain(exc: Exception) -> bool:
    """Only a definite client rejection is known not to have changed TheHive."""
    import httpx
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status in {408, 409, 429}
    return True


def _case_write_outcome(db: Session, tenant: Tenant, case: Case, action: Action,
                        write: CaseWrite, status: str, error_type: str | None = None) -> None:
    write.status = status
    write.error_type = error_type
    if status == "succeeded":
        write.completed_at = utcnow()
        if write.kind == "create_case":
            case.external_id = write.external_id
            action.external_id = write.external_id
            case.status = "pending_enrichment"
    else:
        action.status = status
        action.detail = {"stage": write.kind, "case_write_id": write.id,
                         "error_type": error_type}
        action.attempted_at = utcnow()
        case.status = "enrichment_unknown" if status == "unknown" else "enrichment_failed"
    audit(db, tenant.id, "worker", "case_write_" + status, "case_write", write.id,
          {"kind": write.kind, "case_id": case.id, "external_id": write.external_id,
           "error_type": error_type})
    db.commit()


def _perform_case_action(db: Session, tenant: Tenant, inv: Investigation, alert: Alert,
                         evidence: list[Evidence], action: Action) -> Action:
    case = db.scalar(select(Case).where(Case.tenant_id == tenant.id,
        Case.investigation_id == inv.id).with_for_update())
    if not case:
        case = Case(tenant_id=tenant.id, investigation_id=inv.id, title=inv.summary, status="pending")
        db.add(case)
        db.flush()
        db.commit()
    writes = _case_write_plan(db, tenant, inv, case, action, evidence)
    for write in writes:
        if write.status == "succeeded":
            continue
        if write.status == "failed":
            _case_write_outcome(db, tenant, case, action, write, "failed", write.error_type)
            return action
        try:
            hive = thehive_adapter()
            if write.kind != "create_case":
                linked_id = hive.find_case(action.idempotency_key)
                if not linked_id or str(linked_id) != str(case.external_id):
                    _case_write_outcome(db, tenant, case, action, write, "unknown", "CaseLinkUnconfirmed")
                    return action
            if write.status == "unknown" or write.attempted_at is not None:
                if write.status != "unknown":
                    _case_write_outcome(db, tenant, case, action, write, "unknown", "InterruptedWrite")
                found = (hive.find_case(write.idempotency_key) if write.kind == "create_case"
                         else hive.find_case_step(case.external_id, write.kind, write.request_data,
                                                  write.idempotency_key))
                if not found:
                    _case_write_outcome(db, tenant, case, action, write, "unknown", "ReadbackUnconfirmed")
                    return action
                write.external_id = str(found)
                _case_write_outcome(db, tenant, case, action, write, "succeeded")
                continue
            if write.kind != "create_case" and not case.external_id:
                _case_write_outcome(db, tenant, case, action, write, "unknown", "CaseIdMissing")
                return action
            write.attempted_at = utcnow()
            write.attempts += 1
            audit(db, tenant.id, "worker", "case_write_attempted", "case_write", write.id,
                  {"kind": write.kind, "case_id": case.id, "idempotency_key": write.idempotency_key})
            db.commit()
            if write.kind == "create_case":
                if alert.raw.get("scenario_signal") == "thehive_unavailable" and settings().mode.upper() == "DEMO":
                    raise AdapterError("Симулированная недоступность TheHive")
                result = hive.create_case(write.request_data["title"], write.request_data["description"],
                                          write.idempotency_key)
            else:
                result = hive.write_case_step(case.external_id, write.kind, write.request_data,
                                              write.idempotency_key)
            if not result:
                raise AdapterError("TheHive не подтвердил запись")
            write.external_id = str(result)
            _case_write_outcome(db, tenant, case, action, write, "succeeded")
            if write.kind == "create_case" and alert.raw.get("scenario_signal") == "action_unknown" and settings().mode.upper() == "DEMO":
                # Exercise recovery after the case exists but before enrichment.
                action.status = "unknown"
                action.detail = {"stage": "case_created", "case_write_id": write.id,
                                 "error_type": "SimulatedInterruption"}
                case.status = "pending_enrichment"
                audit(db, tenant.id, "worker", "case_enrichment_interrupted", "case", case.id,
                      {"case_write_id": write.id})
                db.commit()
                return action
        except Exception as exc:
            outcome = "unknown" if _case_write_uncertain(exc) else "failed"
            _case_write_outcome(db, tenant, case, action, write, outcome, type(exc).__name__)
            _integration(db, tenant.id, "thehive", "unavailable", type(exc).__name__)
            db.commit()
            return action
    action.status = "succeeded"
    action.external_id = case.external_id
    action.detail = {"stage": "completed", "case_write_ids": [item.id for item in writes]}
    action.attempted_at = utcnow()
    action.completed_at = utcnow()
    case.status = "open"
    case.data = {"demo": settings().mode.upper() == "DEMO",
                 "evidence_ids": [item.id for item in evidence[:50]],
                 "observables": [item.request_data for item in writes if item.kind == "observable"],
                 "tasks": [item.request_data["title"] for item in writes if item.kind == "task"],
                 "case_write_ids": [item.id for item in writes]}
    audit(db, tenant.id, "worker", "action_succeeded", "action", action.id,
          {"kind": "create_case", "external_id": case.external_id,
           "case_write_ids": [item.id for item in writes]})
    db.commit()
    return action


def perform_action(db: Session, tenant: Tenant, inv: Investigation, alert: Alert, kind: str,
                   evidence: list[Evidence]) -> Action | None:
    if not can_act(tenant, kind):
        return None
    # Serialize competing case creation and alert closure on the investigation.
    # The pending action is committed before an external call, so the next worker
    # sees it after acquiring this lock and cannot issue an incompatible write.
    if not db.scalar(select(Investigation).where(Investigation.tenant_id == tenant.id,
            Investigation.id == inv.id).with_for_update()):
        raise ValueError("Расследование не найдено для действия")
    if kind == "close_alert" and (db.scalar(select(Case.id).where(
            Case.tenant_id == tenant.id, Case.investigation_id == inv.id).limit(1))
            or db.scalar(select(Action.id).where(Action.tenant_id == tenant.id,
                Action.investigation_id == inv.id, Action.kind == "create_case").limit(1))):
        audit(db, tenant.id, "policy", "action_denied_conflict", "investigation", inv.id,
              {"kind": kind, "reason": "case_exists"})
        db.commit()
        return None
    if kind == "create_case" and db.scalar(select(Action.id).where(Action.tenant_id == tenant.id,
            Action.investigation_id == inv.id, Action.kind == "close_alert",
            Action.status.in_(["pending", "unknown"])).limit(1)):
        audit(db, tenant.id, "policy", "action_denied_conflict", "investigation", inv.id,
              {"kind": kind, "reason": "close_unresolved"})
        db.commit()
        return None
    key = f"{inv.id}:{kind}:{alert.id if kind == 'close_alert' else 'case'}"
    action = db.scalar(select(Action).where(Action.tenant_id == tenant.id, Action.idempotency_key == key))
    if action and action.status == "succeeded":
        return action
    if not action:
        action = Action(tenant_id=tenant.id, investigation_id=inv.id, kind=kind, status="pending",
                        idempotency_key=key, target=alert.source_event_id if kind == "close_alert" else inv.id,
                        attempted_at=utcnow())
        db.add(action)
        if kind == "create_case":
            case = db.scalar(select(Case).where(Case.tenant_id == tenant.id,
                Case.investigation_id == inv.id))
            if not case:
                case = Case(tenant_id=tenant.id, investigation_id=inv.id,
                            title=inv.summary, status="pending")
                db.add(case)
            db.flush()
            _case_write_plan(db, tenant, inv, case, action, evidence)
        else:
            db.commit()
    elif action.status == "pending":
        if action.attempted_at and utcnow() - aware(action.attempted_at) < timedelta(minutes=2):
            return action
        # The worker may have stopped during an external write. Reconcile first.
        action.status = "unknown"
        db.commit()
    if kind == "create_case":
        return _perform_case_action(db, tenant, inv, alert, evidence, action)
    try:
        if action.status == "unknown":
            if kind == "close_alert" and settings().mode.upper() == "DEMO":
                external_id = f"demo-close:{alert.source_event_id}"
            else:
                return action
        elif kind == "close_alert":
            splunk = splunk_adapter()
            result = splunk.close_alert(alert.source_event_id, key)
            external_id = result.get("external_id")
        else:
            # These two actions are deliberately simulator-only.
            if settings().mode.upper() != "DEMO":
                raise AdapterError("Реальное воздействие для этого действия не реализовано")
            external_id = f"demo:{kind}:{inv.id}"
        action.status = "succeeded"
        action.external_id = external_id
        action.detail = {"stage": "completed"}
        action.attempted_at = utcnow()
        action.completed_at = utcnow()
        audit(db, tenant.id, "worker", "action_succeeded", "action", action.id, {"kind": kind, "external_id": external_id})
    except Exception as exc:
        action.status = "unknown" if isinstance(exc, (TimeoutError, ConnectionError)) else "failed"
        # httpx network failure can be ambiguous after request transmission.
        import httpx
        if isinstance(exc, httpx.RequestError):
            action.status = "unknown"
        action.detail = {**(action.detail or {}), "error_type": type(exc).__name__, "message": str(exc)[:300]}
        action.attempted_at = utcnow()
        _integration(db, tenant.id, "splunk", "unavailable", type(exc).__name__)
        audit(db, tenant.id, "worker", "action_failed_or_unknown", "action", action.id,
              {"kind": kind, "status": action.status, "error_type": type(exc).__name__})
    db.commit()
    return action


def process_alert(db: Session, alert_id: str) -> None:
    deadline = monotonic() + max(settings().investigation_timeout_seconds, 1)
    alert = db.scalar(select(Alert).where(Alert.id == alert_id).with_for_update())
    if not alert or alert.status in {"completed", "auto_closed", "escalated"}:
        return
    if alert.status == "running" and alert.claimed_at and utcnow() - aware(alert.claimed_at) < timedelta(minutes=2):
        return
    inv = db.scalar(select(Investigation).where(Investigation.id == alert.investigation_id,
                                                 Investigation.tenant_id == alert.tenant_id).with_for_update())
    tenant = db.scalar(select(Tenant).where(Tenant.id == alert.tenant_id))
    if not inv or not tenant:
        raise RuntimeError("Связи заказчика или расследования не найдены")
    if inv.status == "running" and inv.claimed_at and utcnow() - aware(inv.claimed_at) < timedelta(minutes=2):
        return
    inv.status = "running"
    inv.started_at = inv.started_at or utcnow()
    inv.claimed_at = utcnow()
    alert.status = "running"
    alert.claimed_at = utcnow()
    playbook = select_playbook(alert.rule)
    run = PlaybookRun(tenant_id=tenant.id, investigation_id=inv.id, key=playbook.key, version=playbook.version)
    db.add(run)
    db.commit()
    evidence, context_ok, steps = collect(db, alert, inv)
    if len(evidence) > settings().max_evidence_items:
        evidence = evidence[:settings().max_evidence_items]
        context_ok = False
        steps.append({"step": "evidence_limit", "status": "limited"})
    records = [{"id": e.id, "kind": e.kind, "source": e.source, "summary": e.summary, "data": e.data} for e in evidence]
    baseline = playbook.decision_rule(alert.raw, records, context_ok)
    if monotonic() >= deadline:
        from .playbooks import Verdict
        decision = Verdict(verdict="needs_review", priority=baseline.priority, summary="Превышено время расследования",
                           rationale="Истёк лимит времени обработки; требуется ручная проверка.",
                           evidence_ids=[e.id for e in evidence], missing_data=["Проверить доступность источников"],
                           recommended_actions=["review"])
        analyzer = "timeout"
        steps.append({"step": "time_budget", "status": "limited"})
    elif alert.raw.get("scenario_signal") == "llm_error" and settings().mode.upper() == "DEMO":
        from .playbooks import Verdict
        decision = Verdict(verdict="needs_review", priority=baseline.priority, summary="Ошибка анализа модели",
                           rationale="Симулированный сбой модели; нужен ручной анализ.",
                           evidence_ids=[e.id for e in evidence], recommended_actions=["review"])
        analyzer = "model_error"
    else:
        decision, analyzer = model_analyze(records, baseline)
        if monotonic() >= deadline:
            from .playbooks import Verdict
            decision = Verdict(verdict="needs_review", priority=baseline.priority, summary="Превышено время расследования",
                               rationale="Истёк лимит времени обработки; требуется ручная проверка.",
                               evidence_ids=[e.id for e in evidence], missing_data=["Проверить доступность источников"],
                               recommended_actions=["review"])
            analyzer = "timeout"
            steps.append({"step": "time_budget", "status": "limited"})
    if analyzer in {"local_model", "external_model"} and decision.verdict != baseline.verdict:
        from .playbooks import Verdict
        decision = Verdict(verdict="needs_review", priority=baseline.priority,
                           summary="Требуется ручная проверка расхождения",
                           rationale="Вердикт модели не совпал с проверяемым правилом плейбука; автоматическое действие запрещено.",
                           evidence_ids=[e.id for e in evidence],
                           missing_data=["Проверить причину расхождения модели и плейбука"],
                           recommended_actions=["review"])
        steps.append({"step": "model_disagreement", "status": "needs_review"})
    known_ids = {e.id for e in evidence}
    if not set(decision.evidence_ids).issubset(known_ids) or (decision.verdict != "needs_review" and not decision.evidence_ids):
        raise ValueError("Решение с некорректными доказательствами")
    inv.playbook_key, inv.playbook_version = playbook.key, playbook.version
    inv.verdict, inv.priority = decision.verdict, decision.priority
    inv.summary, inv.rationale = decision.summary, decision.rationale
    inv.missing_data, inv.recommended_actions = decision.missing_data, decision.recommended_actions
    inv.analyzer = analyzer
    inv.completed_at = utcnow()
    run.steps = steps + [{"step": "decision", "status": "succeeded", "verdict": decision.verdict}]
    run.status, run.completed_at = "completed", utcnow()
    db.add(Decision(tenant_id=tenant.id, investigation_id=inv.id, verdict=decision.verdict,
                    priority=decision.priority, summary=decision.summary, rationale=decision.rationale,
                    evidence_ids=decision.evidence_ids, missing_data=decision.missing_data,
                    recommended_actions=decision.recommended_actions, actor=analyzer))
    audit(db, tenant.id, analyzer, "decision", "investigation", inv.id, {"verdict": decision.verdict, "playbook": playbook.key})
    db.commit()
    if decision.verdict == "false_positive" and decision.auto_close_eligible:
        if settings().auto_close_enabled:
            action = perform_action(db, tenant, inv, alert, "close_alert", evidence)
            status = "auto_closed" if action and action.status == "succeeded" else "needs_review"
        else:
            status = "needs_review"
            run.steps = [*run.steps, {"step": "auto_close_gate", "status": "denied", "reason": "globally_disabled"}]
            audit(db, tenant.id, "policy", "auto_close_denied", "investigation", inv.id,
                  {"reason": "globally_disabled", "alert_id": alert.id})
    elif decision.verdict == "true_positive":
        action = perform_action(db, tenant, inv, alert, "create_case", evidence)
        status = "escalated" if action and action.status == "succeeded" else "needs_review"
    else:
        status = "needs_review" if decision.verdict == "needs_review" else "completed"
    inv.status = status
    alert.status = status
    alert.processed_at = utcnow()
    db.commit()
