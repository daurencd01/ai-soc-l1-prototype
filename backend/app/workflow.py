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
from .adapters import (AdapterAmbiguousError, AdapterError, misp_adapter, splunk_adapter,
                       thehive_adapter, validate_case_fields)
from .analyzer import model_analyze
from .case_builder import build_case_plan
from .config import settings
from .ingestion import SecurityAlert, compatible_for_correlation, normalize_alert
from .models import (Action, Alert, AlertFingerprint, Asset, Audit, Case, CaseWrite, Decision, EmbeddedEvent, Evidence,
                     ExceptionRule, IntegrationState, Investigation, Maintenance, PlaybookRun,
                     SuppressionRule, Tenant, utcnow)
from .playbooks import Verdict, select_playbook
from .policy import is_effective
from .security import audit
from .state import PipelineState, move_alert, record_initial
from .suppression import is_effective as suppression_is_effective


def aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def ingest(db: Session, tenant_id: str, payload: dict, _attempt: int = 0) -> tuple[Alert, bool]:
    config = settings()
    normalized = normalize_alert(
        payload, tenant_id, now=utcnow(),
        fingerprint_ttl_seconds=config.fingerprint_ttl_seconds,
        correlation_window_seconds=config.correlation_window_seconds,
    )
    source, source_id = normalized.alert.source, normalized.alert.event_id

    def duplicate(item: Alert, reason: str) -> tuple[Alert, bool]:
        audit(db, tenant_id, "ingest", "alert_deduplicated", "alert", item.id,
              {"source": source, "source_event_id": source_id, "reason": reason})
        db.commit()
        return item, False

    existing = db.scalar(select(Alert).where(Alert.tenant_id == tenant_id, Alert.source == source,
                                             Alert.source_event_id == source_id))
    if existing:
        return duplicate(existing, "source_event_id")

    def active_fingerprint() -> tuple[AlertFingerprint | None, Alert | None]:
        claim = db.scalar(select(AlertFingerprint).where(
            AlertFingerprint.tenant_id == tenant_id,
            AlertFingerprint.fingerprint == normalized.fingerprint).with_for_update())
        if claim and aware(claim.expires_at) > normalized.alert.ingestion_time:
            original = db.get(Alert, claim.alert_id)
            if original and original.tenant_id == tenant_id:
                return claim, original
        return claim, None

    claim, original = active_fingerprint()
    if original:
        return duplicate(original, "fingerprint")

    rule = normalized.alert.rule_id or "generic"
    playbook = select_playbook(rule)
    raw_time = payload["event_at"]
    if isinstance(raw_time, datetime):
        source_zone = raw_time.tzinfo
    elif isinstance(raw_time, str):
        try:
            source_zone = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).tzinfo
        except ValueError:
            source_zone = timezone.utc
    else:
        source_zone = timezone.utc
    original_timezone = str(payload.get("original_timezone") or source_zone or "UTC")[:80]

    def compatible_link(item: Alert) -> bool:
        if not isinstance(item.normalized, dict):
            return False
        try:
            prior = SecurityAlert.model_validate(item.normalized)
        except ValueError:
            return False
        return compatible_for_correlation(
            prior, normalized.alert, max_delta_seconds=config.correlation_window_seconds)

    try:
        correlation_key = normalized.correlation_key
        suffix = 0
        while True:
            inv = db.scalar(select(Investigation).where(
                Investigation.tenant_id == tenant_id,
                Investigation.correlation_key == correlation_key).with_for_update())
            if not inv:
                inv = Investigation(tenant_id=tenant_id, correlation_key=correlation_key,
                                    playbook_key=playbook.key, playbook_version=playbook.version,
                                    due_at=utcnow() + timedelta(minutes=15))
                db.add(inv)
                db.flush()
                break
            linked = db.scalars(select(Alert).where(Alert.tenant_id == tenant_id,
                                                   Alert.investigation_id == inv.id)).all()
            if linked and all(compatible_link(item) for item in linked):
                break
            # A supplied correlation key never authorizes an otherwise unsafe merge.
            suffix += 1
            correlation_key = sha256(
                f"{normalized.correlation_key}:{normalized.fingerprint}:{source_id}:{suffix}".encode()
            ).hexdigest()

        alert = Alert(
            tenant_id=tenant_id, investigation_id=inv.id, source=source,
            source_event_id=source_id, rule=rule,
            title=str(payload.get("title") or normalized.alert.rule_name or rule or source_id)[:300],
            severity=(normalized.alert.severity or "unknown")[:20],
            event_at=normalized.alert.event_time, original_timezone=original_timezone,
            raw=normalized.original_raw, normalized=normalized.alert.model_dump(mode="json"),
            fingerprint=normalized.fingerprint,
        )
        db.add(alert)
        db.flush()
        if claim:
            claim.alert_id = alert.id
            claim.expires_at = normalized.fingerprint_expires_at
            claim.created_at = normalized.alert.ingestion_time
        else:
            db.add(AlertFingerprint(
                tenant_id=tenant_id, fingerprint=normalized.fingerprint,
                alert_id=alert.id, expires_at=normalized.fingerprint_expires_at,
                created_at=normalized.alert.ingestion_time))
        record_initial(db, alert)
        for idx, event in enumerate((payload.get("events") or [])[:100]):
            if isinstance(event, dict):
                dt = event.get("event_at")
                if dt:
                    source_event_time = datetime.fromisoformat(str(dt).replace("Z", "+00:00"))
                    if source_event_time.tzinfo is None or source_event_time.utcoffset() is None:
                        raise ValueError("Вложенное event_at должно содержать часовое смещение")
                    when = source_event_time.astimezone(timezone.utc)
                else:
                    when = normalized.alert.event_time
                db.add(EmbeddedEvent(
                    tenant_id=tenant_id, alert_id=alert.id,
                    source_event_id=str(event.get("source_event_id") or f"{source_id}:{idx}")[:256],
                    event_at=when,
                    original_timezone=str(event.get("original_timezone") or alert.original_timezone)[:80],
                    data=event))
        audit(db, tenant_id, "ingest", "alert_received", "alert", alert.id,
              {"source": source, "source_event_id": source_id,
               "investigation_id": inv.id, "fingerprint": normalized.fingerprint})
        db.commit()
        return alert, True
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(Alert).where(Alert.tenant_id == tenant_id, Alert.source == source, Alert.source_event_id == source_id))
        if existing:
            return duplicate(existing, "source_event_id")
        _, original = active_fingerprint()
        if original:
            return duplicate(original, "fingerprint")
        if _attempt == 0:
            return ingest(db, tenant_id, payload, _attempt=1)
        raise
    except Exception:
        db.rollback()
        raise


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
    if status == "unavailable":
        audit(db, tenant_id, "integration", "integration_error", "integration", name,
              {"error_type": detail[:100]})


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
            active = is_effective(db, exc, raw, alert.event_at)
            _ev(db, inv, "active_exception" if active else "expired_exception", "local_policy",
                f"Исключение {exc.id}: {'действует' if active else 'не утверждено, отозвано, истекло или не совпадает область'}",
                {"policy_id": exc.id, "entity": entity, "reason": exc.reason, "scope": exc.scope,
                 "version": exc.version, "approval_status": exc.approval_status,
                 "valid_from": exc.valid_from.isoformat(), "valid_until": exc.valid_until.isoformat(),
                 "approved_by": exc.approved_by})
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
            earliest = alert.event_at - timedelta(hours=1)
            latest = alert.event_at + timedelta(hours=1)
            rule_search = getattr(splunk, "related_events_for_rule", None)
            related = (rule_search(alert.rule, entities[0], earliest, latest) if callable(rule_search)
                       else splunk.related_events(entities[0], earliest, latest))
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
    if level in {"disabled", "observe", "recommend"}:
        return False
    if level not in {"controlled_automation", "auto_close", "approved_response"}:
        return False
    if kind == "suppress_noise" and level not in {"controlled_automation", "approved_response"}:
        return False
    if kind in {"update_case", "disable_account_demo", "isolate_host_demo"} and level not in {
            "controlled_automation", "approved_response"}:
        return False
    if mode == "DEMO":
        return kind in {"close_alert", "create_case", "update_case", "suppress_noise",
                        "disable_account_demo", "isolate_host_demo"}
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

    if inv.verdict != "false_positive" or inv.classification != "FP":
        deny("verdict", "Закрытие требует подтверждённой классификации FP")
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
    if (not decision or decision.verdict != "false_positive" or decision.classification != "FP"
            or decision.missing_data
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
            if is_effective(db, rule, raw, alert.event_at, now)
            and all(rule.scope.get(key) == raw[key] for key in required_scope)
            and any(e.kind == "active_exception" and isinstance(e.data, dict)
                    and e.data.get("policy_id") == rule.id
                    and e.data.get("entity") == rule.entity
                    and e.data.get("approved_by") == rule.approved_by
                    and e.data.get("scope") == rule.scope for e in scoped_evidence)), None)
        if not matched:
            deny("no_current_approved_policy", "Нет действующего утверждённого FP-исключения с совпадающей областью")
        policy_ids.append(matched.id)
    return {"decision_id": decision.id, "policy_ids": policy_ids,
            "evidence_ids": list(decision.evidence_ids), "playbook_version": inv.playbook_version,
            "alert_ids": [a.id for a in linked]}


def noise_suppression_gate(db: Session, tenant: Tenant, inv: Investigation, alert: Alert,
                           evidence: list[Evidence], baseline: Verdict) -> tuple[dict | None, str]:
    """Authorize a local grouping record; never close Splunk or a TheHive case."""
    if not can_act(tenant, "suppress_noise"):
        return None, "automation_level"
    if (alert.rule != "ipsec_failure" or inv.playbook_key != alert.rule
            or baseline.classification != "NOISE" or inv.classification != "NOISE"
            or baseline.missing_data or inv.missing_data):
        return None, "deterministic_rule"
    if str(alert.severity).lower() not in {"low", "medium"} or inv.priority != "low":
        return None, "critical_or_unknown_severity"
    required = ("peer", "device", "tunnel", "failure_reason")
    raw = alert.raw if isinstance(alert.raw, dict) else {}
    if any(not isinstance(raw.get(key), str) or not raw[key] for key in required):
        return None, "missing_scope"
    linked = db.scalars(select(Alert).where(Alert.tenant_id == tenant.id,
        Alert.investigation_id == inv.id).with_for_update()).all()
    if (not linked or any(item.rule != alert.rule or str(item.severity).lower() not in {"low", "medium"}
                          or not isinstance(item.raw, dict)
                          or any(item.raw.get(key) != raw[key] for key in required)
                          or item.status == "escalated" or item.pipeline_state == PipelineState.CASE_CREATED
                          for item in linked)):
        return None, "linked_alert_conflict"
    if db.scalar(select(Case.id).where(Case.tenant_id == tenant.id,
        Case.investigation_id == inv.id).limit(1)) or db.scalar(select(Action.id).where(
            Action.tenant_id == tenant.id, Action.investigation_id == inv.id,
            Action.kind == "create_case").limit(1)):
        return None, "case_exists"
    if settings().mode.upper() == "CONNECTED":
        try:
            if thehive_adapter().find_case(f"{inv.id}:create_case:case"):
                return None, "external_case_exists"
        except Exception:
            return None, "thehive_unavailable"
    evidence_by_id = {item.id: item for item in evidence
                      if item.tenant_id == tenant.id and item.investigation_id == inv.id}
    if not evidence_by_id or any(item.kind == "integration_error" for item in evidence_by_id.values()):
        return None, "insufficient_evidence"
    support_ids = {claim.evidence_id for claim in baseline.evidence_for}
    support_kinds = {evidence_by_id[item_id].kind for item_id in support_ids if item_id in evidence_by_id}
    if (not support_ids or not support_ids.issubset(evidence_by_id)
            or not set(baseline.evidence_ids).issubset(evidence_by_id)
            or not {"raw_alert", "asset"}.issubset({item.kind for item in evidence_by_id.values()})
            or not ({"embedded_event", "related_event"} & support_kinds)
            or "asset" not in support_kinds
            or not ({"approved_maintenance", "active_exception"} & support_kinds)):
        return None, "insufficient_evidence"
    decision = db.scalar(select(Decision).where(Decision.tenant_id == tenant.id,
        Decision.investigation_id == inv.id).order_by(Decision.created_at.desc(), Decision.id.desc()).limit(1))
    if (not decision or decision.classification != "NOISE" or decision.verdict != "needs_review"
            or decision.missing_data or not decision.evidence_ids
            or not set(decision.evidence_ids).issubset(evidence_by_id)
            or not db.scalar(select(Audit.id).where(Audit.tenant_id == tenant.id,
                Audit.operation == "decision", Audit.subject_type == "investigation",
                Audit.subject_id == inv.id).limit(1))):
        return None, "decision_unverified"
    peer = db.scalar(select(Asset).where(Asset.tenant_id == tenant.id, Asset.kind == "vpn_peer",
        Asset.value == raw["peer"]).limit(1))
    if (not peer or not isinstance(peer.attributes, dict) or peer.attributes.get("allowed") is not True
            or peer.attributes.get("device") != raw["device"]
            or peer.attributes.get("tunnel") != raw["tunnel"]):
        return None, "peer_not_current"
    now = utcnow()
    windows = db.scalars(select(Maintenance).where(Maintenance.tenant_id == tenant.id,
        Maintenance.entity == raw["peer"])).all()
    if not any(aware(item.valid_from) <= aware(alert.event_at) < aware(item.valid_until)
               and aware(item.valid_from) <= aware(now) < aware(item.valid_until)
               and isinstance(item.scope, dict)
               and all(item.scope.get(key) == raw[key] for key in ("peer", "device", "tunnel"))
               for item in windows):
        return None, "maintenance_not_current"
    policies = db.scalars(select(SuppressionRule).where(SuppressionRule.tenant_id == tenant.id,
        SuppressionRule.rule == alert.rule, SuppressionRule.entity == raw["peer"])).all()
    policy = next((item for item in policies
                   if suppression_is_effective(db, item, raw, alert.event_at, now)), None)
    if not policy:
        return None, "no_current_approved_policy"
    group_input = json.dumps({"tenant": tenant.id, "rule": alert.rule,
                              "scope": policy.scope}, sort_keys=True, separators=(",", ":"))
    return {"policy_id": policy.id, "policy_version": policy.version,
            "decision_id": decision.id, "evidence_ids": list(decision.evidence_ids),
            "group_key": sha256(group_input.encode()).hexdigest()[:24]}, "approved"


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
        unresolved_before_return = db.scalar(select(Action.id).where(Action.tenant_id == tenant.id,
            Action.kind.in_(["update_case", "update_case_fields"]), Action.target == case.id,
            Action.status.in_(["pending", "unknown"])).limit(1))
        if completed and not unresolved_before_return:
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
        Action.kind.in_(["update_case", "update_case_fields"]), Action.target == case.id,
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
    # The local case row may lag behind an analyst's change in TheHive. Refuse
    # to overwrite that change until the case is reconciled explicitly.
    expected_status = "Open" if case.status == "open" else case.status
    if expected_status not in allowed:
        raise ValueError("Кейс ещё не готов к изменению статуса")
    actual_status = hive.case_status(case.external_id)
    if actual_status != expected_status:
        raise ValueError("Статус кейса в TheHive отличается от локального; требуется сверка")
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
        if actual_status != requested_status:
            hive.update_status(case.external_id, requested_status)
        if hive.case_status(case.external_id) != requested_status:
            raise AdapterAmbiguousError("TheHive не подтвердил новый статус кейса")
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
        action.status = "unknown" if _case_write_uncertain(exc) else "failed"
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


def _field_digest(value: object) -> str:
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")).hexdigest()


def _record_case_fields(case: Case, changes: dict) -> None:
    hashes = dict((case.data or {}).get("remote_field_hashes") or {})
    hashes.update({field: _field_digest(value) for field, value in changes.items()})
    case.data = {**(case.data or {}), "remote_field_hashes": hashes}
    if "title" in changes:
        case.title = changes["title"]


def _check_case_field_drift(db: Session, tenant: Tenant, case: Case, actual: dict) -> None:
    hashes = (case.data or {}).get("remote_field_hashes") or {}
    if not isinstance(hashes, dict):
        raise ValueError("Сохранённые поля кейса повреждены")
    created = db.scalar(select(CaseWrite).where(CaseWrite.tenant_id == tenant.id,
        CaseWrite.case_id == case.id, CaseWrite.kind == "create_case").limit(1))
    initial = created.request_data if created and isinstance(created.request_data, dict) else {}
    for field, value in actual.items():
        expected = hashes.get(field) or (_field_digest(initial[field]) if field in initial else None)
        if expected and _field_digest(value) != expected:
            raise ValueError("Поле кейса в TheHive отличается от локального; требуется сверка")


def update_case_fields(db: Session, tenant: Tenant, case: Case, changes: dict, actor: str) -> Action | None:
    """Persist one allowlisted case update before issuing a remote PATCH."""
    if not can_act(tenant, "update_case"):
        return None
    fields = validate_case_fields(changes)
    if "title" in fields and len(fields["title"]) > 300:
        raise ValueError("Заголовок кейса превышает локальный лимит 300 символов")
    if (case.tenant_id != tenant.id or not case.external_id or not case.status
            or case.status in {"pending", "pending_enrichment", "enrichment_unknown", "enrichment_failed"}):
        raise ValueError("Кейс не готов к изменению полей")
    revision = int((case.data or {}).get("fields_revision", 0))
    digest = _field_digest(fields)[:24]
    key = f"{case.id}:fields:{revision + 1}:{digest}"
    action = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
        Action.idempotency_key == key))
    unresolved = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
        Action.kind.in_(["update_case", "update_case_fields"]), Action.target == case.id,
        Action.status.in_(["pending", "unknown"]), Action.id != (action.id if action else "")))
    if unresolved:
        raise ValueError("Сначала сверьте предыдущее действие с неопределённым результатом")
    if action and action.status == "unknown":
        return action
    if action and action.status == "pending":
        if action.attempted_at and utcnow() - aware(action.attempted_at) < timedelta(minutes=2):
            return action
        action.status = "unknown"
        db.commit()
        return action
    if revision:
        completed = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
            Action.idempotency_key == f"{case.id}:fields:{revision}:{digest}",
            Action.status == "succeeded"))
        if completed:
            return completed
    hive = thehive_adapter()
    creation = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
        Action.investigation_id == case.investigation_id, Action.kind == "create_case").limit(1))
    if not creation or hive.find_case(creation.idempotency_key) != case.external_id:
        raise ValueError("Связь кейса с расследованием не подтверждена в TheHive")
    expected_status = "Open" if case.status == "open" else case.status
    if hive.case_status(case.external_id) != expected_status:
        raise ValueError("Статус кейса в TheHive отличается от локального; требуется сверка")
    current = hive.case_fields(case.external_id, list(fields))
    _check_case_field_drift(db, tenant, case, current)
    if not action:
        action = Action(tenant_id=tenant.id, investigation_id=case.investigation_id,
                        kind="update_case_fields", idempotency_key=key, target=case.id)
        db.add(action)
        db.flush()
    action.status = "pending"
    action.detail = {"requested_fields": fields, "revision": revision + 1,
                     "field_digest": digest}
    action.attempted_at = utcnow()
    audit(db, tenant.id, actor, "case_fields_update_attempted", "case", case.id,
          {"action_id": action.id, "fields": sorted(fields)})
    db.commit()
    try:
        hive.update_case_fields(case.external_id, fields)
        if hive.case_fields(case.external_id, list(fields)) != fields:
            raise AdapterAmbiguousError("TheHive не подтвердил изменение полей кейса")
        action.status = "succeeded"
        action.external_id = case.external_id
        action.completed_at = utcnow()
        action.detail = {**action.detail, "stage": "completed"}
        _record_case_fields(case, fields)
        case.data = {**(case.data or {}), "fields_revision": revision + 1}
        audit(db, tenant.id, actor, "case_fields_updated", "case", case.id,
              {"action_id": action.id, "fields": sorted(fields)})
    except Exception as exc:
        action.status = "unknown" if _case_write_uncertain(exc) else "failed"
        action.detail = {**action.detail, "error_type": type(exc).__name__}
        _integration(db, tenant.id, "thehive", "unavailable", type(exc).__name__)
        audit(db, tenant.id, actor, "case_fields_update_unconfirmed", "case", case.id,
              {"action_id": action.id, "outcome": action.status})
    db.commit()
    return action


def reconcile_case_fields(db: Session, tenant: Tenant, action: Action, case: Case, actor: str) -> Action:
    """Resolve an uncertain field update by readback, without replaying PATCH."""
    if action.status != "unknown" or action.kind != "update_case_fields":
        return action
    if action.tenant_id != tenant.id or action.target != case.id or case.tenant_id != tenant.id or not case.external_id:
        raise ValueError("Действие не принадлежит этому кейсу")
    fields = (action.detail or {}).get("requested_fields")
    try:
        fields = validate_case_fields(fields)
        hive = thehive_adapter()
        creation = db.scalar(select(Action).where(Action.tenant_id == tenant.id,
            Action.investigation_id == case.investigation_id, Action.kind == "create_case").limit(1))
        if not creation or hive.find_case(creation.idempotency_key) != case.external_id:
            raise AdapterError("Связь кейса с расследованием не подтверждена в TheHive")
        actual = hive.case_fields(case.external_id, list(fields))
    except Exception as exc:
        _integration(db, tenant.id, "thehive", "unavailable", type(exc).__name__)
        db.commit()
        return action
    if actual == fields:
        revision = max(int((case.data or {}).get("fields_revision", 0)),
                       int((action.detail or {}).get("revision", 0)))
        action.status = "succeeded"
        action.external_id = case.external_id
        action.completed_at = utcnow()
        action.detail = {**(action.detail or {}), "stage": "completed"}
        _record_case_fields(case, fields)
        case.data = {**(case.data or {}), "fields_revision": revision}
        audit(db, tenant.id, actor, "case_fields_reconciled", "case", case.id,
              {"action_id": action.id, "fields": sorted(fields)})
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
    decision = db.scalar(select(Decision).where(Decision.tenant_id == tenant.id,
        Decision.investigation_id == inv.id).order_by(Decision.created_at.desc(), Decision.id.desc()).limit(1))
    for_claims = getattr(decision, "evidence_for", []) or []
    against_claims = getattr(decision, "evidence_against", []) or []
    plan = build_case_plan(inv, alerts, evidence, decision=decision,
        evidence_for_ids=[claim["evidence_id"] for claim in for_claims if isinstance(claim, dict)
                          and isinstance(claim.get("evidence_id"), str)],
        evidence_against_ids=[claim["evidence_id"] for claim in against_claims if isinstance(claim, dict)
                              and isinstance(claim.get("evidence_id"), str)])
    create_payload = dict(plan.create_case)
    create_payload["severity"] = {"low": 1, "medium": 2, "high": 3, "critical": 4}[plan.create_case["severity"]]
    create_payload["startDate"] = int(datetime.fromisoformat(plan.metadata["interval_start"]).timestamp() * 1000)
    create_payload["endDate"] = int(datetime.fromisoformat(plan.metadata["interval_end"]).timestamp() * 1000)
    case.title = plan.create_case["title"]
    case.data = {**(case.data or {}), **plan.metadata}
    steps: list[tuple[str, dict, str]] = [("create_case", create_payload, action.idempotency_key)]
    steps.extend((kind, payload, "") for kind, payload in plan.steps)
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
                                          write.idempotency_key, severity=write.request_data["severity"],
                                          tags=write.request_data["tags"],
                                          start_date=write.request_data["startDate"],
                                          end_date=write.request_data["endDate"])
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
    case.data = {**(case.data or {}), "demo": settings().mode.upper() == "DEMO",
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
    if kind == "close_alert":
        try:
            manual_close_gate(db, tenant, inv, evidence)
        except ManualCloseDenied as exc:
            audit(db, tenant.id, "policy", "close_gate_denied", "investigation", inv.id,
                  {"reason": exc.code, "alert_id": alert.id})
            db.commit()
            return None
    if kind == "create_case" and (inv.verdict != "true_positive" or inv.classification != "TP"):
        audit(db, tenant.id, "policy", "action_denied_conflict", "investigation", inv.id,
              {"kind": kind, "reason": "unconfirmed_tp"})
        db.commit()
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
    if kind in {"create_case", "close_alert"}:
        pending_state = PipelineState.CASE_PENDING if kind == "create_case" else PipelineState.CLOSE_PENDING
        move_alert(db, alert, pending_state, "policy", "authorized_external_action")
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
        result = _perform_case_action(db, tenant, inv, alert, evidence, action)
        move_alert(db, alert, PipelineState.CASE_CREATED if result.status == "succeeded"
                   else PipelineState.NEEDS_REVIEW, "worker", "case_write_" + result.status)
        db.commit()
        return result
    try:
        if action.status == "unknown":
            if kind == "close_alert" and settings().mode.upper() == "DEMO":
                external_id = f"demo-close:{alert.source_event_id}"
            else:
                if kind == "close_alert":
                    move_alert(db, alert, PipelineState.NEEDS_REVIEW, "worker", "close_outcome_unknown")
                    db.commit()
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
    if kind == "close_alert":
        move_alert(db, alert, PipelineState.CLOSED_FP if action.status == "succeeded"
                   else PipelineState.NEEDS_REVIEW, "worker", "close_" + action.status)
    db.commit()
    return action


def process_alert(db: Session, alert_id: str) -> None:
    deadline = monotonic() + max(settings().investigation_timeout_seconds, 1)
    alert = db.scalar(select(Alert).where(Alert.id == alert_id).with_for_update())
    if not alert or alert.status in {"completed", "auto_closed", "escalated"}:
        return
    if alert.pipeline_state in {PipelineState.CASE_CREATED, PipelineState.CLOSED_FP,
                                PipelineState.SUPPRESSED, PipelineState.FAILED_PERMANENT}:
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
    if alert.pipeline_state in {PipelineState.VALIDATED, PipelineState.ENRICHING,
                                PipelineState.TRIAGING, PipelineState.TRIAGED,
                                PipelineState.CASE_PENDING, PipelineState.CLOSE_PENDING}:
        move_alert(db, alert, PipelineState.FAILED_RETRYABLE, "worker", "stale_claim_retried")
    move_alert(db, alert, PipelineState.VALIDATED, "worker", "payload_validated")
    move_alert(db, alert, PipelineState.ENRICHING, "worker", "evidence_collection_started")
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
    current_evidence = []
    for item in evidence:
        if item.kind != "active_exception":
            current_evidence.append(item)
            continue
        policy_id = item.data.get("policy_id") if isinstance(item.data, dict) else None
        policy = db.get(ExceptionRule, policy_id) if policy_id else None
        if policy and policy.tenant_id == tenant.id and is_effective(db, policy, alert.raw, alert.event_at):
            current_evidence.append(item)
    if len(current_evidence) != len(evidence):
        steps.append({"step": "stale_policy_evidence", "status": "excluded",
                      "count": len(evidence) - len(current_evidence)})
    evidence = current_evidence
    if len(evidence) > settings().max_evidence_items:
        evidence = evidence[:settings().max_evidence_items]
        context_ok = False
        steps.append({"step": "evidence_limit", "status": "limited"})
    records = [{"id": e.id, "kind": e.kind, "source": e.source, "summary": e.summary, "data": e.data} for e in evidence]
    move_alert(db, alert, PipelineState.TRIAGING, "worker", "triage_started")
    db.commit()
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
    if analyzer in {"local_model", "external_model"} and decision.classification != baseline.classification:
        from .playbooks import Verdict
        decision = Verdict(verdict="needs_review", priority=baseline.priority,
                           summary="Требуется ручная проверка расхождения",
                           rationale="Классификация модели не совпала с проверяемым правилом плейбука; автоматическое действие запрещено.",
                           evidence_ids=[e.id for e in evidence],
                           missing_data=["Проверить причину расхождения модели и плейбука"],
                           recommended_actions=["review"])
        steps.append({"step": "model_disagreement", "status": "needs_review"})
    known_ids = {e.id for e in evidence}
    claim_ids = {claim.evidence_id for claim in decision.evidence_for + decision.evidence_against}
    if (not set(decision.evidence_ids).issubset(known_ids) or not claim_ids.issubset(known_ids)
            or (decision.classification != "INCONCLUSIVE" and not decision.evidence_ids)):
        raise ValueError("Решение с некорректными доказательствами")
    inv.playbook_key, inv.playbook_version = playbook.key, playbook.version
    inv.verdict, inv.priority = decision.verdict, decision.priority
    inv.classification, inv.confidence = decision.classification, decision.confidence
    inv.summary, inv.rationale = decision.summary, decision.rationale
    inv.missing_data, inv.recommended_actions = decision.missing_data, decision.recommended_actions
    inv.analyzer = analyzer
    inv.completed_at = utcnow()
    run.steps = steps + [{"step": "decision", "status": "succeeded",
                          "classification": decision.classification, "verdict": decision.verdict}]
    run.status, run.completed_at = "completed", utcnow()
    db.add(Decision(tenant_id=tenant.id, investigation_id=inv.id, verdict=decision.verdict,
                    classification=decision.classification, confidence=decision.confidence,
                    priority=decision.priority, summary=decision.summary, rationale=decision.rationale,
                    evidence_ids=decision.evidence_ids,
                    evidence_for=[claim.model_dump() for claim in decision.evidence_for],
                    evidence_against=[claim.model_dump() for claim in decision.evidence_against],
                    missing_data=decision.missing_data,
                    recommended_actions=decision.recommended_actions, actor=analyzer))
    move_alert(db, alert, PipelineState.TRIAGED, "worker", "decision_persisted")
    audit(db, tenant.id, analyzer, "decision", "investigation", inv.id,
          {"classification": decision.classification, "verdict": decision.verdict, "playbook": playbook.key})
    db.commit()
    if decision.classification == "FP" and decision.auto_close_eligible:
        if settings().auto_close_enabled:
            action = perform_action(db, tenant, inv, alert, "close_alert", evidence)
            status = "auto_closed" if action and action.status == "succeeded" else "needs_review"
            if not action:
                audit(db, tenant.id, "policy", "auto_close_denied", "investigation", inv.id,
                      {"reason": "close_gate_or_automation_level", "alert_id": alert.id})
        else:
            status = "needs_review"
            run.steps = [*run.steps, {"step": "auto_close_gate", "status": "denied", "reason": "globally_disabled"}]
            audit(db, tenant.id, "policy", "auto_close_denied", "investigation", inv.id,
                  {"reason": "globally_disabled", "alert_id": alert.id})
    elif decision.classification == "TP":
        action = perform_action(db, tenant, inv, alert, "create_case", evidence)
        status = "escalated" if action and action.status == "succeeded" else "needs_review"
    elif decision.classification == "NOISE":
        grant, reason = noise_suppression_gate(db, tenant, inv, alert, evidence, baseline)
        if grant:
            now = utcnow()
            action = Action(tenant_id=tenant.id, investigation_id=inv.id, kind="suppress_noise",
                            status="succeeded", idempotency_key=f"{inv.id}:suppress_noise:{alert.id}",
                            target=alert.source_event_id, detail=grant,
                            attempted_at=now, completed_at=now)
            db.add(action)
            db.flush()
            audit(db, tenant.id, "policy", "noise_suppressed", "action", action.id,
                  {"alert_id": alert.id, "policy_id": grant["policy_id"],
                   "policy_version": grant["policy_version"], "group_key": grant["group_key"]})
            status = "suppressed"
        else:
            audit(db, tenant.id, "policy", "noise_suppression_denied", "investigation", inv.id,
                  {"alert_id": alert.id, "reason": reason})
            status = "needs_review"
    else:
        status = "needs_review"
    target_state = {"auto_closed": PipelineState.CLOSED_FP,
                    "escalated": PipelineState.CASE_CREATED,
                    "suppressed": PipelineState.SUPPRESSED}.get(status, PipelineState.NEEDS_REVIEW)
    if target_state == PipelineState.CASE_CREATED and alert.pipeline_state == PipelineState.TRIAGED:
        move_alert(db, alert, PipelineState.CASE_PENDING, "worker", "case_already_confirmed")
    if target_state == PipelineState.CLOSED_FP and alert.pipeline_state == PipelineState.TRIAGED:
        move_alert(db, alert, PipelineState.CLOSE_PENDING, "worker", "close_already_confirmed")
    move_alert(db, alert, target_state, "worker", "processing_finished")
    inv.status = status
    alert.status = status
    alert.processed_at = utcnow()
    db.commit()
