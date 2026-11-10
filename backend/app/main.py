import csv
import hmac
import hashlib
import io
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .config import settings
from .db import SessionLocal, get_db
from .classification import Classification, action_lane, classification_for_lane
from .metrics import metric_snapshot
from .models import (Action, Alert, Asset, Audit, Case, CaseWrite, DeadLetter, Decision, Evidence,
                     ExceptionRule, IntegrationState, Investigation, Maintenance, MispNotice, PlaybookRun, PolicyEvent,
                     PipelineTransition, Report, Shift, Tenant, User, utcnow)
from .playbooks import REGISTRY
from .policy import aware as policy_aware, record_event, validate_contract
from .report import build_report, export_docx_bytes, export_txt_bytes, next_report_version
from .security import (admin, analyst, audit, current_user, hash_password, policy_approver,
                       policy_revoker, token_for, verify_password)
from .state import PipelineState, move_alert
from .tasks import celery_app, check_integrations, dispatch
from .workflow import (ManualCloseDenied, aware, ingest, manual_close_gate,
                       perform_action, reconcile_case_status, update_case_status)


def seed() -> None:
    with SessionLocal() as db:
        existing_tenants = db.scalars(select(Tenant)).all()
        if existing_tenants:
            if any(t.deployment_mode != settings().mode.upper() for t in existing_tenants):
                raise RuntimeError("MODE не соответствует существующей БД: используйте отдельную базу для CONNECTED")
            return
        if settings().mode.upper() == "DEMO":
            main = Tenant(name="Sauyt.Lab — DEMO", deployment_mode="DEMO", automation_level="controlled_automation")
            second = Tenant(name="Отдельный заказчик — DEMO", deployment_mode="DEMO", automation_level="observe")
            db.add_all([main, second])
            db.flush()
            db.add_all([
                User(tenant_id=main.id, username="admin", password_hash=hash_password(settings().demo_admin_password), role="admin"),
                User(tenant_id=main.id, username="analyst", password_hash=hash_password(settings().demo_analyst_password), role="analyst"),
                User(tenant_id=second.id, username="analyst-b", password_hash=hash_password(settings().demo_analyst_password), role="analyst"),
                Asset(tenant_id=main.id, kind="host", value="srv-bastion-01", owner="ИТ", criticality="high"),
                Asset(tenant_id=main.id, kind="host", value="win-client-01", owner="ИТ", criticality="medium"),
                Asset(tenant_id=main.id, kind="vpn_peer", value="peer-branch-01", owner="Сеть", criticality="high",
                      attributes={"allowed": True, "tunnel": "branch-01"}),
            ])
        else:
            if not settings().connected_admin_password:
                raise RuntimeError("CONNECTED_ADMIN_PASSWORD обязателен в CONNECTED")
            main = Tenant(name="Sauyt.Lab", deployment_mode="CONNECTED", automation_level="observe")
            db.add(main)
            db.flush()
            db.add(User(tenant_id=main.id, username="admin", password_hash=hash_password(settings().connected_admin_password), role="admin"))
            if settings().connected_analyst_password:
                db.add(User(tenant_id=main.id, username="analyst", password_hash=hash_password(settings().connected_analyst_password), role="analyst"))
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    seed()
    yield


app = FastAPI(title="Sauyt.Lab AI SOC L1", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


class LoginIn(BaseModel):
    username: str
    password: str


class ReviewIn(BaseModel):
    classification: Classification | None = None
    verdict: Literal["true_positive", "false_positive", "needs_review"] | None = None
    note: str = Field(min_length=3, max_length=2000)


class WindowIn(BaseModel):
    rule: str = Field(default="*", min_length=1, max_length=100)
    entity: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=3, max_length=2000)
    scope: dict[str, str] = Field(default_factory=dict)
    valid_from: datetime
    valid_until: datetime
    owner: str | None = Field(default=None, max_length=100)
    change_reason: str = Field(default="Initial proposal", min_length=3, max_length=1000)


class PolicyRevokeIn(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)


class PolicyVersionIn(WindowIn):
    change_reason: str = Field(min_length=10, max_length=1000)


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,99}$")
    password: str = Field(min_length=12, max_length=128)
    role: Literal["viewer", "analyst", "policy_approver"]


class MaintenanceIn(BaseModel):
    title: str
    entity: str
    reason: str
    scope: dict[str, str] = Field(default_factory=dict)
    valid_from: datetime
    valid_until: datetime


class ShiftIn(BaseModel):
    starts_at: datetime
    ends_at: datetime
    timezone: str = "Asia/Qyzylorda"
    outgoing_name: str | None = None
    incoming_name: str | None = None


class SettingsIn(BaseModel):
    automation_level: Literal["disabled", "observe", "recommend", "controlled_automation",
                              "auto_close", "approved_response"]


class CaseStatusIn(BaseModel):
    status: str = Field(min_length=1, max_length=64)


class AssetIn(BaseModel):
    kind: Literal["host", "ip", "user", "vpn_peer", "device"]
    value: str = Field(min_length=1, max_length=256)
    owner: str = Field(default="", max_length=256)
    criticality: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"
    attributes: dict = Field(default_factory=dict)


class MispNoticeUpdate(BaseModel):
    l1_status: Literal["pending", "reviewed", "needs_review", "escalated"] | None = None
    l2_status: Literal["not_transferred", "pending_confirmation", "handoff_recorded"] | None = None
    handoff_reference: str | None = Field(default=None, max_length=200)


def serialize(row, keys: tuple[str, ...]) -> dict:
    return {key: getattr(row, key) for key in keys}


def exception_view(row: ExceptionRule) -> dict:
    return {**serialize(row, ("id", "policy_key", "version", "rule", "entity", "owner", "created_by",
                              "reason", "scope", "valid_from", "valid_until", "approval_status",
                              "approved_by", "approved_at", "revoked_by", "revoked_at",
                              "change_reason", "revocation_reason", "created_at")),
            "rule_id": row.rule}


def integration_view(row: IntegrationState) -> dict:
    item = serialize(row, ("id", "name", "status", "last_checked_at", "last_received_at", "detail"))
    if row.name == "worker" and row.last_checked_at and utcnow() - aware(row.last_checked_at) > timedelta(minutes=3):
        item["status"] = "stale"
        item["detail"] = "Нет heartbeat worker более 3 минут"
    return item


def scoped(db: Session, model, tenant_id: str, id: str):
    row = db.scalar(select(model).where(model.id == id, model.tenant_id == tenant_id))
    if not row:
        raise HTTPException(404, "Объект не найден")
    return row


def checked_window(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    if start.tzinfo is None or start.utcoffset() is None or end.tzinfo is None or end.utcoffset() is None:
        raise HTTPException(422, "Время должно содержать часовое смещение")
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if end <= start:
        raise HTTPException(422, "Конец должен быть позже начала")
    return start, end


@app.get("/api/health/live")
def live():
    return {"status": "alive"}


@app.get("/api/health/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        if not celery_app.conf.task_always_eager:
            import redis
            redis.Redis.from_url(settings().redis_url, socket_timeout=2).ping()
    except Exception:
        raise HTTPException(503, "БД или очередь недоступны")
    return {"status": "ready"}


@app.post("/api/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username, User.active.is_(True)))
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Неверные учётные данные")
    audit(db, user.tenant_id, user.username, "login", "user", user.id)
    db.commit()
    return {"access_token": token_for(user), "token_type": "bearer"}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, user.tenant_id)
    return {"id": user.id, "username": user.username, "role": user.role, "tenant_id": user.tenant_id,
            "tenant_name": tenant.name, "mode": settings().mode.upper()}


@app.get("/api/users")
def users(user: User = Depends(admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).where(User.tenant_id == user.tenant_id)
                      .order_by(User.username).limit(200)).all()
    return {"items": [serialize(x, ("id", "username", "role", "active")) for x in rows]}


@app.post("/api/users")
def create_user(body: UserIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    row = User(tenant_id=user.tenant_id, username=body.username,
               password_hash=hash_password(body.password), role=body.role)
    db.add(row)
    try:
        db.flush()
        audit(db, user.tenant_id, user.username, "user_created", "user", row.id,
              {"username": row.username, "role": row.role})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Имя пользователя занято")
    return serialize(row, ("id", "username", "role", "active"))


@app.post("/api/users/{user_id}/deactivate")
def deactivate_user(user_id: str, user: User = Depends(admin), db: Session = Depends(get_db)):
    row = scoped(db, User, user.tenant_id, user_id)
    if row.id == user.id:
        raise HTTPException(409, "Нельзя отключить свою учётную запись")
    if row.active:
        row.active = False
        audit(db, user.tenant_id, user.username, "user_deactivated", "user", row.id,
              {"username": row.username, "role": row.role})
        db.commit()
    return serialize(row, ("id", "username", "role", "active"))


@app.get("/api/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    operational = metric_snapshot(db, user.tenant_id)
    statuses = {status: db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == user.tenant_id, Alert.status == status))
                for status in ("queued", "running", "needs_review", "failed")}
    integrations = [integration_view(x)
                    for x in db.scalars(select(IntegrationState).where(IntegrationState.tenant_id == user.tenant_id)).all()]
    present = {x["name"] for x in integrations}
    integrations += [{"name": name, "status": "unknown", "last_checked_at": None, "last_received_at": None,
                      "detail": "Проверка ещё не выполнялась"} for name in ("splunk", "thehive", "misp", "worker") if name not in present]
    return {"queue": statuses, "alerts_total": db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == user.tenant_id)),
            "investigations_total": db.scalar(select(func.count()).select_from(Investigation).where(Investigation.tenant_id == user.tenant_id)),
            "classification_counts": operational["triage_results_total"],
            "cases_created_total": operational["cases_created_total"],
            "deduplicated_total": operational["alert_deduplicated_total"],
            "integrations": integrations, "mode": settings().mode.upper(),
            "automation_level": db.get(Tenant, user.tenant_id).automation_level}


@app.get("/api/alerts")
def alerts(status: str | None = None, verdict: str | None = None,
           classification: Classification | None = None, search: str | None = None,
           limit: int = 100, user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = select(Alert, Investigation.verdict, Investigation.classification, Investigation.confidence).join(
        Investigation, Alert.investigation_id == Investigation.id).where(Alert.tenant_id == user.tenant_id)
    if status:
        query = query.where(Alert.status == status)
    if verdict:
        query = query.where(Investigation.verdict == verdict)
    if classification:
        query = query.where(Investigation.classification == classification)
    if search:
        query = query.where(Alert.title.ilike(f"%{search[:100]}%"))
    rows = db.execute(query.order_by(Alert.received_at.desc()).limit(min(max(limit, 1), 500))).all()
    return {"items": [{**serialize(a, ("id", "title", "rule", "severity", "status", "pipeline_state",
                                    "event_at", "received_at", "source", "source_event_id", "investigation_id")),
                       "verdict": v, "classification": c, "confidence": confidence}
                      for a, v, c, confidence in rows], "total": len(rows)}


@app.get("/api/investigations/{investigation_id}")
def investigation(investigation_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    inv = scoped(db, Investigation, user.tenant_id, investigation_id)
    return {**serialize(inv, ("id", "status", "verdict", "classification", "confidence",
                              "priority", "summary", "rationale", "missing_data",
                              "recommended_actions", "playbook_key", "playbook_version", "analyzer", "created_at", "started_at", "completed_at", "due_at")),
            "alerts": [serialize(x, ("id", "source_event_id", "title", "rule", "status", "pipeline_state",
                                     "event_at", "received_at", "raw"))
                       for x in db.scalars(select(Alert).where(Alert.tenant_id == user.tenant_id, Alert.investigation_id == inv.id)).all()],
            "transitions": [serialize(x, ("id", "alert_id", "from_state", "to_state", "actor", "reason", "created_at"))
                            for x in db.scalars(select(PipelineTransition).where(
                                PipelineTransition.tenant_id == user.tenant_id,
                                PipelineTransition.investigation_id == inv.id).order_by(
                                    PipelineTransition.created_at, PipelineTransition.id)).all()],
            "evidence": [serialize(x, ("id", "kind", "source", "summary", "data", "event_at", "collected_at"))
                         for x in db.scalars(select(Evidence).where(Evidence.tenant_id == user.tenant_id, Evidence.investigation_id == inv.id)).all()],
            "playbook_runs": [serialize(x, ("id", "key", "version", "status", "steps", "started_at", "completed_at"))
                              for x in db.scalars(select(PlaybookRun).where(PlaybookRun.tenant_id == user.tenant_id, PlaybookRun.investigation_id == inv.id)).all()],
            "decisions": [serialize(x, ("id", "verdict", "classification", "confidence", "priority",
                                        "summary", "rationale", "evidence_ids", "evidence_for", "evidence_against",
                                        "missing_data", "recommended_actions", "actor", "created_at"))
                          for x in db.scalars(select(Decision).where(Decision.tenant_id == user.tenant_id, Decision.investigation_id == inv.id)).all()],
            "actions": [serialize(x, ("id", "kind", "status", "target", "external_id", "detail", "attempted_at", "completed_at"))
                        for x in db.scalars(select(Action).where(Action.tenant_id == user.tenant_id, Action.investigation_id == inv.id)).all()],
            "case_writes": [serialize(x, ("id", "case_id", "sequence", "kind", "idempotency_key",
                                          "request_data", "status", "external_id", "attempts",
                                          "error_type", "attempted_at", "completed_at"))
                            for x in db.scalars(select(CaseWrite).where(CaseWrite.tenant_id == user.tenant_id,
                                CaseWrite.investigation_id == inv.id).order_by(CaseWrite.sequence)).all()],
            "cases": [serialize(x, ("id", "external_id", "status", "title", "data", "created_at"))
                      for x in db.scalars(select(Case).where(Case.tenant_id == user.tenant_id, Case.investigation_id == inv.id)).all()]}


@app.post("/api/investigations/{investigation_id}/review")
def review(investigation_id: str, body: ReviewIn, user: User = Depends(analyst), db: Session = Depends(get_db)):
    inv = scoped(db, Investigation, user.tenant_id, investigation_id)
    if body.classification is None and body.verdict is None:
        raise HTTPException(422, "Укажите классификацию")
    classification = body.classification or classification_for_lane(body.verdict)
    verdict = action_lane(classification)
    if body.verdict is not None and body.verdict != verdict:
        raise HTTPException(422, "Классификация и вердикт противоречат друг другу")
    evidence_ids = db.scalars(select(Evidence.id).where(Evidence.tenant_id == user.tenant_id, Evidence.investigation_id == inv.id)).all()
    db.add(Decision(tenant_id=user.tenant_id, investigation_id=inv.id, verdict=verdict,
                    classification=classification, confidence=None, priority=inv.priority,
                    summary=inv.summary or "Ручная проверка", rationale=body.note, evidence_ids=list(evidence_ids),
                    missing_data=[], recommended_actions=[], actor=user.username))
    inv.verdict, inv.classification, inv.confidence, inv.rationale = verdict, classification, None, body.note
    inv.status = "needs_review" if verdict == "needs_review" else "completed"
    inv.completed_at = utcnow()
    if inv.status == "needs_review":
        for alert in db.scalars(select(Alert).where(Alert.tenant_id == user.tenant_id,
                                                   Alert.investigation_id == inv.id)).all():
            if alert.pipeline_state == PipelineState.TRIAGED:
                move_alert(db, alert, PipelineState.NEEDS_REVIEW, user.username, "manual_review")
    audit(db, user.tenant_id, user.username, "review", "investigation", inv.id,
          {"verdict": verdict, "classification": classification})
    db.commit()
    return {"id": inv.id, "status": inv.status, "verdict": inv.verdict,
            "classification": inv.classification}


@app.post("/api/investigations/{investigation_id}/actions/{kind}")
def manual_action(investigation_id: str, kind: Literal["create_case", "close_alert", "disable_account_demo", "isolate_host_demo"],
                  user: User = Depends(admin), db: Session = Depends(get_db)):
    inv = scoped(db, Investigation, user.tenant_id, investigation_id)
    tenant = db.get(Tenant, user.tenant_id)
    if not can_manual_action(tenant, kind):
        raise HTTPException(403, "Действие не разрешено политикой")
    if tenant.automation_level not in {"controlled_automation", "approved_response"}:
        raise HTTPException(403, "Ручные действия требуют CONTROLLED_AUTOMATION")
    alert = db.scalar(select(Alert).where(Alert.tenant_id == user.tenant_id, Alert.investigation_id == inv.id).order_by(Alert.received_at))
    if not alert:
        raise HTTPException(409, "Нет алерта")
    evidence = db.scalars(select(Evidence).where(Evidence.tenant_id == user.tenant_id, Evidence.investigation_id == inv.id)).all()
    if kind == "close_alert":
        try:
            grant = manual_close_gate(db, tenant, inv, evidence)
        except ManualCloseDenied as exc:
            audit(db, user.tenant_id, user.username, "manual_close_denied", "investigation", inv.id,
                  {"reason": exc.code})
            db.commit()
            raise HTTPException(409, str(exc)) from exc
        audit(db, user.tenant_id, user.username, "manual_close_granted", "investigation", inv.id,
              grant)
        db.commit()
    action = perform_action(db, tenant, inv, alert, kind, evidence)
    if action:
        audit(db, user.tenant_id, user.username, "manual_action_requested", "action", action.id,
              {"kind": kind, "outcome": action.status})
        db.commit()
    return serialize(action, ("id", "kind", "status", "external_id", "detail")) if action else {"status": "blocked"}


@app.get("/api/cases/{case_id}/statuses")
def case_status_options(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .adapters import thehive_adapter
    case = scoped(db, Case, user.tenant_id, case_id)
    if not case.external_id:
        raise HTTPException(409, "Кейс ещё не подтверждён во внешней системе")
    try:
        return {"items": thehive_adapter().case_statuses()}
    except Exception:
        raise HTTPException(503, "Статусы TheHive недоступны")


@app.post("/api/cases/{case_id}/status")
def set_case_status(case_id: str, body: CaseStatusIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    case = db.scalar(select(Case).where(Case.tenant_id == user.tenant_id, Case.id == case_id).with_for_update())
    if not case:
        raise HTTPException(404, "Объект не найден")
    tenant = db.get(Tenant, user.tenant_id)
    if tenant.automation_level not in {"controlled_automation", "approved_response"} or not can_manual_action(tenant, "update_case"):
        raise HTTPException(403, "Изменение статуса кейса не разрешено политикой")
    if not case.external_id:
        raise HTTPException(409, "Кейс ещё не подтверждён во внешней системе")
    try:
        action = update_case_status(db, tenant, case, body.status, user.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except Exception:
        raise HTTPException(503, "TheHive недоступен для обновления статуса")
    return serialize(action, ("id", "status", "external_id", "detail"))


def can_manual_action(tenant: Tenant, kind: str) -> bool:
    from .workflow import can_act
    return can_act(tenant, kind)


def checked_asset(body: AssetIn) -> tuple[str, dict]:
    value = body.value.strip()
    if not value or len(json.dumps(body.attributes, ensure_ascii=False)) > 4000:
        raise HTTPException(422, "Неверное значение или слишком большие атрибуты актива")
    if body.kind == "vpn_peer" and body.attributes.get("allowed") is True:
        if not all(isinstance(body.attributes.get(key), str) and body.attributes[key].strip()
                   for key in ("tunnel", "device")):
            raise HTTPException(422, "Разрешённый VPN peer требует tunnel и device")
    return value, body.attributes


@app.get("/api/assets")
def assets(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Asset).where(Asset.tenant_id == user.tenant_id).order_by(Asset.kind, Asset.value).limit(300)).all()
    return {"items": [serialize(row, ("id", "kind", "value", "owner", "criticality", "attributes")) for row in rows]}


@app.post("/api/assets")
def create_asset(body: AssetIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    value, attributes = checked_asset(body)
    if db.scalar(select(Asset.id).where(Asset.tenant_id == user.tenant_id, Asset.kind == body.kind, Asset.value == value)):
        raise HTTPException(409, "Актив уже есть в инвентаре")
    row = Asset(tenant_id=user.tenant_id, kind=body.kind, value=value, owner=body.owner.strip(),
                criticality=body.criticality, attributes=attributes)
    db.add(row)
    try:
        db.flush()
        audit(db, user.tenant_id, user.username, "asset_created", "asset", row.id,
              {"kind": row.kind, "value": row.value})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Актив уже есть в инвентаре")
    return serialize(row, ("id", "kind", "value", "owner", "criticality", "attributes"))


@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: str, body: AssetIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    row = scoped(db, Asset, user.tenant_id, asset_id)
    value, attributes = checked_asset(body)
    row.kind, row.value, row.owner = body.kind, value, body.owner.strip()
    row.criticality, row.attributes = body.criticality, attributes
    audit(db, user.tenant_id, user.username, "asset_updated", "asset", row.id,
          {"kind": row.kind, "value": row.value})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Актив уже есть в инвентаре")
    return serialize(row, ("id", "kind", "value", "owner", "criticality", "attributes"))


@app.get("/api/exceptions")
def exceptions(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(ExceptionRule).where(ExceptionRule.tenant_id == user.tenant_id)
                      .order_by(ExceptionRule.created_at.desc(), ExceptionRule.version.desc()).limit(300)).all()
    return {"items": [exception_view(x) for x in rows]}


@app.post("/api/exceptions")
def create_exception(body: WindowIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    valid_from, valid_until = checked_window(body.valid_from, body.valid_until)
    row = ExceptionRule(tenant_id=user.tenant_id, rule=body.rule.strip(), entity=body.entity.strip(),
                        owner=(body.owner or user.username).strip(), created_by=user.username,
                        reason=body.reason.strip(), scope=body.scope, valid_from=valid_from,
                        valid_until=valid_until, approval_status="draft", approved_by="",
                        change_reason=body.change_reason.strip())
    db.add(row)
    db.flush()
    record_event(db, row, user.username, "proposed", None, "draft")
    audit(db, user.tenant_id, user.username, "exception_proposed", "exception", row.id,
          {"policy_key": row.policy_key, "version": row.version, "rule_id": row.rule})
    db.commit()
    return exception_view(row)


@app.post("/api/exceptions/{exception_id}/versions")
def create_exception_version(exception_id: str, body: PolicyVersionIn,
                             user: User = Depends(admin), db: Session = Depends(get_db)):
    if len(body.change_reason.strip()) < 10:
        raise HTTPException(422, "Укажите причину изменения политики")
    source = scoped(db, ExceptionRule, user.tenant_id, exception_id)
    latest = db.scalar(select(ExceptionRule).where(ExceptionRule.tenant_id == user.tenant_id,
        ExceptionRule.policy_key == source.policy_key).order_by(ExceptionRule.version.desc()).with_for_update().limit(1))
    if source.id != latest.id:
        raise HTTPException(409, "Новая версия создаётся от последней версии политики")
    valid_from, valid_until = checked_window(body.valid_from, body.valid_until)
    row = ExceptionRule(tenant_id=user.tenant_id, policy_key=source.policy_key, version=source.version + 1,
                        rule=body.rule.strip(), entity=body.entity.strip(),
                        owner=(body.owner or source.owner).strip(), created_by=user.username,
                        reason=body.reason.strip(), scope=body.scope, valid_from=valid_from,
                        valid_until=valid_until, approval_status="draft", approved_by="",
                        change_reason=body.change_reason.strip())
    db.add(row)
    try:
        db.flush()
        record_event(db, row, user.username, "version_proposed", None, "draft",
                     {"previous_version_id": source.id, "change_reason": row.change_reason})
        audit(db, user.tenant_id, user.username, "exception_version_proposed", "exception", row.id,
              {"policy_key": row.policy_key, "version": row.version, "previous_version_id": source.id})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Версия политики уже создана")
    return exception_view(row)


@app.post("/api/exceptions/{exception_id}/approve")
def approve_exception(exception_id: str, user: User = Depends(policy_approver), db: Session = Depends(get_db)):
    row = db.scalar(select(ExceptionRule).where(ExceptionRule.tenant_id == user.tenant_id,
        ExceptionRule.id == exception_id).with_for_update())
    if not row:
        raise HTTPException(404, "Объект не найден")
    if row.approval_status != "draft":
        raise HTTPException(409, "Утвердить можно только черновик политики")
    if not row.created_by or row.created_by == user.username:
        raise HTTPException(403, "Автор не может утвердить собственную политику")
    latest = db.scalar(select(ExceptionRule.version).where(ExceptionRule.tenant_id == user.tenant_id,
        ExceptionRule.policy_key == row.policy_key).order_by(ExceptionRule.version.desc()).limit(1))
    if latest != row.version:
        raise HTTPException(409, "Есть более новая версия политики")
    denial = validate_contract(row)
    if denial:
        raise HTTPException(409, f"Политика не может быть утверждена: {denial}")
    now = utcnow()
    if policy_aware(row.valid_until) <= now:
        raise HTTPException(409, "Срок действия политики истёк")
    previous = db.scalars(select(ExceptionRule).where(ExceptionRule.tenant_id == user.tenant_id,
        ExceptionRule.policy_key == row.policy_key, ExceptionRule.approval_status == "approved")
        .with_for_update()).all()
    for older in previous:
        older.approval_status = "superseded"
        older.revoked_at, older.revoked_by = now, user.username
        older.revocation_reason = f"Superseded by version {row.version}"
        record_event(db, older, user.username, "superseded", "approved", "superseded",
                     {"new_policy_id": row.id, "new_version": row.version})
        audit(db, user.tenant_id, user.username, "exception_superseded", "exception", older.id,
              {"new_policy_id": row.id})
    db.flush()  # release the one-approved-version constraint before approving the replacement
    row.approval_status, row.approved_by, row.approved_at = "approved", user.username, now
    record_event(db, row, user.username, "approved", "draft", "approved")
    audit(db, user.tenant_id, user.username, "exception_approved", "exception", row.id,
          {"policy_key": row.policy_key, "version": row.version, "rule_id": row.rule})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Другая версия уже утверждена")
    return exception_view(row)


@app.post("/api/exceptions/{exception_id}/revoke")
def revoke_exception(exception_id: str, body: PolicyRevokeIn,
                     user: User = Depends(policy_revoker), db: Session = Depends(get_db)):
    if len(body.reason.strip()) < 10:
        raise HTTPException(422, "Укажите причину отзыва политики")
    row = db.scalar(select(ExceptionRule).where(ExceptionRule.tenant_id == user.tenant_id,
        ExceptionRule.id == exception_id).with_for_update())
    if not row:
        raise HTTPException(404, "Объект не найден")
    if row.approval_status != "approved":
        raise HTTPException(409, "Отозвать можно только действующее утверждение")
    row.approval_status, row.revoked_at, row.revoked_by = "revoked", utcnow(), user.username
    row.revocation_reason = body.reason.strip()
    record_event(db, row, user.username, "revoked", "approved", "revoked",
                 {"reason": row.revocation_reason})
    audit(db, user.tenant_id, user.username, "exception_revoked", "exception", row.id,
          {"policy_key": row.policy_key, "version": row.version, "reason": row.revocation_reason})
    db.commit()
    return exception_view(row)


@app.get("/api/exceptions/{exception_id}/history")
def exception_history(exception_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = scoped(db, ExceptionRule, user.tenant_id, exception_id)
    versions = db.scalars(select(ExceptionRule).where(ExceptionRule.tenant_id == user.tenant_id,
        ExceptionRule.policy_key == row.policy_key).order_by(ExceptionRule.version)).all()
    ids = [x.id for x in versions]
    events = db.scalars(select(PolicyEvent).where(PolicyEvent.tenant_id == user.tenant_id,
        PolicyEvent.policy_id.in_(ids)).order_by(PolicyEvent.created_at, PolicyEvent.id)).all()
    return {"policy_key": row.policy_key, "versions": [exception_view(x) for x in versions],
            "events": [serialize(x, ("id", "policy_id", "actor", "event_type", "from_status",
                                    "to_status", "detail", "created_at")) for x in events]}


@app.get("/api/maintenance")
def maintenance(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Maintenance).where(Maintenance.tenant_id == user.tenant_id).order_by(Maintenance.valid_until.desc())).all()
    return {"items": [serialize(x, ("id", "title", "entity", "reason", "scope", "valid_from", "valid_until", "approved_by")) for x in rows]}


@app.post("/api/maintenance")
def create_maintenance(body: MaintenanceIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    valid_from, valid_until = checked_window(body.valid_from, body.valid_until)
    row = Maintenance(tenant_id=user.tenant_id, title=body.title, entity=body.entity, reason=body.reason, scope=body.scope,
                      valid_from=valid_from, valid_until=valid_until, approved_by=user.username)
    db.add(row)
    db.flush()
    audit(db, user.tenant_id, user.username, "maintenance_created", "maintenance", row.id, {"entity": body.entity})
    db.commit()
    return {"id": row.id}


@app.get("/api/integrations")
def integrations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(IntegrationState).where(IntegrationState.tenant_id == user.tenant_id)).all()
    mapped = {x.name: integration_view(x) for x in rows}
    return {"items": [mapped.get(name, {"name": name, "status": "unknown", "last_checked_at": None,
                    "last_received_at": None, "detail": "Проверка ещё не выполнялась"}) for name in ("splunk", "thehive", "misp", "worker")]}


@app.get("/api/integrations/webhook-config")
def webhook_config(user: User = Depends(admin)):
    token = hmac.new(settings().webhook_secret.encode(), user.tenant_id.encode(), hashlib.sha256).hexdigest()
    return {"path": f"/api/ingest/webhook/{user.tenant_id}/{token}",
            "note": "Секретный URL передавать только по HTTPS; Splunk webhook передаёт первый result."}


@app.post("/api/integrations/check")
def integrations_check(user: User = Depends(admin)):
    try:
        check_integrations.delay()
    except Exception:
        raise HTTPException(503, "Очередь недоступна")
    return {"status": "queued"}


@app.get("/api/misp/notices")
def misp_notices(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(MispNotice).where(MispNotice.tenant_id == user.tenant_id)
                      .order_by(MispNotice.received_at.desc()).limit(100)).all()
    return {"items": [serialize(row, ("id", "external_id", "title", "received_status", "l1_status",
                                      "l2_status", "received_at")) for row in rows]}


@app.patch("/api/misp/notices/{notice_id}")
def update_misp_notice(notice_id: str, body: MispNoticeUpdate, user: User = Depends(analyst),
                       db: Session = Depends(get_db)):
    row = scoped(db, MispNotice, user.tenant_id, notice_id)
    if body.l1_status is None and body.l2_status is None:
        raise HTTPException(422, "Укажите статус L1 или L2")
    if body.l2_status is not None and body.l2_status != row.l2_status and user.role != "admin":
        raise HTTPException(403, "Статус передачи L2 меняет администратор")
    if body.l2_status == "handoff_recorded" and row.l2_status != "handoff_recorded":
        reference = (body.handoff_reference or "").strip()
        if len(reference) < 3:
            raise HTTPException(422, "Нужна ссылка или номер подтверждения передачи L2")
        row.data = {**(row.data or {}), "soc_tracking": {"handoff_reference": reference,
                    "recorded_by": user.username, "recorded_at": utcnow().isoformat()}}
    if body.l1_status is not None:
        row.l1_status = body.l1_status
    if body.l2_status is not None:
        row.l2_status = body.l2_status
    audit(db, user.tenant_id, user.username, "misp_notice_updated", "misp_notice", row.id,
          {"l1_status": row.l1_status, "l2_status": row.l2_status})
    db.commit()
    return serialize(row, ("id", "l1_status", "l2_status"))


@app.get("/api/sla")
def sla(user: User = Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    rows = db.scalars(select(Investigation).where(Investigation.tenant_id == user.tenant_id,
                        Investigation.status.in_(["queued", "running", "needs_review"]))
                      .order_by(Investigation.due_at).limit(200)).all()
    return {"items": [{**serialize(x, ("id", "status", "priority", "summary", "created_at", "due_at")),
                       "overdue": bool(x.due_at and aware(x.due_at) < now)} for x in rows]}


@app.get("/api/shifts")
def shifts(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Shift).where(Shift.tenant_id == user.tenant_id).order_by(Shift.starts_at.desc()).limit(100)).all()
    return {"items": [serialize(x, ("id", "starts_at", "ends_at", "timezone", "status", "outgoing_name", "incoming_name")) for x in rows]}


@app.post("/api/shifts")
def create_shift(body: ShiftIn, user: User = Depends(analyst), db: Session = Depends(get_db)):
    try:
        ZoneInfo(body.timezone)
    except Exception:
        raise HTTPException(422, "Неизвестный часовой пояс")
    starts_at, ends_at = checked_window(body.starts_at, body.ends_at)
    row = Shift(tenant_id=user.tenant_id, starts_at=starts_at, ends_at=ends_at,
                timezone=body.timezone, outgoing_name=body.outgoing_name, incoming_name=body.incoming_name)
    db.add(row)
    db.flush()
    audit(db, user.tenant_id, user.username, "shift_created", "shift", row.id)
    db.commit()
    return {"id": row.id}


@app.get("/api/shifts/{shift_id}/report/preview")
def preview(shift_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    shift = scoped(db, Shift, user.tenant_id, shift_id)
    result = build_report(db, user.tenant_id, shift)
    return {**result, "version": next_report_version(db, user.tenant_id, shift.id), "status": "preview"}


@app.post("/api/shifts/{shift_id}/report/approve")
def approve(shift_id: str, user: User = Depends(admin), db: Session = Depends(get_db)):
    shift = scoped(db, Shift, user.tenant_id, shift_id)
    version = next_report_version(db, user.tenant_id, shift.id)
    result = build_report(db, user.tenant_id, shift, version=version)
    row = Report(tenant_id=user.tenant_id, shift_id=shift.id, version=version,
                 content=result["content"], counters=result["counters"], approved_by=user.username)
    db.add(row)
    shift.status = "reported"
    db.flush()
    audit(db, user.tenant_id, user.username, "report_approved", "report", row.id, {"version": version})
    db.commit()
    return {"id": row.id, "version": version, "status": row.status}


@app.get("/api/shifts/{shift_id}/report/export")
def export(shift_id: str, format: Literal["txt", "docx"] = "txt", user: User = Depends(current_user), db: Session = Depends(get_db)):
    shift = scoped(db, Shift, user.tenant_id, shift_id)
    report = db.scalar(select(Report).where(Report.tenant_id == user.tenant_id, Report.shift_id == shift.id)
                       .order_by(Report.version.desc()).limit(1))
    if not report:
        raise HTTPException(409, "Сначала утвердите отчёт")
    body = export_docx_bytes(report.content) if format == "docx" else export_txt_bytes(report.content)
    media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if format == "docx" else "text/plain; charset=utf-8"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="shift-{shift.id}-v{report.version}.{format}"'})


@app.get("/api/audit")
def audit_list(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Audit).where(Audit.tenant_id == user.tenant_id).order_by(Audit.created_at.desc()).limit(300)).all()
    return {"items": [serialize(x, ("id", "actor", "operation", "subject_type", "subject_id", "detail", "created_at")) for x in rows]}


@app.get("/api/settings")
def get_settings(user: User = Depends(current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, user.tenant_id)
    return {"mode": settings().mode.upper(), "automation_level": tenant.automation_level,
            "auto_close_enabled": settings().auto_close_enabled,
            "connected_writes_enabled": settings().connected_writes_enabled}


@app.patch("/api/settings")
def update_settings(body: SettingsIn, user: User = Depends(admin), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, user.tenant_id)
    old = tenant.automation_level
    if (settings().mode.upper() == "CONNECTED" and
            body.automation_level in {"controlled_automation", "auto_close", "approved_response"} and
            not settings().connected_writes_enabled):
        raise HTTPException(409, "Операции записи CONNECTED не разрешены конфигурацией сервера")
    tenant.automation_level = body.automation_level
    audit(db, user.tenant_id, user.username, "automation_level_changed", "tenant", tenant.id,
          {"old": old, "new": body.automation_level})
    db.commit()
    return {"automation_level": tenant.automation_level}


@app.get("/api/playbooks")
def playbooks(user: User = Depends(current_user)):
    return {"items": [{"key": p.key, "version": p.version, "title": p.title, "required": p.required,
                       "evidence_steps": p.evidence_steps} for p in REGISTRY.values()]}


@app.get("/api/dead-letters")
def dead_letters(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(DeadLetter).where(DeadLetter.tenant_id == user.tenant_id).order_by(DeadLetter.created_at.desc())).all()
    return {"items": [serialize(x, ("id", "alert_id", "error", "attempts", "status", "created_at")) for x in rows]}


@app.post("/api/dead-letters/{letter_id}/retry")
def retry_dead_letter(letter_id: str, user: User = Depends(admin), db: Session = Depends(get_db)):
    letter = scoped(db, DeadLetter, user.tenant_id, letter_id)
    if letter.status != "open":
        raise HTTPException(409, "Задача уже повторена")
    alert = scoped(db, Alert, user.tenant_id, letter.alert_id)
    if alert.pipeline_state == PipelineState.FAILED_PERMANENT:
        move_alert(db, alert, PipelineState.FAILED_RETRYABLE, user.username, "manual_dead_letter_retry")
    alert.status, letter.status = "queued", "retried"
    audit(db, user.tenant_id, user.username, "dead_letter_retry", "alert", alert.id)
    db.commit()
    queued = dispatch(alert.id)
    return {"status": "queued" if queued else "persisted_waiting_for_queue"}


@app.post("/api/actions/{action_id}/reconcile")
def reconcile_action(action_id: str, user: User = Depends(admin), db: Session = Depends(get_db)):
    action = scoped(db, Action, user.tenant_id, action_id)
    if action.status != "unknown":
        raise HTTPException(409, "Требуется статус unknown")
    tenant = db.get(Tenant, user.tenant_id)
    if action.kind == "update_case":
        case = scoped(db, Case, user.tenant_id, action.target)
        result = reconcile_case_status(db, tenant, action, case, user.username)
        audit(db, user.tenant_id, user.username, "action_reconcile_requested", "action", action.id,
              {"outcome": result.status})
        db.commit()
        return serialize(result, ("id", "status", "external_id", "detail"))
    inv = scoped(db, Investigation, user.tenant_id, action.investigation_id)
    alert = db.scalar(select(Alert).where(Alert.tenant_id == user.tenant_id, Alert.investigation_id == inv.id).order_by(Alert.received_at))
    evidence = db.scalars(select(Evidence).where(Evidence.tenant_id == user.tenant_id, Evidence.investigation_id == inv.id)).all()
    result = perform_action(db, tenant, inv, alert, action.kind, evidence)
    audit(db, user.tenant_id, user.username, "action_reconcile_requested", "action", action.id,
          {"outcome": result.status})
    db.commit()
    return serialize(result, ("id", "status", "external_id", "detail"))


def _check_demo() -> None:
    if settings().mode.upper() != "DEMO":
        raise HTTPException(404, "Демонстрационные сценарии доступны только в DEMO")


@app.get("/api/scenarios")
def scenarios(user: User = Depends(current_user)):
    _check_demo()
    from .scenarios import get_scenarios
    return {"items": get_scenarios()}


@app.post("/api/scenarios/{key}/run")
def run_scenario(key: str, user: User = Depends(analyst), db: Session = Depends(get_db)):
    _check_demo()
    from .scenarios import SCENARIOS, instantiate_scenario
    try:
        spec = SCENARIOS[key]
        samples = instantiate_scenario(key)
    except KeyError:
        raise HTTPException(404, "Сценарий не найден")
    event_at = datetime.fromisoformat(samples[0]["event_at"].replace("Z", "+00:00"))
    from datetime import timedelta
    raw = samples[0]["raw"]
    if spec["expected_classification"] in {"BENIGN_TRUE_POSITIVE", "NOISE"} and raw.get("peer") and raw.get("tunnel") and raw.get("device"):
        peer = str(raw["peer"])
        if not db.scalar(select(Asset).where(Asset.tenant_id == user.tenant_id, Asset.kind == "vpn_peer", Asset.value == peer)):
            db.add(Asset(tenant_id=user.tenant_id, kind="vpn_peer", value=peer, owner="DEMO: сеть",
                         criticality="high", attributes={"allowed": True, "tunnel": raw["tunnel"], "device": raw["device"]}))
    maintenance_spec = spec.get("seed_maintenance")
    if maintenance_spec:
        scope = {key: str(raw[key]) for key in ("host", "src_ip", "auth_method", "peer", "device", "tunnel", "user", "command_line") if raw.get(key)}
        db.add(Maintenance(tenant_id=user.tenant_id, title="DEMO: согласованное окно",
                           entity=maintenance_spec["entity"], reason=maintenance_spec["reason"], scope=scope,
                           valid_from=event_at + timedelta(minutes=maintenance_spec["valid_from_offset_minutes"]),
                           valid_until=event_at + timedelta(minutes=maintenance_spec["valid_until_offset_minutes"]),
                           approved_by=maintenance_spec["approved_by"]))
    exception_spec = spec.get("seed_exception")
    if exception_spec:
        scope = {key: str(raw[key]) for key in ("host", "src_ip", "auth_method", "peer", "device", "tunnel", "user", "command_line") if raw.get(key)}
        db.add(ExceptionRule(tenant_id=user.tenant_id, rule=exception_spec["rule"],
                             entity=exception_spec["entity"], reason=exception_spec["reason"], scope=scope,
                             valid_from=event_at + timedelta(minutes=exception_spec["valid_from_offset_minutes"]),
                             valid_until=event_at + timedelta(minutes=exception_spec["valid_until_offset_minutes"]),
                             approved_by=exception_spec["approved_by"]))
    db.commit()
    results = []
    created_count = 0
    for item in samples:
        alert, created = ingest(db, user.tenant_id, item)
        if created:
            created_count += 1
            dispatch(alert.id)
        results.append({"id": alert.id, "investigation_id": alert.investigation_id, "created": created})
    return {"alerts": results, "created_count": created_count}


@app.post("/api/ingest/webhook/{tenant_id}/{secret}")
async def webhook(tenant_id: str, secret: str, request: Request, x_soc_signature: str | None = Header(default=None), db: Session = Depends(get_db)):
    expected_token = hmac.new(settings().webhook_secret.encode(), tenant_id.encode(), hashlib.sha256).hexdigest()
    if not db.get(Tenant, tenant_id) or not hmac.compare_digest(secret, expected_token):
        raise HTTPException(401, "Недействительный источник")
    body = await request.body()
    if len(body) > 1_000_000:
        raise HTTPException(413, "Слишком большой запрос")
    if x_soc_signature:
        signature = hmac.new(settings().webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(x_soc_signature, signature):
            raise HTTPException(401, "Недействительная подпись")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(400, "Некорректный JSON")
    if "result" in payload and "search_name" in payload:
        result = payload.get("result") or {}
        payload = {"source": "splunk", "source_event_id": str(result.get("_cd") or payload.get("sid") or ""),
                   "rule": payload.get("search_name"), "title": payload.get("search_name"),
                   "event_at": result.get("_time") or utcnow().isoformat(), "raw": result}
    try:
        alert, created = ingest(db, tenant_id, payload)
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc))
    queued = dispatch(alert.id) if created else False
    return {"id": alert.id, "investigation_id": alert.investigation_id, "created": created, "queued": queued}


@app.post("/api/ingest/import")
async def import_file(file: UploadFile = File(...), user: User = Depends(admin), db: Session = Depends(get_db)):
    data = await file.read(2_000_001)
    if len(data) > 2_000_000:
        raise HTTPException(413, "Лимит импорта 2 МБ")
    try:
        content = data.decode("utf-8-sig")
        if file.filename and file.filename.lower().endswith(".csv"):
            items = list(csv.DictReader(io.StringIO(content)))
            for item in items:
                if isinstance(item.get("raw"), str):
                    item["raw"] = json.loads(item["raw"])
        else:
            parsed = json.loads(content)
            items = parsed if isinstance(parsed, list) else [parsed]
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(422, f"Ошибка разбора: {exc}")
    if len(items) > 1000:
        raise HTTPException(413, "Лимит 1000 алертов")
    results = []
    for item in items:
        if not isinstance(item, dict):
            raise HTTPException(422, "Каждый алерт должен быть объектом")
        try:
            alert, created = ingest(db, user.tenant_id, item)
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(422, str(exc))
        if created:
            dispatch(alert.id)
        results.append({"id": alert.id, "created": created})
    return {"items": results, "created_count": sum(x["created"] for x in results)}


@app.get("/api/dataset")
def dataset_info(user: User = Depends(current_user)):
    _check_demo()
    from .dataset import DATASET_COMMIT, DATASET_URL
    return {"source": DATASET_URL, "commit": DATASET_COMMIT, "format": "Wazuh JSONL",
            "recommended_path": "Data/2_Merged/2_alerts_preprocessed_merged_20250712_123030.jsonl",
            "note": "Учебные метки используются только для сравнения, не для автоматического решения."}


@app.post("/api/dataset/import")
async def import_dataset(file: UploadFile = File(...), path: str = "Data/2_Merged/2_alerts_preprocessed_merged_20250712_123030.jsonl",
                         user: User = Depends(admin), db: Session = Depends(get_db)):
    _check_demo()
    from .dataset import iter_wazuh_jsonl
    body = await file.read(2_000_001)
    if len(body) > 2_000_000:
        raise HTTPException(413, "Лимит файла 2 МБ")
    lines = body.splitlines()
    if sum(bool(line.strip()) for line in lines) > 200:
        raise HTTPException(413, "Лимит набора 200 алертов")
    try:
        mapped = list(iter_wazuh_jsonl(lines, path=path))
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    created_count = 0
    for item in mapped:
        alert, created = ingest(db, user.tenant_id, item["payload"])
        if created:
            dispatch(alert.id)
            created_count += 1
    audit(db, user.tenant_id, user.username, "dataset_import", "fixture", path,
          {"records": len(mapped), "created": created_count})
    db.commit()
    return {"records": len(mapped), "created_count": created_count,
            "reference_labels": {"TP": sum(x["reference"]["label"] == "TP" for x in mapped),
                                 "FP": sum(x["reference"]["label"] == "FP" for x in mapped)},
            "note": "Метки не передавались анализатору и не создавали исключений."}


@app.get("/api/metrics")
def metrics(user: User = Depends(admin), db: Session = Depends(get_db)):
    snapshot = metric_snapshot(db, user.tenant_id)
    snapshot["dead_letters_open"] = db.scalar(select(func.count()).select_from(DeadLetter).where(
        DeadLetter.tenant_id == user.tenant_id, DeadLetter.status == "open"))
    return snapshot
