from datetime import timedelta
from hashlib import sha256
import json
from celery import Celery
from sqlalchemy import and_, or_, select, text
from sqlalchemy.exc import IntegrityError
from .adapters import splunk_adapter, thehive_adapter, misp_adapter
from .analyzer import ollama_health
from .config import settings
from .db import SessionLocal
from .ingestion import normalize_alert
from .models import (Alert, Audit, Checkpoint, DeadLetter, IngestionQuarantine, IntegrationState,
                     Investigation, MispNotice, PlaybookRun, Tenant, utcnow)
from .observability import log_event
from .security import audit, validate_runtime_secrets
from .state import PipelineState, move_alert
from .workflow import _integration, aware, ingest, process_alert

celery_app = Celery("soc", broker=settings().redis_url, backend=settings().redis_url)
celery_app.conf.update(task_serializer="json", accept_content=["json"], result_serializer="json",
                       task_acks_late=True, worker_prefetch_multiplier=1,
                       broker_connection_retry_on_startup=True,
                       beat_schedule={
                           "recover": {"task": "soc.recover", "schedule": 60.0},
                           "poll_splunk": {"task": "soc.poll_splunk", "schedule": float(settings().splunk_poll_seconds)},
                           "health": {"task": "soc.check_integrations", "schedule": 120.0},
                       })
validate_runtime_secrets(settings().mode, settings().jwt_secret, settings().webhook_secret)


_TERMINAL_STATUS = {
    PipelineState.CASE_CREATED: "escalated",
    PipelineState.CLOSED_FP: "auto_closed",
    PipelineState.SUPPRESSED: "suppressed",
    PipelineState.FAILED_PERMANENT: "failed",
}


def _repair_terminal_alert(db, alert: Alert) -> bool:
    """Keep a committed terminal action terminal after a worker interruption."""
    expected = _TERMINAL_STATUS.get(alert.pipeline_state)
    if expected is None:
        return False
    if alert.pipeline_state == PipelineState.CLOSED_FP:
        manual = db.scalar(select(Audit.id).where(
            Audit.tenant_id == alert.tenant_id,
            Audit.subject_type == "investigation",
            Audit.subject_id == alert.investigation_id,
            Audit.operation == "manual_close_granted").limit(1))
        if manual:
            expected = "closed"
        elif alert.status == "closed":
            # Preserve an already final human-initiated outcome.
            expected = "closed"
    inv = db.scalar(select(Investigation).where(
        Investigation.id == alert.investigation_id,
        Investigation.tenant_id == alert.tenant_id))
    changed = alert.status != expected or alert.claimed_at is not None
    if inv:
        changed = changed or inv.status != expected or inv.claimed_at is not None
    if not changed:
        return False
    alert.status = expected
    alert.claimed_at = None
    alert.processed_at = alert.processed_at or utcnow()
    if inv:
        inv.status = expected
        inv.claimed_at = None
        if alert.pipeline_state != PipelineState.FAILED_PERMANENT:
            inv.completed_at = inv.completed_at or utcnow()
    audit(db, alert.tenant_id, "worker", "terminal_state_reconciled", "alert", alert.id,
          {"pipeline_state": alert.pipeline_state, "status": expected})
    return True


def dispatch(alert_id: str) -> bool:
    try:
        process_alert_task.delay(alert_id)
        with SessionLocal() as db:
            alert = db.get(Alert, alert_id)
            if alert:
                alert.last_dispatched_at = utcnow()
                db.commit()
        return True
    except Exception:
        # Persisted queued alert is recovered by periodic task when Redis returns.
        return False


@celery_app.task(name="soc.process_alert", bind=True, max_retries=3,
                 soft_time_limit=settings().investigation_timeout_seconds,
                 time_limit=settings().investigation_timeout_seconds + 15)
def process_alert_task(self, alert_id: str) -> None:
    with SessionLocal() as db:
        try:
            process_alert(db, alert_id)
            log_event("alert_processed", event_id=alert_id)
        except Exception as exc:
            db.rollback()
            alert = db.get(Alert, alert_id)
            if alert and alert.pipeline_state in _TERMINAL_STATUS:
                _repair_terminal_alert(db, alert)
                db.commit()
                log_event("alert_terminal_recovered", event_id=alert_id,
                          tenant_id=alert.tenant_id, status=alert.status,
                          error_type=type(exc).__name__)
                return
            if self.request.retries < self.max_retries:
                log_event("alert_retryable_error", event_id=alert_id, error_type=type(exc).__name__)
                if alert:
                    if alert.pipeline_state not in {PipelineState.CASE_CREATED, PipelineState.CLOSED_FP,
                                                    PipelineState.SUPPRESSED, PipelineState.FAILED_PERMANENT}:
                        move_alert(db, alert, PipelineState.FAILED_RETRYABLE, "worker",
                                   "processing_exception")
                    alert.status = "queued"
                    alert.claimed_at = None
                    inv = db.get(Investigation, alert.investigation_id)
                    if inv and inv.status == "running":
                        inv.status = "queued"
                        inv.claimed_at = None
                    run = db.scalar(select(PlaybookRun).where(PlaybookRun.tenant_id == alert.tenant_id,
                        PlaybookRun.investigation_id == alert.investigation_id,
                        PlaybookRun.status == "running").order_by(PlaybookRun.started_at.desc()).limit(1))
                    if run:
                        run.status = "failed"
                        run.completed_at = utcnow()
                    db.commit()
                raise self.retry(exc=exc, countdown=min(10 * (2 ** self.request.retries), 60))
            alert = db.scalar(select(Alert).where(Alert.id == alert_id))
            if alert:
                if alert.pipeline_state not in {PipelineState.CASE_CREATED, PipelineState.CLOSED_FP,
                                                PipelineState.SUPPRESSED, PipelineState.FAILED_PERMANENT}:
                    move_alert(db, alert, PipelineState.FAILED_RETRYABLE, "worker",
                               "retry_budget_exhausted")
                    move_alert(db, alert, PipelineState.FAILED_PERMANENT, "worker",
                               "dead_letter_created")
                alert.status = "failed"
                existing = db.scalar(select(DeadLetter).where(DeadLetter.tenant_id == alert.tenant_id,
                    DeadLetter.alert_id == alert.id, DeadLetter.status == "open"))
                if not existing:
                    db.add(DeadLetter(tenant_id=alert.tenant_id, alert_id=alert.id,
                                      error=f"{type(exc).__name__}: {str(exc)[:300]}", attempts=self.max_retries + 1))
                audit(db, alert.tenant_id, "worker", "dead_letter", "alert", alert.id,
                      {"error_type": type(exc).__name__})
                db.commit()
                log_event("alert_dead_lettered", event_id=alert_id,
                          tenant_id=alert.tenant_id, error_type=type(exc).__name__)


@celery_app.task(name="soc.recover")
def recover() -> int:
    queued_cutoff = utcnow() - timedelta(minutes=5)
    running_cutoff = utcnow() - timedelta(minutes=2)
    with SessionLocal() as db:
        terminal_mismatch = or_(
            and_(Alert.pipeline_state == PipelineState.CASE_CREATED,
                 Alert.status != "escalated"),
            and_(Alert.pipeline_state == PipelineState.CLOSED_FP,
                 Alert.status.notin_(("auto_closed", "closed"))),
            and_(Alert.pipeline_state == PipelineState.SUPPRESSED,
                 Alert.status != "suppressed"),
            and_(Alert.pipeline_state == PipelineState.FAILED_PERMANENT,
                 Alert.status != "failed"),
        )
        terminal = db.scalars(select(Alert).where(terminal_mismatch)
                              .limit(200).with_for_update()).all()
        for alert in terminal:
            _repair_terminal_alert(db, alert)
        alerts = db.scalars(select(Alert).where(
            Alert.pipeline_state.notin_(_TERMINAL_STATUS),
            ((Alert.status == "queued") & ((Alert.last_dispatched_at.is_(None)) | (Alert.last_dispatched_at < queued_cutoff))) |
            ((Alert.status == "running") & ((Alert.claimed_at.is_(None)) | (Alert.claimed_at < running_cutoff)))
        ).limit(200)).all()
        for alert in alerts:
            if alert.status != "running":
                continue
            if alert.pipeline_state not in {PipelineState.CASE_CREATED, PipelineState.CLOSED_FP,
                                            PipelineState.SUPPRESSED, PipelineState.FAILED_PERMANENT}:
                move_alert(db, alert, PipelineState.FAILED_RETRYABLE, "worker", "stale_claim_recovered")
            alert.status = "queued"
            alert.claimed_at = None
            inv = db.get(Investigation, alert.investigation_id)
            if inv and inv.status == "running":
                inv.status = "queued"
                inv.claimed_at = None
            run = db.scalar(select(PlaybookRun).where(PlaybookRun.tenant_id == alert.tenant_id,
                PlaybookRun.investigation_id == alert.investigation_id,
                PlaybookRun.status == "running").order_by(PlaybookRun.started_at.desc()).limit(1))
            if run:
                run.status = "interrupted"
                run.completed_at = utcnow()
            audit(db, alert.tenant_id, "worker", "stale_claim_recovered", "alert", alert.id)
        for tenant in db.scalars(select(Tenant)).all():
            _integration(db, tenant.id, "worker", "healthy", "Последний heartbeat worker")
        db.commit()
        count = 0
        for alert in alerts:
            if dispatch(alert.id):
                count += 1
        return count


MAX_QUARANTINE_RAW_BYTES = 256 * 1024


def _splunk_row_identity(row: object) -> tuple[dict | object, str, str]:
    """Keep the original JSON, but ignore volatile search metadata for identity."""
    raw_json = json.dumps(row, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    stable_row = ({key: value for key, value in row.items()
                   if not key.startswith("_soc_splunk_")} if isinstance(row, dict) else row)
    stable_json = json.dumps(stable_row, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    supplied = (stable_row.get("_cd") or stable_row.get("event_id")) if isinstance(stable_row, dict) else None
    if isinstance(supplied, (str, int)) and not isinstance(supplied, bool):
        source_id = str(supplied)
    else:
        source_id = ""
    if not source_id:
        source_id = sha256(stable_json.encode()).hexdigest()
    elif len(source_id) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in source_id):
        source_id = "sha256:" + sha256(source_id.encode()).hexdigest()
    return stable_row, raw_json, source_id


def _save_quarantine(db, tenant_id: str, source_id: str, raw_json: str, exc: Exception) -> None:
    """Commit before continuing; a failed write must leave the checkpoint in place."""
    full_raw = raw_json.encode("utf-8")
    truncated = len(full_raw) > MAX_QUARANTINE_RAW_BYTES
    excerpt = (full_raw[:MAX_QUARANTINE_RAW_BYTES].decode("utf-8", errors="ignore")
               if truncated else raw_json)
    row = db.scalar(select(IngestionQuarantine).where(
        IngestionQuarantine.tenant_id == tenant_id,
        IngestionQuarantine.source == "splunk",
        IngestionQuarantine.source_event_id == source_id).with_for_update())
    if row:
        row.occurrences += 1
        row.last_seen_at = utcnow()
    else:
        db.add(IngestionQuarantine(
            tenant_id=tenant_id, source="splunk", source_event_id=source_id,
            raw_json=excerpt, raw_sha256=sha256(full_raw).hexdigest(),
            raw_bytes=len(full_raw), raw_truncated=truncated,
            error_type=type(exc).__name__[:100], reason=str(exc)[:500]))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        row = db.scalar(select(IngestionQuarantine).where(
            IngestionQuarantine.tenant_id == tenant_id,
            IngestionQuarantine.source == "splunk",
            IngestionQuarantine.source_event_id == source_id).with_for_update())
        if row is None:
            raise
        row.occurrences += 1
        row.last_seen_at = utcnow()
        db.commit()


@celery_app.task(name="soc.poll_splunk")
def poll_splunk() -> int:
    if settings().mode.upper() != "CONNECTED":
        return 0
    total = 0
    with SessionLocal() as db:
        tenants = db.scalars(select(Tenant)).all()
        if len(tenants) != 1:
            for tenant in tenants:
                _integration(db, tenant.id, "splunk", "unknown", "Общий опрос Splunk поддерживает только одного заказчика")
            db.commit()
            return 0
        for tenant in tenants:
            now = utcnow()
            cp = db.scalar(select(Checkpoint).where(Checkpoint.tenant_id == tenant.id, Checkpoint.source == "splunk"))
            cursor = aware(cp.cursor_at) if cp else now - timedelta(minutes=5)
            if cursor >= now:
                _integration(db, tenant.id, "splunk", "degraded", "Checkpoint Splunk находится в будущем")
                db.commit()
                return total
            max_window = settings().splunk_max_window_seconds
            overlap = max(0, min(settings().splunk_overlap_seconds, max_window // 2))
            earliest = cursor - timedelta(seconds=overlap)
            latest = min(now, cursor + timedelta(seconds=max_window - overlap))
            try:
                splunk = splunk_adapter()
                rows = splunk.poll(earliest, latest)
                quarantined = 0
                for row in rows:
                    stable_row, raw_json, source_id = _splunk_row_identity(row)
                    try:
                        if not isinstance(stable_row, dict):
                            raise ValueError("Строка Splunk должна быть объектом")
                        payload = {"source": "splunk", "source_event_id": source_id,
                                   "event_at": (stable_row.get("_time") if "_time" in stable_row
                                                else stable_row.get("event_at")),
                                   "raw": stable_row}
                        if "rule" not in stable_row and stable_row.get("search_name"):
                            payload["rule"] = stable_row["search_name"]
                        if stable_row.get("title") or stable_row.get("search_name"):
                            payload["title"] = stable_row.get("title") or stable_row["search_name"]
                        if stable_row.get("original_timezone"):
                            payload["original_timezone"] = stable_row["original_timezone"]
                        normalize_alert(payload, tenant.id)
                    except (TypeError, ValueError) as exc:
                        _save_quarantine(db, tenant.id, source_id, raw_json, exc)
                        quarantined += 1
                        log_event("splunk_row_quarantined", tenant_id=tenant.id,
                                  error_type=type(exc).__name__)
                        continue
                    alert, created = ingest(db, tenant.id, payload)
                    if created:
                        dispatch(alert.id)
                        total += 1
                if len(rows) >= 2000:
                    _integration(db, tenant.id, "splunk", "degraded", "Окно опроса достигло лимита 2000; checkpoint не сдвинут")
                    db.commit()
                    log_event("splunk_poll_capped", tenant_id=tenant.id, status="degraded")
                    return total
                if not cp:
                    cp = Checkpoint(tenant_id=tenant.id, source="splunk", cursor_at=latest)
                    db.add(cp)
                cp.cursor_at, cp.updated_at = latest, now
                status = "degraded" if quarantined else "healthy"
                detail = f"Некорректных строк сохранено в карантин: {quarantined}" if quarantined else ""
                _integration(db, tenant.id, "splunk", status, detail, received=bool(rows))
                db.commit()
                log_event("splunk_poll_completed", tenant_id=tenant.id, status=status)
            except Exception as exc:
                db.rollback()
                _integration(db, tenant.id, "splunk", "unavailable", type(exc).__name__)
                db.commit()
                log_event("splunk_poll_failed", tenant_id=tenant.id, status="unavailable",
                          error_type=type(exc).__name__)
    return total


@celery_app.task(name="soc.check_integrations")
def check_integrations() -> None:
    with SessionLocal() as db:
        for tenant in db.scalars(select(Tenant)).all():
            db.execute(text("SELECT 1"))
            dialect = db.get_bind().dialect.name
            database_status = "healthy" if (settings().mode.upper() == "DEMO" or dialect == "postgresql") else "unavailable"
            database_detail = "SQLite DEMO" if settings().mode.upper() == "DEMO" else (
                "PostgreSQL отвечает" if database_status == "healthy" else "CONNECTED требует PostgreSQL")
            _integration(db, tenant.id, "database", database_status, database_detail)
            if settings().mode.upper() == "DEMO":
                _integration(db, tenant.id, "redis", "not_applicable", "DEMO использует Celery eager")
                _integration(db, tenant.id, "worker", "not_applicable", "DEMO выполняет задачи в процессе API")
            else:
                import redis

                try:
                    redis.Redis.from_url(settings().redis_url, socket_connect_timeout=2, socket_timeout=2).ping()
                    _integration(db, tenant.id, "redis", "healthy", "Redis отвечает")
                except redis.RedisError as exc:
                    _integration(db, tenant.id, "redis", "unavailable", type(exc).__name__)
            if settings().ollama_base_url or settings().ollama_model:
                try:
                    model = ollama_health()
                    _integration(db, tenant.id, "ollama", "healthy",
                                 f"{model['model']}, prompt {model['prompt_version']}")
                except Exception as exc:
                    _integration(db, tenant.id, "ollama", "unavailable", type(exc).__name__)
            else:
                _integration(db, tenant.id, "ollama", "not_configured", "Локальная модель не настроена")
            for name, factory in (("splunk", splunk_adapter), ("thehive", thehive_adapter), ("misp", misp_adapter)):
                try:
                    adapter = factory()
                    adapter.health()
                    version = getattr(adapter, "_verified_version", None) if name == "thehive" else None
                    _integration(db, tenant.id, name, "healthy", f"API {version}" if version else "")
                    if name == "misp":
                        for item in adapter.notices()[:20]:
                            event = item.get("Event", item)
                            external_id = str(event.get("uuid") or event.get("id") or "")
                            if external_id and not db.scalar(select(MispNotice).where(
                                MispNotice.tenant_id == tenant.id, MispNotice.external_id == external_id)):
                                db.add(MispNotice(tenant_id=tenant.id, external_id=external_id,
                                                  title=str(event.get("info") or "Сообщение MISP")[:300], data=event))
                except Exception as exc:
                    _integration(db, tenant.id, name, "unavailable", type(exc).__name__)
            # A green API check cannot assert that data is arriving. Track the gap separately.
            for row in db.scalars(select(IntegrationState).where(IntegrationState.tenant_id == tenant.id)).all():
                if row.name == "splunk" and row.last_received_at:
                    if utcnow() - aware(row.last_received_at) > timedelta(minutes=15) and row.status == "healthy":
                        row.status = "stale"
                        row.detail = "Нет поступления алертов более 15 минут"
                elif row.name == "splunk" and row.status == "healthy":
                    row.status = "unknown"
                    row.detail = "Поступление логов ещё не подтверждено"
            db.commit()
