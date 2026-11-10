from datetime import timedelta
from celery import Celery
from sqlalchemy import select
from .adapters import splunk_adapter, thehive_adapter, misp_adapter
from .config import settings
from .db import SessionLocal
from .models import (Alert, Checkpoint, DeadLetter, IntegrationState, Investigation, MispNotice, PlaybookRun, Tenant, utcnow)
from .security import audit
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
        except Exception as exc:
            db.rollback()
            if self.request.retries < self.max_retries:
                alert = db.get(Alert, alert_id)
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


@celery_app.task(name="soc.recover")
def recover() -> int:
    queued_cutoff = utcnow() - timedelta(minutes=5)
    running_cutoff = utcnow() - timedelta(minutes=2)
    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).where(
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
            earliest = (cp.cursor_at if cp else now - timedelta(minutes=5)) - timedelta(seconds=settings().splunk_overlap_seconds)
            try:
                splunk = splunk_adapter()
                rows = splunk.poll(earliest, now)
                for row in rows:
                    source_id = str(row.get("_cd") or row.get("event_id") or row.get("sid") or "")
                    if not source_id:
                        continue
                    payload = {"source": "splunk", "source_event_id": source_id,
                               "rule": row.get("rule") or row.get("search_name") or "generic",
                               "title": row.get("title") or row.get("search_name") or "Событие Splunk",
                               "severity": row.get("severity") or "medium", "event_at": row.get("_time") or now.isoformat(),
                               "original_timezone": row.get("original_timezone") or "UTC", "raw": row}
                    alert, created = ingest(db, tenant.id, payload)
                    if created:
                        dispatch(alert.id)
                        total += 1
                if len(rows) >= 2000:
                    _integration(db, tenant.id, "splunk", "degraded", "Окно опроса достигло лимита 2000; checkpoint не сдвинут")
                    db.commit()
                    return total
                if not cp:
                    cp = Checkpoint(tenant_id=tenant.id, source="splunk", cursor_at=now)
                    db.add(cp)
                cp.cursor_at, cp.updated_at = now, now
                _integration(db, tenant.id, "splunk", "healthy", received=bool(rows))
                db.commit()
            except Exception as exc:
                db.rollback()
                _integration(db, tenant.id, "splunk", "unavailable", type(exc).__name__)
                db.commit()
    return total


@celery_app.task(name="soc.check_integrations")
def check_integrations() -> None:
    with SessionLocal() as db:
        for tenant in db.scalars(select(Tenant)).all():
            for name, factory in (("splunk", splunk_adapter), ("thehive", thehive_adapter), ("misp", misp_adapter)):
                try:
                    adapter = factory()
                    adapter.health()
                    _integration(db, tenant.id, name, "healthy")
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
