"""A malformed Splunk row cannot silently disappear or pin the poll cursor."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from types import SimpleNamespace

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Alert, Checkpoint, IngestionQuarantine, IntegrationState, Tenant
import app.tasks as tasks


NOW = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)


def setup(monkeypatch, rows):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="splunk-quarantine", deployment_mode="CONNECTED")
        db.add(tenant)
        db.flush()
        db.add(Checkpoint(tenant_id=tenant.id, source="splunk", cursor_at=NOW - timedelta(minutes=30)))
        db.commit()
        tenant_id = tenant.id
    splunk = SimpleNamespace(poll=lambda _earliest, _latest: rows)
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    monkeypatch.setattr(tasks, "settings", lambda: SimpleNamespace(
        mode="CONNECTED", splunk_max_window_seconds=3600, splunk_overlap_seconds=120))
    monkeypatch.setattr(tasks, "utcnow", lambda: NOW)
    monkeypatch.setattr(tasks, "splunk_adapter", lambda: splunk)
    monkeypatch.setattr(tasks, "dispatch", lambda _alert_id: True)
    return engine, tenant_id


def test_invalid_row_is_durable_and_good_rows_continue(monkeypatch):
    invalid = {"_cd": "bad-1", "_time": "bad-time", "rule": "root_ssh",
               "host": "srv-1", "_soc_splunk_search_sid": "job-1"}
    good = {"_cd": "good-1", "_time": "2026-11-10T11:59:00+00:00",
            "rule": "root_ssh", "host": "srv-2", "user": "root"}
    rows = [invalid, good]
    engine, tenant_id = setup(monkeypatch, rows)
    try:
        assert tasks.poll_splunk() == 1
        with Session(engine) as db:
            quarantine = db.scalar(select(IngestionQuarantine))
            assert quarantine.tenant_id == tenant_id
            assert quarantine.source == "splunk" and quarantine.source_event_id == "bad-1"
            assert json.loads(quarantine.raw_json) == invalid
            assert quarantine.reason and quarantine.error_type == "ValueError"
            assert quarantine.raw_truncated is False
            assert db.scalar(select(func.count()).select_from(Alert)) == 1
            assert db.scalar(select(Checkpoint.cursor_at)) == NOW.replace(tzinfo=None)
            state = db.scalar(select(IntegrationState).where(IntegrationState.name == "splunk"))
            assert state.status == "degraded"

            # Overlap/replay sees the same bad source ID with a new search SID.
            db.scalar(select(Checkpoint)).cursor_at = NOW - timedelta(minutes=30)
            db.commit()
        invalid["_soc_splunk_search_sid"] = "job-2"
        assert tasks.poll_splunk() == 0
        with Session(engine) as db:
            assert db.scalar(select(func.count()).select_from(IngestionQuarantine)) == 1
            quarantine = db.scalar(select(IngestionQuarantine))
            assert quarantine.occurrences == 2
            assert json.loads(quarantine.raw_json)["_soc_splunk_search_sid"] == "job-1"
            assert db.scalar(select(func.count()).select_from(Alert)) == 1
    finally:
        engine.dispose()


def test_oversized_bad_row_has_bounded_raw_and_full_digest(monkeypatch):
    bad = {"_cd": "huge-bad-1", "_time": "bad-time", "_raw": "x" * 300_000}
    engine, _ = setup(monkeypatch, [bad])
    try:
        assert tasks.poll_splunk() == 0
        with Session(engine) as db:
            item = db.scalar(select(IngestionQuarantine))
            original = json.dumps(bad, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False, allow_nan=False).encode()
            assert item.raw_truncated is True
            assert item.raw_bytes == len(original)
            assert item.raw_sha256 == sha256(original).hexdigest()
            assert len(item.raw_json.encode()) <= tasks.MAX_QUARANTINE_RAW_BYTES
            assert db.scalar(select(Checkpoint.cursor_at)) == NOW.replace(tzinfo=None)
    finally:
        engine.dispose()


def test_checkpoint_does_not_advance_when_quarantine_persistence_fails(monkeypatch):
    bad = {"_cd": "bad-1", "_time": "bad-time"}
    engine, _ = setup(monkeypatch, [bad])

    class FailingSession(Session):
        def commit(self):
            if any(isinstance(item, IngestionQuarantine) for item in self.new):
                raise OSError("quarantine storage failed")
            return super().commit()

    monkeypatch.setattr(tasks, "SessionLocal", lambda: FailingSession(engine))
    try:
        assert tasks.poll_splunk() == 0
        with Session(engine) as db:
            assert db.scalar(select(Checkpoint.cursor_at)) == (NOW - timedelta(minutes=30)).replace(tzinfo=None)
            assert db.scalar(select(func.count()).select_from(IngestionQuarantine)) == 0
            state = db.scalar(select(IntegrationState).where(IntegrationState.name == "splunk"))
            assert state.status == "unavailable"
    finally:
        engine.dispose()


def test_non_json_row_cannot_be_quarantined_and_keeps_checkpoint(monkeypatch):
    bad = {"_cd": "bad-1", "_time": "bad-time", "object": object()}
    engine, _ = setup(monkeypatch, [bad])
    try:
        assert tasks.poll_splunk() == 0
        with Session(engine) as db:
            assert db.scalar(select(Checkpoint.cursor_at)) == (NOW - timedelta(minutes=30)).replace(tzinfo=None)
            assert db.scalar(select(func.count()).select_from(IngestionQuarantine)) == 0
    finally:
        engine.dispose()
