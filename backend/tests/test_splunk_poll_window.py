"""A long Splunk outage must be replayed in bounded checkpoint windows."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Checkpoint, Tenant
import app.tasks as tasks


def test_long_backlog_advances_only_one_bounded_window(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
    old_cursor = now - timedelta(hours=10)
    with Session(engine) as db:
        tenant = Tenant(name="splunk-backlog", deployment_mode="CONNECTED", automation_level="observe")
        db.add(tenant)
        db.flush()
        db.add(Checkpoint(tenant_id=tenant.id, source="splunk", cursor_at=old_cursor))
        db.commit()

    class Splunk:
        def __init__(self):
            self.windows = []

        def poll(self, earliest, latest):
            self.windows.append((earliest, latest))
            return [{"_time": "2026-11-10T11:00:00+00:00", "rule": "test",
                     "host": "srv-1", "_raw": "same event",
                     "_soc_splunk_search_sid": f"job-{len(self.windows)}",
                     "_soc_splunk_result_offset": len(self.windows)}]

    splunk = Splunk()
    payloads = []
    monkeypatch.setattr(tasks, "SessionLocal", lambda: Session(engine))
    monkeypatch.setattr(tasks, "settings", lambda: SimpleNamespace(
        mode="CONNECTED", splunk_max_window_seconds=3600, splunk_overlap_seconds=120))
    monkeypatch.setattr(tasks, "utcnow", lambda: now)
    monkeypatch.setattr(tasks, "splunk_adapter", lambda: splunk)
    monkeypatch.setattr(tasks, "ingest", lambda _db, _tenant, payload: (
        payloads.append(payload) or SimpleNamespace(id="unchanged"), False))

    assert tasks.poll_splunk() == 0
    assert len(splunk.windows) == 1
    earliest, latest = splunk.windows[0]
    assert earliest == old_cursor - timedelta(seconds=120)
    assert latest - earliest == timedelta(seconds=3600)
    assert latest < now
    with Session(engine) as db:
        checkpoint = db.scalar(select(Checkpoint).where(Checkpoint.source == "splunk"))
        assert tasks.aware(checkpoint.cursor_at) == latest
    assert tasks.poll_splunk() == 0
    assert splunk.windows[1][0] == latest - timedelta(seconds=120)
    assert payloads[0]["source_event_id"] == payloads[1]["source_event_id"]
    assert "_soc_splunk_search_sid" not in payloads[0]["raw"]
    assert "_soc_splunk_result_offset" not in payloads[1]["raw"]
    engine.dispose()
