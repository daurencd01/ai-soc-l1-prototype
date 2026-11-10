"""Database-level ingestion guarantees for normalization and deduplication."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.config import settings
from app.models import Alert, AlertFingerprint, Investigation, Tenant, utcnow
from app.workflow import ingest


def database() -> Session:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return Session(engine)


def tenant(db: Session, name: str) -> Tenant:
    row = Tenant(name=name)
    db.add(row)
    db.commit()
    return row


def sample(source_id: str = "delivery-1") -> dict:
    return {
        "source": "splunk", "source_event_id": source_id, "rule": "root_ssh",
        "event_at": "2026-11-10T12:00:00+06:00", "severity": "high",
        "correlation_key": "untrusted-client-group",
        "raw": {"host": "APP-01.Example.COM", "user": "root", "src_ip": "203.0.113.4",
                "auth_method": "publickey", "success": True},
    }


def test_same_source_id_is_idempotent_and_raw_is_unchanged():
    with database() as db:
        owner = tenant(db, "one")
        payload = sample()
        before = deepcopy(payload["raw"])
        first, created = ingest(db, owner.id, payload)
        assert created
        second, created = ingest(db, owner.id, payload)
        assert not created and second.id == first.id
        assert db.scalar(select(func.count()).select_from(Alert)) == 1
        assert first.raw == before and payload["raw"] == before
        assert first.normalized["host"] == "app-01.example.com"
        assert first.normalized["event_id"] == "delivery-1"
        assert first.normalized["rule_name"] is None
        assert first.normalized["raw_event_reference"] is None


def test_new_source_id_with_same_fingerprint_is_deduplicated_until_expiry():
    with database() as db:
        owner = tenant(db, "one")
        first, _ = ingest(db, owner.id, sample())
        redelivery, created = ingest(db, owner.id, sample("delivery-2"))
        assert not created and redelivery.id == first.id
        assert db.scalar(select(func.count()).select_from(Alert)) == 1
        claim = db.scalar(select(AlertFingerprint).where(AlertFingerprint.tenant_id == owner.id))
        assert claim.alert_id == first.id

        claim.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
        later, created = ingest(db, owner.id, sample("delivery-3"))
        assert created and later.id != first.id
        assert later.fingerprint == first.fingerprint
        assert db.scalar(select(func.count()).select_from(Alert)) == 2
        assert db.scalar(select(func.count()).select_from(AlertFingerprint)) == 1
        assert claim.alert_id == later.id


def test_configured_fingerprint_ttl_is_stored(monkeypatch):
    monkeypatch.setattr(settings(), "fingerprint_ttl_seconds", 7)
    with database() as db:
        owner = tenant(db, "one")
        alert, _ = ingest(db, owner.id, sample())
        claim = db.scalar(select(AlertFingerprint).where(AlertFingerprint.tenant_id == owner.id))
        ingested_at = datetime.fromisoformat(alert.normalized["ingestion_time"])
        expires_at = claim.expires_at.replace(tzinfo=timezone.utc)
        assert expires_at - ingested_at == timedelta(seconds=7)


def test_fingerprint_and_source_id_are_tenant_scoped():
    with database() as db:
        first_tenant = tenant(db, "one")
        second_tenant = tenant(db, "two")
        first, _ = ingest(db, first_tenant.id, sample())
        second, created = ingest(db, second_tenant.id, sample())
        assert created and second.id != first.id
        assert second.fingerprint != first.fingerprint
        assert second.investigation_id != first.investigation_id
        assert db.scalar(select(func.count()).select_from(AlertFingerprint)) == 2


def test_conflicting_client_correlation_key_cannot_merge():
    with database() as db:
        owner = tenant(db, "one")
        first, _ = ingest(db, owner.id, sample())
        conflict = sample("delivery-2")
        conflict["raw"]["host"] = "other.example.com"
        second, _ = ingest(db, owner.id, conflict)
        assert first.investigation_id != second.investigation_id


def test_database_guard_splits_colliding_correlation_keys(monkeypatch):
    import app.workflow as workflow

    with database() as db:
        owner = tenant(db, "one")
        first, _ = ingest(db, owner.id, sample())
        same_key = db.get(Investigation, first.investigation_id).correlation_key
        real_normalize = workflow.normalize_alert

        def forced_collision(payload, tenant_id, **kwargs):
            result = real_normalize(payload, tenant_id, **kwargs)
            return replace(result, correlation_key=same_key)

        monkeypatch.setattr(workflow, "normalize_alert", forced_collision)
        conflict = sample("delivery-2")
        conflict["raw"]["host"] = "other.example.com"
        second, _ = ingest(db, owner.id, conflict)
        assert first.investigation_id != second.investigation_id
        assert db.scalar(select(func.count()).select_from(Investigation)) == 2


def test_sparse_normalized_fields_are_null_not_inferred():
    with database() as db:
        owner = tenant(db, "one")
        payload = {"source": "splunk", "source_event_id": "sparse",
                   "event_at": "2026-11-10T12:00:00+06:00", "raw": {}}
        alert, created = ingest(db, owner.id, payload)
        assert created
        assert alert.normalized["rule_id"] is None
        assert alert.normalized["severity"] is None
        assert alert.normalized["host"] is None
        assert alert.normalized["user"] is None
