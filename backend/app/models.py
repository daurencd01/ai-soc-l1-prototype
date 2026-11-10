from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, Index, text
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


def uid() -> str:
    return str(uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    deployment_mode: Mapped[str] = mapped_column(String(20), default="DEMO")
    automation_level: Mapped[str] = mapped_column(String(30), default="observe")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(20))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("tenant_id", "source", "source_event_id"), Index("ix_alert_tenant_received", "tenant_id", "received_at"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(50))
    source_event_id: Mapped[str] = mapped_column(String(256))
    rule: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="queued")
    pipeline_state: Mapped[str] = mapped_column(String(30), default="RECEIVED")
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    original_timezone: Mapped[str] = mapped_column(String(80), default="UTC")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AlertFingerprint(Base):
    """Active tenant-scoped deduplication claim; expired claims can be reused."""

    __tablename__ = "alert_fingerprints"
    __table_args__ = (UniqueConstraint("tenant_id", "fingerprint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EmbeddedEvent(Base):
    __tablename__ = "embedded_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    source_event_id: Mapped[str] = mapped_column(String(256))
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    original_timezone: Mapped[str] = mapped_column(String(80), default="UTC")
    data: Mapped[dict] = mapped_column(JSON)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (UniqueConstraint("tenant_id", "correlation_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    correlation_key: Mapped[str] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(30), default="queued")
    verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)
    classification: Mapped[str | None] = mapped_column(String(30), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    playbook_key: Mapped[str] = mapped_column(String(100))
    playbook_version: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    missing_data: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    analyzer: Mapped[str] = mapped_column(String(50), default="deterministic_demo")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    kind: Mapped[str] = mapped_column(String(80))
    source: Mapped[str] = mapped_column(String(80))
    summary: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    key: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="running")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Decision(Base):
    __tablename__ = "decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(30))
    classification: Mapped[str | None] = mapped_column(String(30), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority: Mapped[str] = mapped_column(String(20))
    summary: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    evidence_for: Mapped[list] = mapped_column(JSON, default=list)
    evidence_against: Mapped[list] = mapped_column(JSON, default=list)
    missing_data: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    actor: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PipelineTransition(Base):
    """Append-only history for one alert's validated processing stages."""
    __tablename__ = "pipeline_transitions"
    __table_args__ = (Index("ix_pipeline_transition_alert_time", "tenant_id", "alert_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    from_state: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_state: Mapped[str] = mapped_column(String(30))
    actor: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Action(Base):
    __tablename__ = "actions"
    __table_args__ = (UniqueConstraint("tenant_id", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    kind: Mapped[str] = mapped_column(String(60))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    idempotency_key: Mapped[str] = mapped_column(String(256))
    target: Mapped[str] = mapped_column(String(256), default="")
    external_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Case(Base):
    __tablename__ = "cases"
    __table_args__ = (UniqueConstraint("tenant_id", "investigation_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    external_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="pending")
    title: Mapped[str] = mapped_column(String(300))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaseWrite(Base):
    """One durable, auditable external mutation in a TheHive case workflow."""
    __tablename__ = "case_writes"
    __table_args__ = (UniqueConstraint("tenant_id", "idempotency_key"),
                      UniqueConstraint("tenant_id", "case_id", "sequence"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(30))
    idempotency_key: Mapped[str] = mapped_column(String(256))
    request_data: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    external_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExceptionRule(Base):
    __tablename__ = "exceptions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "policy_key", "version", name="uq_exceptions_tenant_policy_version"),
        Index("uq_exceptions_one_approved_version", "tenant_id", "policy_key", unique=True,
              sqlite_where=text("approval_status = 'approved'"),
              postgresql_where=text("approval_status = 'approved'")),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_key: Mapped[str] = mapped_column(String(36), default=uid)
    version: Mapped[int] = mapped_column(Integer, default=1)
    rule: Mapped[str] = mapped_column(String(100))
    entity: Mapped[str] = mapped_column(String(256))
    owner: Mapped[str] = mapped_column(String(100), default="")
    created_by: Mapped[str] = mapped_column(String(100), default="")
    reason: Mapped[str] = mapped_column(Text)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approval_status: Mapped[str] = mapped_column(String(20), default="draft")
    approved_by: Mapped[str] = mapped_column(String(100), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    change_reason: Mapped[str] = mapped_column(Text, default="")
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyEvent(Base):
    """Append-only API history for one FP policy version."""
    __tablename__ = "policy_events"
    __table_args__ = (Index("ix_policy_events_tenant_policy_time", "tenant_id", "policy_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("exceptions.id"), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(30))
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SuppressionRule(Base):
    """Separately approved policy for grouping one bounded NOISE fingerprint."""
    __tablename__ = "suppression_rules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "policy_key", "version", name="uq_suppression_tenant_policy_version"),
        Index("uq_suppression_one_approved_version", "tenant_id", "policy_key", unique=True,
              sqlite_where=text("approval_status = 'approved'"),
              postgresql_where=text("approval_status = 'approved'")),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_key: Mapped[str] = mapped_column(String(36), default=uid)
    version: Mapped[int] = mapped_column(Integer, default=1)
    rule: Mapped[str] = mapped_column(String(100))
    entity: Mapped[str] = mapped_column(String(256))
    owner: Mapped[str] = mapped_column(String(100))
    created_by: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(Text)
    scope: Mapped[dict] = mapped_column(JSON)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approval_status: Mapped[str] = mapped_column(String(20), default="draft")
    approved_by: Mapped[str] = mapped_column(String(100), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    change_reason: Mapped[str] = mapped_column(Text)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SuppressionEvent(Base):
    """Append-only approval trail for a NOISE suppression policy version."""
    __tablename__ = "suppression_events"
    __table_args__ = (Index("ix_suppression_events_tenant_policy_time", "tenant_id", "policy_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("suppression_rules.id"), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(30))
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Maintenance(Base):
    __tablename__ = "maintenance"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    entity: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str] = mapped_column(String(100))


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "kind", "value"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    value: Mapped[str] = mapped_column(String(256))
    owner: Mapped[str] = mapped_column(String(256), default="")
    criticality: Mapped[str] = mapped_column(String(20), default="unknown")
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)


class Shift(Base):
    __tablename__ = "shifts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    timezone: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(30), default="open")
    outgoing_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    incoming_name: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("tenant_id", "shift_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default="approved")
    content: Mapped[str] = mapped_column(Text)
    counters: Mapped[dict] = mapped_column(JSON, default=dict)
    approved_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    actor: Mapped[str] = mapped_column(String(100))
    operation: Mapped[str] = mapped_column(String(100))
    subject_type: Mapped[str] = mapped_column(String(50))
    subject_id: Mapped[str] = mapped_column(String(256))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntegrationState(Base):
    __tablename__ = "integration_states"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(60))
    status: Mapped[str] = mapped_column(String(30), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")


class Checkpoint(Base):
    __tablename__ = "checkpoints"
    __table_args__ = (UniqueConstraint("tenant_id", "source"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    source: Mapped[str] = mapped_column(String(60))
    cursor_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IngestionQuarantine(Base):
    """Durable evidence of a source row rejected by alert normalization."""

    __tablename__ = "ingestion_quarantine"
    __table_args__ = (UniqueConstraint("tenant_id", "source", "source_event_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    source: Mapped[str] = mapped_column(String(50))
    source_event_id: Mapped[str] = mapped_column(String(256))
    raw_json: Mapped[str] = mapped_column(Text)
    raw_sha256: Mapped[str] = mapped_column(String(64))
    raw_bytes: Mapped[int] = mapped_column(Integer)
    raw_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    error_type: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(String(500))
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeadLetter(Base):
    __tablename__ = "dead_letters"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    error: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(30), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MispNotice(Base):
    __tablename__ = "misp_notices"
    __table_args__ = (UniqueConstraint("tenant_id", "external_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(256))
    title: Mapped[str] = mapped_column(String(300))
    received_status: Mapped[str] = mapped_column(String(30), default="received")
    l1_status: Mapped[str] = mapped_column(String(30), default="pending")
    l2_status: Mapped[str] = mapped_column(String(30), default="not_transferred")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
