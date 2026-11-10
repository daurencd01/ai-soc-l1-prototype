"""Tenant-scoped normalization and conservative duplicate/correlation keys.

This module is pure: it does not ingest events or decide whether to merge DB
records. The caller must persist fingerprint expiry and check the compatibility
guard before attaching a new alert to an existing investigation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
from math import isfinite
import re
from typing import Any
from unicodedata import normalize as unicode_normalize

from pydantic import BaseModel, ConfigDict, Field, field_validator


DEFAULT_FINGERPRINT_TTL_SECONDS = 24 * 60 * 60
DEFAULT_CORRELATION_WINDOW_SECONDS = 15 * 60
MAX_FINGERPRINT_TTL_SECONDS = 30 * 24 * 60 * 60
_ENTITY_FIELDS = ("host", "user", "src_ip", "dest_ip")


class SecurityAlert(BaseModel):
    """Normalized view of fields actually available in a source alert."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=50)
    tenant_id: str = Field(min_length=1, max_length=100)
    event_time: datetime
    ingestion_time: datetime
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    process_name: str | None = None
    process_command_line: str | None = None
    event_action: str | None = None
    raw_event_reference: str | None = None
    related_event_ids: tuple[str, ...] | None = None
    processing_status: str | None = None

    @field_validator("event_time", "ingestion_time")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Время должно содержать часовое смещение")
        return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class NormalizedIngest:
    alert: SecurityAlert
    original_raw: dict[str, Any]
    fingerprint: str
    fingerprint_expires_at: datetime
    correlation_key: str
    correlation_window_start: datetime


def _nonempty(value: object, field: str, limit: int) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} должен быть строкой")
    cleaned = unicode_normalize("NFC", value).strip()
    if not cleaned or len(cleaned) > limit or any(ord(char) < 32 or ord(char) == 127 for char in cleaned):
        raise ValueError(f"{field} содержит недопустимое значение")
    return cleaned


def _host(value: object) -> str | None:
    original = _nonempty(value, "host", 253)
    if original is None:
        return None
    normalized = original.rstrip(".").casefold()
    if not normalized or any(char.isspace() for char in normalized):
        raise ValueError("host содержит недопустимое значение")
    return normalized


def _ip(value: object, field: str) -> str | None:
    original = _nonempty(value, field, 45)
    if original is None:
        return None
    try:
        return ip_address(original).compressed
    except ValueError as exc:
        raise ValueError(f"{field} не является IP-адресом") from exc


def _time(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            finite = isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError(f"{field} содержит недопустимое время")
        try:
            parsed = datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"{field} содержит недопустимое время") from exc
    elif isinstance(value, str):
        try:
            if len(value) <= 30 and re.fullmatch(r"-?\d+(?:\.\d+)?", value):
                parsed = datetime.fromtimestamp(float(value), timezone.utc)
            else:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"{field} содержит недопустимое время") from exc
    else:
        raise ValueError(f"{field} обязателен")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} должен содержать часовое смещение")
    return parsed.astimezone(timezone.utc)


def _field(payload: dict[str, Any], raw: dict[str, Any], *keys: str) -> object:
    found = []
    for key in keys:
        if key in payload and payload[key] is not None:
            found.append(payload[key])
        if key in raw and raw[key] is not None:
            found.append(raw[key])
    if any(value != found[0] for value in found[1:]):
        raise ValueError(f"Противоречивые значения поля {keys[0]}")
    return found[0] if found else None


def _json_digest(value: object) -> str:
    try:
        canonical = json.dumps(value, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Исходное событие должно быть JSON-совместимым") from exc
    return sha256(canonical.encode("utf-8")).hexdigest()


def normalize_alert(
    payload: dict[str, Any], tenant_id: str, *, now: datetime | None = None,
    fingerprint_ttl_seconds: int = DEFAULT_FINGERPRINT_TTL_SECONDS,
    correlation_window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> NormalizedIngest:
    """Normalize without changing the raw source or trusting client grouping IDs."""
    if not isinstance(payload, dict):
        raise ValueError("Алерт должен быть объектом")
    tenant = _nonempty(tenant_id, "tenant_id", 100)
    if tenant is None or (payload.get("tenant_id") is not None and payload["tenant_id"] != tenant):
        raise ValueError("Заказчик алерта не совпадает с проверенным заказчиком")
    if not 1 <= fingerprint_ttl_seconds <= MAX_FINGERPRINT_TTL_SECONDS:
        raise ValueError("Недопустимый TTL отпечатка")
    if not 60 <= correlation_window_seconds <= 3600:
        raise ValueError("Недопустимое окно корреляции")
    raw = payload.get("raw", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("raw должен быть объектом")
    original_raw = deepcopy(raw)
    raw_digest = _json_digest(original_raw)
    received = _time(now or datetime.now(timezone.utc), "ingestion_time")
    event_time = _time(payload.get("event_at"), "event_at")
    event_id = _nonempty(payload.get("source_event_id"), "source_event_id", 256)
    source = _nonempty(payload.get("source"), "source", 50)
    if event_id is None or source is None:
        raise ValueError("source и source_event_id обязательны")
    rule_id = _nonempty(_field(payload, raw, "rule", "rule_id"), "rule_id", 100)
    user = _nonempty(_field(payload, raw, "user"), "user", 256)
    host = _host(_field(payload, raw, "host", "hostname"))
    src_ip = _ip(_field(payload, raw, "src_ip", "source_ip"), "src_ip")
    dest_ip = _ip(_field(payload, raw, "dst_ip", "dest_ip", "destination_ip"), "dest_ip")
    related = _field(payload, raw, "related_event_ids")
    if related is not None:
        if (not isinstance(related, list) or len(related) > 100 or
                any(_nonempty(item, "related_event_id", 256) is None for item in related)):
            raise ValueError("related_event_ids должен быть списком непустых ID")
        related = tuple(_nonempty(item, "related_event_id", 256) for item in related)
    alert = SecurityAlert(
        event_id=event_id, source=source, tenant_id=tenant, event_time=event_time,
        ingestion_time=received, rule_id=rule_id,
        rule_name=_nonempty(_field(payload, raw, "rule_name"), "rule_name", 300),
        severity=_nonempty(_field(payload, raw, "severity"), "severity", 30),
        host=host, user=user, src_ip=src_ip, dest_ip=dest_ip,
        process_name=_nonempty(_field(payload, raw, "process_name"), "process_name", 256),
        process_command_line=_nonempty(_field(payload, raw, "process_command_line", "command_line"),
                                       "process_command_line", 4096),
        event_action=_nonempty(_field(payload, raw, "event_action", "action"), "event_action", 100),
        raw_event_reference=_nonempty(_field(payload, raw, "raw_event_reference"),
                                      "raw_event_reference", 2048),
        related_event_ids=related,
        processing_status=_nonempty(payload.get("processing_status"), "processing_status", 30),
    )
    # Exact event time and raw digest make semantic dedup conservative. The
    # delivery ID is intentionally omitted so a redelivery with a new ID can
    # be recognized, while differing raw evidence never collides by design.
    fingerprint = _json_digest({
        "alert": alert.model_dump(mode="json", exclude={"event_id", "ingestion_time", "processing_status"}),
        "raw_digest": raw_digest,
    })
    window_index = int(event_time.timestamp()) // correlation_window_seconds
    window_start = datetime.fromtimestamp(window_index * correlation_window_seconds, timezone.utc)
    identities = {name: getattr(alert, name) for name in _ENTITY_FIELDS if getattr(alert, name)}
    supplied_key = _nonempty(payload.get("correlation_key"), "correlation_key", 256)
    correlation_key = _json_digest({
        "tenant_id": tenant, "rule_id": rule_id,
        "identity": identities if len(identities) >= 2 and rule_id else {"event_id": event_id},
        "window": window_index, "source_key": supplied_key,
    })
    return NormalizedIngest(
        alert=alert, original_raw=original_raw, fingerprint=fingerprint,
        fingerprint_expires_at=received + timedelta(seconds=fingerprint_ttl_seconds),
        correlation_key=correlation_key, correlation_window_start=window_start,
    )


def compatible_for_correlation(
    left: SecurityAlert, right: SecurityAlert, *,
    max_delta_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> bool:
    """Require rule, tenant, time and two agreeing entities with no conflicts."""
    if not 0 < max_delta_seconds <= 3600:
        raise ValueError("Недопустимый интервал корреляции")
    if (left.tenant_id != right.tenant_id or not left.rule_id or left.rule_id != right.rule_id or
            abs((left.event_time - right.event_time).total_seconds()) > max_delta_seconds):
        return False
    shared = [(getattr(left, key), getattr(right, key)) for key in _ENTITY_FIELDS
              if getattr(left, key) is not None and getattr(right, key) is not None]
    return len(shared) >= 2 and all(a == b for a, b in shared)
