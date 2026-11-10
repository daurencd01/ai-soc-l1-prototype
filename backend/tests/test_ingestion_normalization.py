"""Normalized views do not invent fields or merge unrelated tenant events."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from app.ingestion import compatible_for_correlation, normalize_alert


NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def sample() -> dict:
    return {
        "source": "splunk", "source_event_id": "delivery-1", "rule": "root_ssh",
        "event_at": "2026-11-10T17:56:00+06:00", "severity": "high",
        "correlation_key": "client-supplied-group",
        "raw": {"host": " SRV-01.Example.COM. ", "user": " Jose\u0301 ",
                "src_ip": "2001:0DB8:0:0:0:0:0:1", "dst_ip": "192.0.2.7",
                "event_action": "login_failed", "command_line": "whoami"},
    }


def test_normalizes_present_fields_and_preserves_raw_source():
    payload = sample()
    raw_before = deepcopy(payload["raw"])
    result = normalize_alert(payload, "tenant-a", now=NOW, fingerprint_ttl_seconds=3600)
    alert = result.alert
    assert alert.event_time == datetime(2026, 11, 10, 11, 56, tzinfo=timezone.utc)
    assert alert.ingestion_time == NOW
    assert (alert.host, alert.user, alert.src_ip, alert.dest_ip) == (
        "srv-01.example.com", "José", "2001:db8::1", "192.0.2.7")
    assert alert.process_command_line == "whoami"
    assert alert.rule_name is None and alert.raw_event_reference is None
    assert alert.related_event_ids is None and alert.processing_status is None
    assert result.original_raw == raw_before and payload["raw"] == raw_before
    assert result.original_raw is not payload["raw"]
    assert result.fingerprint_expires_at == NOW + timedelta(hours=1)


def test_fingerprint_is_stable_across_delivery_ids_but_scoped_to_tenant_and_content():
    first = sample()
    second = sample()
    second["source_event_id"] = "redelivery-2"
    second["raw"] = dict(reversed(list(second["raw"].items())))
    a = normalize_alert(first, "tenant-a", now=NOW)
    b = normalize_alert(second, "tenant-a", now=NOW + timedelta(seconds=3))
    assert a.fingerprint == b.fingerprint
    assert a.correlation_key == b.correlation_key
    assert a.fingerprint != normalize_alert(second, "tenant-b", now=NOW).fingerprint
    changed = deepcopy(second)
    changed["raw"]["event_action"] = "login_success"
    assert a.fingerprint != normalize_alert(changed, "tenant-a", now=NOW).fingerprint
    changed = deepcopy(second)
    changed["raw"]["new_evidence"] = "different"
    assert a.fingerprint != normalize_alert(changed, "tenant-a", now=NOW).fingerprint


def test_client_correlation_key_never_overrides_rule_entities_or_time_guard():
    first = normalize_alert(sample(), "tenant-a", now=NOW)
    related = sample()
    related["source_event_id"] = "delivery-2"
    related["event_at"] = "2026-11-10T17:58:00+06:00"
    second = normalize_alert(related, "tenant-a", now=NOW)
    assert first.correlation_key == second.correlation_key
    assert compatible_for_correlation(first.alert, second.alert)

    unrelated = deepcopy(related)
    unrelated["raw"]["host"] = "other.example.com"
    third = normalize_alert(unrelated, "tenant-a", now=NOW)
    assert first.correlation_key != third.correlation_key
    assert not compatible_for_correlation(first.alert, third.alert)
    assert not compatible_for_correlation(first.alert, normalize_alert(related, "tenant-b", now=NOW).alert)

    late = deepcopy(related)
    late["event_at"] = "2026-11-10T18:20:00+06:00"
    assert not compatible_for_correlation(first.alert, normalize_alert(late, "tenant-a", now=NOW).alert)


def test_sparse_events_get_distinct_group_keys_even_with_same_client_key():
    first = sample()
    first["raw"] = {"host": "srv-01"}
    second = deepcopy(first)
    second["source_event_id"] = "another-delivery"
    a = normalize_alert(first, "tenant-a", now=NOW)
    b = normalize_alert(second, "tenant-a", now=NOW)
    assert a.correlation_key != b.correlation_key
    assert not compatible_for_correlation(a.alert, b.alert)


def test_numeric_splunk_timestamp_and_missing_optional_fields():
    payload = {"source": "splunk", "source_event_id": "x", "event_at": "1794312000.25", "raw": {}}
    alert = normalize_alert(payload, "tenant-a", now=NOW).alert
    assert alert.event_time == datetime.fromtimestamp(1794312000.25, timezone.utc)
    assert all(getattr(alert, name) is None for name in (
        "rule_id", "rule_name", "severity", "host", "user", "src_ip", "dest_ip", "event_action"))


@pytest.mark.parametrize("mutator", [
    lambda p: p.update(event_at="2026-11-10T12:00:00"),
    lambda p: p["raw"].update(src_ip="999.1.1.1"),
    lambda p: p.update(raw="not an object"),
    lambda p: p.update(raw=[]),
    lambda p: p.update(tenant_id="other-tenant"),
    lambda p: p.update(host="different.example.com"),
    lambda p: p["raw"].update(unserializable=object()),
])
def test_malformed_or_conflicting_source_data_is_rejected(mutator):
    payload = sample()
    mutator(payload)
    with pytest.raises(ValueError):
        normalize_alert(payload, "tenant-a", now=NOW)
