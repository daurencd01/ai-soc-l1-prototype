import json

import pytest

from app.dataset import iter_wazuh_jsonl, normalize_wazuh_record


def sample_record():
    return {
        "_id": "example-id",
        "_source": {
            "id": "1750789915.1194139",
            "timestamp": "06/24/2025 23:31:55",  # Naive Wazuh display time.
            "agent": {"name": "Linux-Server", "ip": "10.0.2.9"},
            "rule": {"id": "2502", "level": 10, "description": "Password failures", "groups": ["authentication_failed"]},
            "data": {"srcip": "192.0.2.1", "dstuser": "admin"},
        },
        "fields": {"timestamp": ["2025-06-24T18:31:55.675Z"]},
        "sort": 1750789915675,
    }


def test_wazuh_mapper_keeps_reference_label_out_of_ingestion_payload():
    wrapper = {
        "id": "example-id", "label": "FP", "rule_priority": "Medium",
        "description": "Password failures", "alert": sample_record(),
    }
    mapped = normalize_wazuh_record(
        wrapper, path="Data/2_Merged/2_alerts_preprocessed_merged_20250712_123030.jsonl"
    )
    payload = mapped["payload"]
    assert payload["source"] == "wazuh_fixture"
    assert payload["source_event_id"] == "example-id"
    assert payload["rule"] == "wazuh:2502"
    assert payload["severity"] == "high"
    assert payload["event_at"] == "2025-06-24T18:31:55.675000+00:00"
    assert payload["original_timezone"] == "UTC"
    assert payload["raw"]["src_ip"] == "192.0.2.1"
    assert payload["raw"]["fixture_provenance"]["original_id"] == "example-id"
    assert "FP" not in json.dumps(payload)
    assert mapped["reference"]["label"] == "FP"


def test_wazuh_stream_bounds_and_rejects_naive_time():
    row = sample_record()
    items = list(iter_wazuh_jsonl([json.dumps(row), json.dumps(row)], path="Data/0_Raw/FP_alerts_raw.jsonl", limit=1))
    assert len(items) == 1
    assert items[0]["reference"]["label"] == "FP"
    assert "FP" not in json.dumps(items[0]["payload"])
    assert items[0]["reference"]["provenance"]["path"] == "Data/0_Raw/FP_alerts_raw.jsonl"
    row.pop("fields")
    row.pop("sort")
    with pytest.raises(ValueError, match="временной зоной"):
        normalize_wazuh_record(row, path="Data/0_Raw/FP_alerts_raw.jsonl")


def test_published_merged_shape_uses_wazuh_level_without_leaking_reference():
    # In the published merged file, preprocessing removes _source.rule.level
    # and puts that Wazuh attribute on the outer row next to evaluation data.
    row = sample_record()
    row["_source"]["rule"].pop("level")
    row["_source"]["data"] = {
        "win": {"eventdata": {
            "user": "SOCLAB\\analyst", "sourceIp": "192.0.2.2",
            "destinationIp": "192.0.2.3", "commandLine": "whoami",
        }}
    }
    wrapper = {
        "id": row["_id"], "description": "Suspicious command", "label": "TP",
        "rule_level": 14, "rule_priority": "Critical", "alert": row,
    }
    mapped = normalize_wazuh_record(
        wrapper, path="Data/2_Merged/2_alerts_preprocessed_merged_20250712_123030.jsonl"
    )
    payload = mapped["payload"]
    assert payload["severity"] == "critical"
    assert payload["raw"]["wazuh_rule_level"] == 14
    assert payload["raw"]["user"] == "SOCLAB\\analyst"
    assert payload["raw"]["src_ip"] == "192.0.2.2"
    assert payload["raw"]["dst_ip"] == "192.0.2.3"
    assert payload["raw"]["wazuh_data"]["win"]["eventdata"]["commandLine"] == "whoami"
    assert mapped["reference"]["label"] == "TP"
    assert mapped["reference"]["priority"] == "Critical"
    assert "label" not in json.dumps(payload).lower()
    assert "critical" not in json.dumps(payload["raw"]["fixture_provenance"]).lower()


def test_published_raw_timestamp_uses_utc_sort_value():
    row = sample_record()
    row["fields"]["timestamp"] = ["24.06.2025 18:31:55"]
    row["sort"] = [1750789915675]
    mapped = normalize_wazuh_record(row, path="Data/0_Raw/FP_alerts_raw.jsonl")
    assert mapped["payload"]["event_at"] == "2025-06-24T18:31:55.675000+00:00"
    assert mapped["reference"]["label"] == "FP"


def test_reference_labels_cannot_change_ingestion_payload():
    row = sample_record()
    wrapper = {"alert": row, "label": "FP", "rule_priority": "Low"}
    path = "Data/2_Merged/2_alerts_preprocessed_merged_20250712_123030.jsonl"
    first = normalize_wazuh_record(wrapper, path=path)
    wrapper.update(label="TP", rule_priority="Critical")
    second = normalize_wazuh_record(wrapper, path=path)
    assert first["payload"] == second["payload"]
    assert first["reference"] != second["reference"]


@pytest.mark.parametrize("sort", [True, float("nan"), 10**30])
def test_timestamp_rejects_invalid_epoch(sort):
    row = sample_record()
    row.pop("fields")
    row["sort"] = [sort]
    with pytest.raises(ValueError, match="временной зоной"):
        normalize_wazuh_record(row, path="Data/0_Raw/FP_alerts_raw.jsonl")
