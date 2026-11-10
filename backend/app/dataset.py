"""Opt-in Wazuh JSONL fixture mapper for a published, simulated SOC dataset.

Source: https://github.com/c0deing/llm-soc-alert-triage at commit
3b3beaaa859f3997f8a0aa1c8fb482620096046e.
MIT License, Copyright (c) 2025 Matthias Rieger. This module copies no dataset
records. Supply a JSONL file explicitly; it is never downloaded by the app.

The dataset's TP/FP label is reference metadata outside the ingestion payload.
Every record uses a generic Wazuh rule key, so a historical FP cannot grant
an automatic exception or automatic closure.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from math import isfinite
from typing import Any


DATASET_URL = "https://github.com/c0deing/llm-soc-alert-triage"
DATASET_COMMIT = "3b3beaaa859f3997f8a0aa1c8fb482620096046e"
MAX_JSONL_LINE_BYTES = 256_000
MAX_IMPORT_RECORDS = 200


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _first_nonempty(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _event_time(record: dict) -> tuple[str, str]:
    fields = _mapping(record.get("fields"))
    timestamps = fields.get("timestamp")
    if isinstance(timestamps, list):
        candidate = timestamps[0] if timestamps else None
    else:
        candidate = timestamps
    if isinstance(candidate, str):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                original_tz = "UTC" if candidate.endswith("Z") else str(parsed.strftime("%z"))
                return parsed.astimezone(timezone.utc).isoformat(), original_tz
        except ValueError:
            pass
    # Wazuh's _source.timestamp in this dataset is local and has no timezone.
    # The epoch-millisecond sort value is the only safe fallback.
    sort = record.get("sort")
    if isinstance(sort, list):
        sort = sort[0] if sort else None
    if isinstance(sort, (int, float)) and not isinstance(sort, bool) and isfinite(sort) and sort > 0:
        try:
            return datetime.fromtimestamp(sort / 1000, timezone.utc).isoformat(), "UTC"
        except (OverflowError, OSError, ValueError):
            pass
    raise ValueError("В записи Wazuh нет времени с известной временной зоной")


def _rule_level(rule: dict, record: dict) -> int | None:
    # The repository's preprocessing moves Wazuh's rule.level to the outer
    # rule_level field. It remains a technical alert attribute, distinct from
    # the evaluation label and rule_priority fields.
    value = rule.get("level")
    if value is None:
        value = record.get("rule_level")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    if isinstance(value, str) and not value.isdecimal():
        return None
    try:
        level = int(value)
    except (TypeError, ValueError):
        return None
    return level if 0 <= level <= 15 else None


def normalize_wazuh_record(record: dict, *, path: str) -> dict:
    """Return {'payload': normal ingestion data, 'reference': labels/provenance}.

    Supports both raw repository rows and its preprocessed/merged wrapper. The
    caller must submit only ``payload`` to workflow.ingest and may compare a
    human-reviewed outcome against ``reference`` after processing.
    """
    if not isinstance(record, dict):
        raise ValueError("Строка JSONL должна быть объектом")
    if not path.startswith("Data/") or ".." in path.replace("\\", "/").split("/"):
        raise ValueError("Путь набора данных должен быть относительным к Data/")
    original = _mapping(record.get("alert")) if "alert" in record else record
    source = _mapping(original.get("_source"))
    rule = _mapping(source.get("rule"))
    agent = _mapping(source.get("agent"))
    data = _mapping(source.get("data"))
    windows = _mapping(data.get("win"))
    windows_event = _mapping(windows.get("eventdata"))

    source_id = _first_nonempty(original.get("_id"), source.get("id"), record.get("id"))
    if not source_id:
        raise ValueError("В записи Wazuh нет идентификатора")
    rule_id = str(rule.get("id") or "unknown")[:60]
    level_number = _rule_level(rule, record)
    severity = (
        "critical" if level_number is not None and level_number >= 13 else
        "high" if level_number is not None and level_number >= 10 else
        "medium" if level_number is not None and level_number >= 7 else
        "low" if level_number is not None else "unknown"
    )
    event_at, original_timezone = _event_time(original)
    description = _first_nonempty(rule.get("description"), record.get("description")) or "Алерт Wazuh"
    if description == "MISSING":
        description = "Алерт Wazuh"
    provenance = {
        "dataset": DATASET_URL,
        "commit": DATASET_COMMIT,
        "path": path,
        "original_id": source_id,
        "license": "MIT; Copyright (c) 2025 Matthias Rieger",
    }
    # Raw source filenames reveal the TP/FP partition. Keep the exact path only
    # in the comparison envelope; the stable original ID and commit still make
    # the persisted evidence traceable without leaking a reference label.
    evidence_provenance = {key: value for key, value in provenance.items() if key != "path"}
    payload = {
        "source": "wazuh_fixture",
        "source_event_id": source_id[:256],
        "rule": f"wazuh:{rule_id}",  # Deliberately routes to the generic playbook.
        "title": description[:300],
        "severity": severity,
        "event_at": event_at,
        "original_timezone": original_timezone,
        "raw": {
            "host": _first_nonempty(agent.get("name")),
            "src_ip": _first_nonempty(data.get("srcip"), data.get("src_ip"),
                                      windows_event.get("sourceIp"), windows_event.get("ipAddress")),
            "dst_ip": _first_nonempty(data.get("dest_ip"), data.get("dstip"),
                                      windows_event.get("destinationIp")),
            "user": _first_nonempty(data.get("dstuser"), windows_event.get("targetUserName"),
                                    windows_event.get("user"), windows_event.get("subjectUserName")),
            "wazuh_rule_id": rule_id,
            "wazuh_rule_level": level_number,
            "wazuh_groups": rule.get("groups") if isinstance(rule.get("groups"), list) else [],
            "wazuh_data": data,  # Untrusted evidence; commands are never executed.
            "wazuh_source_timestamp": source.get("timestamp"),
            "fixture_provenance": evidence_provenance,
        },
    }
    reference = {
        "label": (
            record.get("label") if record.get("label") in {"TP", "FP"}
            else "TP" if path.startswith("Data/0_Raw/TP_")
            else "FP" if path.startswith("Data/0_Raw/FP_")
            else None
        ),
        "priority": record.get("rule_priority"),
        "provenance": provenance,
    }
    return {"payload": payload, "reference": reference}


def iter_wazuh_jsonl(lines: Iterable[str | bytes], *, path: str, limit: int = MAX_IMPORT_RECORDS) -> Iterator[dict]:
    """Parse a bounded stream of user-supplied fixture records."""
    if not 1 <= limit <= MAX_IMPORT_RECORDS:
        raise ValueError("Недопустимый лимит импорта")
    yielded = 0
    for line_number, line in enumerate(lines, 1):
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        if len(line.encode("utf-8")) > MAX_JSONL_LINE_BYTES:
            raise ValueError(f"Строка {line_number} превышает допустимый размер")
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Неверный JSON в строке {line_number}") from exc
        yield normalize_wazuh_record(record, path=path)
        yielded += 1
        if yielded >= limit:
            break
