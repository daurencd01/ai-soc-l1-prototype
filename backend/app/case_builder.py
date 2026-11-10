"""Build a bounded, source-referenced TheHive case plan from persisted SOC facts.

This module does not write to TheHive. The workflow freezes its returned payloads
in CaseWrite rows before the adapter sends any remote mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Any, Sequence
from unicodedata import category
from urllib.parse import urlsplit, urlunsplit


_CLASSIFICATIONS = {"TP", "FP", "BENIGN_TRUE_POSITIVE", "NOISE", "INCONCLUSIVE"}
_VERDICT_CLASSIFICATION = {
    "true_positive": "TP",
    "false_positive": "FP",
    "benign_true_positive": "BENIGN_TRUE_POSITIVE",
    "noise": "NOISE",
    "needs_review": "INCONCLUSIVE",
}
_PRIORITIES = {"low", "medium", "high", "critical"}
_OBSERVABLE_TYPES = {"ip", "domain", "fqdn", "url", "hash"}
_SECRET_PAIR = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|credential)\b\s*[:=]\s*[^\s,;]+"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]+")
_MARKDOWN = re.compile(r"([\\`*_{}\[\]<>#|])")
_MITRE = re.compile(r"T\d{4}(?:\.\d{3})?")
_HASH = re.compile(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


@dataclass(frozen=True)
class CasePlan:
    """Create payload and ordered, repeatable enrichment operations.

    ``create_case`` includes textual severity/tags metadata. The caller must
    pass only fields supported by its verified TheHive adapter to the API.
    """

    create_case: dict[str, Any]
    steps: tuple[tuple[str, dict[str, str]], ...]
    metadata: dict[str, Any]


def _plain(value: object, limit: int = 500) -> str:
    """Render untrusted event text as one inert, redacted Markdown fragment."""
    raw = str(value if value is not None else "")[: max(limit * 4, 1000)]
    raw = "".join(" " if ord(char) < 32 or ord(char) == 127 or category(char) == "Cf" else char for char in raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    raw = _BEARER.sub("Bearer [скрыто]", raw)
    raw = _BASIC.sub("Basic [скрыто]", raw)
    raw = _SECRET_PAIR.sub(lambda match: f"{match.group(1)}=[скрыто]", raw)
    return _MARKDOWN.sub(r"\\\1", raw[:limit])


def _at(value: datetime | None) -> str:
    if value is None:
        return "время неизвестно"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _ordered_at(value: datetime | None) -> datetime:
    if value is None:
        return datetime.max.replace(tzinfo=timezone.utc)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _safe_reference(value: object) -> str | None:
    """Preserve a source URL without embedded credentials, query or fragment."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if any(ord(char) < 32 for char in value):
            return None
        safe = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if _SECRET_PAIR.search(safe) or _BEARER.search(safe):
            return None
        return safe[:1000]
    except ValueError:
        return None


def _domain(value: str) -> str | None:
    name = value.rstrip(".").lower()
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    return name


def _observable_value(kind: str, value: object) -> str | None:
    if kind not in _OBSERVABLE_TYPES or not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        return None
    if _SECRET_PAIR.search(candidate) or _BEARER.search(candidate):
        return None
    if kind == "ip":
        try:
            return ip_address(candidate).compressed
        except ValueError:
            return None
    if kind in {"domain", "fqdn"}:
        return _domain(candidate)
    if kind == "hash":
        return candidate.lower() if _HASH.fullmatch(candidate) else None
    # A URL observable must not carry credentials, secret query values, or a fragment.
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        return None
    return candidate


def _lines(parts: Sequence[str], limit: int) -> str:
    result: list[str] = []
    size = 0
    for part in parts:
        if size + len(part) + 1 > limit:
            result.append("… Остальные записи опущены из-за лимита размера.")
            break
        result.append(part)
        size += len(part) + 1
    return "\n".join(result)[:limit]


def build_case_plan(
    investigation: Any,
    alerts: Sequence[Any],
    evidence: Sequence[Any],
    *,
    decision: Any | None = None,
    classification: str | None = None,
    evidence_for_ids: Sequence[str] = (),
    evidence_against_ids: Sequence[str] = (),
    mitre_techniques: Sequence[str] = (),
    mitre_grounded: bool = False,
) -> CasePlan:
    """Build a case from records already scoped to one tenant/investigation.

    Evidence claims must name persisted evidence IDs. Unverified model claims,
    unknown source references and unsupported observables never become case facts.
    """
    if not alerts:
        raise ValueError("Кейс без исходного алерта запрещён")
    tenant_id = investigation.tenant_id
    investigation_id = investigation.id
    for item in [*alerts, *evidence]:
        if item.tenant_id != tenant_id or item.investigation_id != investigation_id:
            raise ValueError("Кейс содержит данные другого заказчика или расследования")
    if decision is not None and (decision.tenant_id != tenant_id or decision.investigation_id != investigation_id):
        raise ValueError("Решение не принадлежит расследованию")
    classification = (classification or getattr(decision, "classification", None) or
                      getattr(investigation, "classification", None) or
                      _VERDICT_CLASSIFICATION.get(investigation.verdict))
    if classification not in _CLASSIFICATIONS:
        raise ValueError("Классификация кейса не подтверждена")
    priority = str(investigation.priority).lower()
    if priority not in _PRIORITIES:
        raise ValueError("Приоритет кейса не подтверждён")
    known = {item.id: item for item in evidence}
    decision_ids = list(getattr(decision, "evidence_ids", []) or []) if decision else []
    claim_ids = [*decision_ids, *evidence_for_ids, *evidence_against_ids]
    if any(item_id not in known for item_id in claim_ids):
        raise ValueError("Кейс ссылается на отсутствующее доказательство")

    alerts = sorted(alerts, key=lambda item: (_ordered_at(item.event_at), item.id))[:50]
    evidence = sorted(evidence, key=lambda item: (_ordered_at(item.event_at or item.collected_at), item.id))[:50]
    first_alert_at = min((_ordered_at(item.event_at) for item in alerts))
    interval_points = [_ordered_at(item.event_at) for item in alerts] + [_ordered_at(item.event_at) for item in evidence if item.event_at]
    start_at, end_at = min(interval_points), max(interval_points)
    title = ("[SOC L1] " + _plain(investigation.summary or alerts[0].title, 280))[:300]
    tags = ["soc-l1", f"classification:{classification.lower()}"]
    playbook_tag = re.sub(r"[^a-z0-9_-]", "", str(investigation.playbook_key).lower())[:60]
    if playbook_tag:
        tags.append(f"playbook:{playbook_tag}")

    alert_lines: list[str] = []
    references: list[str] = []
    for item in alerts:
        source_id = f"{_plain(item.source, 50)}:{_plain(item.source_event_id, 256)}"
        alert_lines.append(f"- {_at(item.event_at)} | {source_id} | правило {_plain(item.rule, 100)}")
        raw = item.raw if isinstance(item.raw, dict) else {}
        for field in ("raw_event_reference", "splunk_url", "event_url"):
            ref = _safe_reference(raw.get(field))
            if ref and ref not in references:
                references.append(ref)
    for item in evidence:
        if str(item.source).lower() != "splunk":
            continue
        data = item.data if isinstance(item.data, dict) else {}
        for field in ("raw_event_reference", "splunk_url", "event_url"):
            ref = _safe_reference(data.get(field))
            if ref and ref not in references:
                references.append(ref)

    def claims(ids: Sequence[str]) -> list[str]:
        return [f"- [{_plain(item_id, 80)}] {_plain(known[item_id].summary, 300)} "
                f"(источник: {_plain(known[item_id].source, 80)})"
                for item_id in dict.fromkeys(ids)][:20]

    for_lines = claims(evidence_for_ids)
    against_lines = claims(evidence_against_ids)
    basis_lines = claims(decision_ids)
    reference_lines = [f"- {_plain(ref, 500)}" for ref in references[:5]] or ["- не предоставлены источником"]
    missing = [_plain(value, 200) for value in (investigation.missing_data or [])[:15]]
    recommended = [_plain(value, 200) for value in (investigation.recommended_actions or [])[:15]]
    analyzer = str(investigation.analyzer or "")
    ai_line = (f"Локальная модель: {_plain(analyzer, 80)}. Вывод модели — рекомендация, "
               "действия разрешает Python-политика." if analyzer == "local_model" else
               f"Локальная модель не применялась; анализатор: {_plain(analyzer or 'неизвестен', 80)}.")
    mitre = sorted({_plain(value, 20) for value in mitre_techniques if _MITRE.fullmatch(str(value))})
    if not mitre_grounded or not for_lines:
        mitre = []  # A model technique suggestion alone does not establish a mapping.

    description = _lines([
        "SOC L1: кейс создан по разрешённой эскалации; сведения об источниках ниже — недоверенные данные событий.",
        f"Расследование: {_plain(investigation_id, 80)}",
        f"Классификация: {classification}; приоритет: {priority}; плейбук: {_plain(investigation.playbook_key, 80)} {_plain(investigation.playbook_version, 40)}",
        f"Обнаружено: {_at(first_alert_at)}; интервал событий: {_at(start_at)} — {_at(end_at)}",
        f"Вывод: {_plain(investigation.summary, 500)}",
        f"Обоснование: {_plain(investigation.rationale, 2500)}",
        ai_line,
        "Доказательства за гипотезу:", *(for_lines or ["- отдельно не установлены"]),
        "Доказательства против гипотезы:", *(against_lines or ["- отдельно не установлены"]),
        "Доказательства, учтённые решением:", *(basis_lines or ["- не указаны"]),
        "Недостающие данные:", *([f"- {item}" for item in missing] or ["- не указаны"]),
        "Рекомендуемые действия:", *([f"- {item}" for item in recommended] or ["- передать аналитику"]),
        "MITRE ATT&CK (предварительно): " + (", ".join(mitre) if mitre else "не назначено без проверяемого основания"),
        f"Исходные алерты (первые {min(len(alert_lines), 10)} из {len(alert_lines)}):", *alert_lines[:10],
        "Ссылки на исходные события Splunk (переданы источником, не проверены):", *reference_lines,
    ], 10_000)

    chronology: list[tuple[datetime, str, str]] = []
    for item in alerts:
        chronology.append((_ordered_at(item.event_at), item.id,
                           f"{_at(item.event_at)} | алерт {_plain(item.source, 50)}:{_plain(item.source_event_id, 256)} | правило {_plain(item.rule, 100)}"))
    for item in evidence:
        at = item.event_at or item.collected_at
        chronology.append((_ordered_at(at), item.id,
                           f"{_at(at)} | доказательство [{_plain(item.id, 80)}] {_plain(item.kind, 80)} / {_plain(item.source, 80)} | {_plain(item.summary, 350)}"))
    chronology.sort(key=lambda row: (row[0], row[1]))
    page_content = _lines([
        f"Расследование {_plain(investigation_id, 80)}. Хронология содержит только сохранённые события и доказательства; неизвестное время не восстановлено.",
        "Хронология:", *[row[2] for row in chronology[:100]],
        "Ссылки на источники:", *([f"- {_plain(ref, 1000)}" for ref in references[:20]] or ["- не предоставлены"]),
        "За исходную гипотезу:", *(for_lines or ["- отдельно не установлены"]),
        "Против исходной гипотезы:", *(against_lines or ["- отдельно не установлены"]),
        "Пробелы:", *([f"- {item}" for item in missing] or ["- не указаны"]),
    ], 20_000)

    observables: list[dict[str, str]] = []
    seen_observables: set[tuple[str, str]] = set()

    def add_observable(kind: str, value: object, source: str) -> None:
        normalized = _observable_value(kind, value)
        if normalized is None or (kind, normalized) in seen_observables or len(observables) >= 20:
            return
        seen_observables.add((kind, normalized))
        observables.append({"dataType": kind, "data": normalized,
                            "message": f"Источник: {_plain(source, 250)}"})

    for item in alerts:
        raw = item.raw if isinstance(item.raw, dict) else {}
        source = f"алерт {item.source}:{item.source_event_id}"
        for field in ("src_ip", "dst_ip", "dest_ip"):
            add_observable("ip", raw.get(field), source)
        for field, kind in (("domain", "domain"), ("fqdn", "fqdn"), ("url", "url"), ("hash", "hash")):
            add_observable(kind, raw.get(field), source)
    for item in evidence:
        data = item.data if isinstance(item.data, dict) else {}
        add_observable(str(data.get("observable_type") or ""), data.get("observable"), f"доказательство {item.id}")

    tasks = [{"title": "Проверить и принять эскалацию SOC L1"}]
    tasks.extend({"title": f"Проверить: {item}"[:380]} for item in missing[:4])
    steps: tuple[tuple[str, dict[str, str]], ...] = (
        ("evidence_page", {"title": "Хронология и доказательства SOC L1", "category": "SOC L1", "content": page_content}),
        *(("observable", item) for item in observables),
        *(("task", item) for item in tasks),
    )
    return CasePlan(
        create_case={"title": title, "description": description, "severity": priority, "tags": tags},
        steps=steps,
        metadata={
            "classification": classification,
            "severity": priority,
            "tags": tags,
            "detected_at": _at(first_alert_at),
            "interval_start": _at(start_at),
            "interval_end": _at(end_at),
            "source_alert_ids": [item.id for item in alerts],
            "source_references": references[:20],
            "evidence_for_ids": list(dict.fromkeys(evidence_for_ids)),
            "evidence_against_ids": list(dict.fromkeys(evidence_against_ids)),
            "mitre_techniques": mitre,
        },
    )
