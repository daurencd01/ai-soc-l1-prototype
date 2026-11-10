"""Shift handover reports built from persisted facts, without an LLM."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    Action,
    Alert,
    Case,
    DeadLetter,
    EmbeddedEvent,
    IntegrationState,
    Investigation,
    MispNotice,
    Report,
    Shift,
)


TITLE = "ОТЧЁТ — L1 ЦОК ТОО „Sauyt.Lab“ (передача смены)"
SECTIONS = (
    "1. Сводная информация.",
    "2. События кибербезопасности.",
    "3. Подтверждённые инциденты по критичности.",
    "4. Эскалации.",
    "5. Оповещение заказчика.",
    "6. НКЦКБ (MISP).",
    "7. Проблемы и сбои средств мониторинга.",
    "8. Открытые задачи.",
    "9. Передача смены.",
)

_FINISHED_INVESTIGATIONS = {"closed", "completed", "resolved", "done", "auto_closed", "escalated"}
_FINISHED_ACTIONS = {"succeeded"}
_FINISHED_DEAD_LETTERS = {"resolved", "closed", "retried"}
_CUSTOMER_NOTIFICATION_KINDS = {"notify_customer", "customer_notification"}


def _utc(value: datetime) -> datetime:
    """SQLite can return naive values even for timezone aware model columns."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _single_line(value: object, limit: int = 180) -> str:
    """Keep untrusted titles and summaries from creating fake report sections."""
    result = " ".join(str(value or "").split())
    return (result[: limit - 1] + "…") if len(result) > limit else result


def _fmt(value: datetime | None, tz: ZoneInfo) -> str:
    if value is None:
        return "не указано"
    return _utc(value).astimezone(tz).strftime("%d.%m.%Y %H:%M %z")


def _rows(db: Session, statement):
    return list(db.scalars(statement).all())


def next_report_version(db: Session, tenant_id: str, shift_id: str) -> int:
    """Return the next per-shift version; caller persists Report in a transaction."""
    latest = db.scalar(
        select(func.max(Report.version)).where(
            Report.tenant_id == tenant_id, Report.shift_id == shift_id
        )
    )
    return (latest or 0) + 1


def build_report(
    db: Session,
    tenant_id: str,
    shift: Shift,
    *,
    version: int | None = None,
    generated_at: datetime | None = None,
) -> dict:
    """Build a preview for one tenant and a half-open shift event-time interval.

    This function does not mutate the session. Persisting and approving a Report,
    including version allocation, belongs to the authenticated API caller.
    """
    if shift.tenant_id != tenant_id:
        raise ValueError("Смена принадлежит другому заказчику")
    start, end = _utc(shift.starts_at), _utc(shift.ends_at)
    if start >= end:
        raise ValueError("Конец смены должен быть позже начала")
    try:
        tz = ZoneInfo(shift.timezone)
    except (KeyError, ValueError) as exc:
        raise ValueError("Неизвестный часовой пояс смены") from exc
    if version is not None and version < 1:
        raise ValueError("Версия отчёта должна быть положительной")
    as_of = _utc(generated_at or datetime.now(timezone.utc))

    alerts = _rows(
        db,
        select(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.event_at >= start, Alert.event_at < end)
        .order_by(Alert.event_at, Alert.id),
    )
    embedded = _rows(
        db,
        select(EmbeddedEvent).where(
            EmbeddedEvent.tenant_id == tenant_id,
            EmbeddedEvent.event_at >= start,
            EmbeddedEvent.event_at < end,
        ),
    )
    investigation_ids = {a.investigation_id for a in alerts if a.investigation_id}
    investigations = (
        _rows(
            db,
            select(Investigation).where(
                Investigation.tenant_id == tenant_id,
                Investigation.id.in_(investigation_ids),
            ),
        )
        if investigation_ids
        else []
    )
    cases = (
        _rows(
            db,
            select(Case).where(Case.tenant_id == tenant_id, Case.investigation_id.in_(investigation_ids)),
        )
        if investigation_ids
        else []
    )
    notifications = (
        _rows(
            db,
            select(Action).where(
                Action.tenant_id == tenant_id,
                Action.investigation_id.in_(investigation_ids),
                Action.kind.in_(_CUSTOMER_NOTIFICATION_KINDS),
            ),
        )
        if investigation_ids
        else []
    )
    misp_notices = _rows(
        db,
        select(MispNotice)
        .where(MispNotice.tenant_id == tenant_id, MispNotice.received_at >= start, MispNotice.received_at < end)
        .order_by(MispNotice.received_at, MispNotice.id),
    )
    integrations = _rows(db, select(IntegrationState).where(IntegrationState.tenant_id == tenant_id))
    open_investigations = _rows(
        db,
        select(Investigation).where(
            Investigation.tenant_id == tenant_id,
            Investigation.status.not_in(_FINISHED_INVESTIGATIONS),
        ),
    )
    open_actions = _rows(
        db,
        select(Action).where(Action.tenant_id == tenant_id, Action.status.not_in(_FINISHED_ACTIONS)),
    )
    dead_letters = _rows(
        db,
        select(DeadLetter).where(
            DeadLetter.tenant_id == tenant_id,
            DeadLetter.status.not_in(_FINISHED_DEAD_LETTERS),
        ),
    )

    incident_list = [item for item in investigations if item.verdict == "true_positive"]
    late_alerts = [a for a in alerts if _utc(a.received_at) >= end]
    alert_rules = Counter(a.rule for a in alerts)
    incident_priorities = Counter(i.priority for i in incident_list)
    misp_received = Counter(n.received_status for n in misp_notices)
    misp_l1 = Counter(n.l1_status for n in misp_notices)
    misp_l2 = Counter(n.l2_status for n in misp_notices)
    confirmed_notifications = [a for a in notifications if a.status == "succeeded"]
    confirmed_cases = [c for c in cases if c.external_id and c.status not in {"failed", "unknown"}]

    counters = {
        # «Всего событий» is deliberately an alert count. Embedded logs and
        # connections are separate units and must never be added to this value.
        "total_events": len(alerts),
        "source_alerts": len(alerts),
        "embedded_logs": len(embedded),
        "connections": None,  # No normalized connection entity exists.
        "investigations": len(investigations),
        "confirmed_incidents": len(incident_list),
        "incidents_by_priority": dict(incident_priorities),
        "late_alerts": len(late_alerts),
        "case_records": len(cases),
        "confirmed_escalations": len(confirmed_cases),
        "customer_notifications_confirmed": len(confirmed_notifications) if notifications else None,
        "misp_notices": len(misp_notices),
        "misp_received_statuses": dict(misp_received),
        "misp_l1_statuses": dict(misp_l1),
        "misp_l2_statuses": dict(misp_l2),
        "open_investigations": len(open_investigations),
        "open_actions": len(open_actions),
        "open_dead_letters": len(dead_letters),
    }

    lines = [TITLE]
    lines.append(f"Период: [{_fmt(start, tz)}, {_fmt(end, tz)}) — {shift.timezone}.")
    lines.append(f"Срез данных: {_fmt(as_of, tz)}.")
    if version is not None:
        lines.append(f"Версия: {version}.")

    lines.extend(("", SECTIONS[0]))
    lines.append(
        "Всего событий: "
        f"{len(alerts)}. Определение: уникальные исходные алерты с временем события "
        "в интервале смены; вложенные логи, соединения и инциденты в эту величину не входят."
    )
    lines.append(f"Вложенных логов с временем события в интервале: {len(embedded)}.")
    lines.append("Соединения: нет нормализованного счётчика; количество неизвестно.")
    lines.append(f"Расследований по этим алертам: {len(investigations)}.")
    lines.append(f"Поздно поступивших алертов (после окончания смены): {len(late_alerts)}.")
    lines.append("Полнота источников определяется отдельно по состоянию интеграций; отсутствие алертов не подтверждает исправность мониторинга.")

    lines.extend(("", SECTIONS[1]))
    if alerts:
        for rule, count in sorted(alert_rules.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"• {_single_line(rule)}: {count} алерт(ов).")
        lines.append("Исходные алерты сохранены отдельно от вложенных логов и связаны с расследованиями.")
    else:
        lines.append("В БД нет исходных алертов с временем события в интервале; полнота поступления данных не установлена этим фактом.")

    lines.extend(("", SECTIONS[2]))
    if incident_list:
        for priority, count in sorted(incident_priorities.items(), key=lambda item: ("critical high medium low".split().index(item[0]) if item[0] in {"critical", "high", "medium", "low"} else 4, item[0])):
            lines.append(f"• Критичность {_single_line(priority)}: {count} подтверждённый(ых) инцидент(ов).")
        for item in sorted(incident_list, key=lambda inv: inv.id):
            lines.append(f"  Расследование {item.id}: {_single_line(item.summary or item.playbook_key)}.")
    else:
        lines.append("В связанных расследованиях нет вердикта true_positive; это не утверждение об отсутствии инцидентов вне доступных данных.")

    lines.extend(("", SECTIONS[3]))
    if cases:
        for case in sorted(cases, key=lambda c: (c.created_at, c.id)):
            external = f", внешний ID {case.external_id}" if case.external_id else ""
            lines.append(f"• Кейс {case.id}: статус {_single_line(case.status)}{external}; {_single_line(case.title)}.")
        lines.append(f"Подтверждено внешним ID: {len(confirmed_cases)} из {len(cases)} записей о кейсах.")
    else:
        lines.append("Записей о кейсах для расследований этой смены в БД нет; факт эскалации не подтверждён.")

    lines.extend(("", SECTIONS[4]))
    if notifications:
        for action in sorted(notifications, key=lambda a: a.id):
            lines.append(f"• Действие {action.id}: статус {_single_line(action.status)}, расследование {action.investigation_id}.")
        lines.append(f"Подтверждённых выполненных уведомлений: {len(confirmed_notifications)}.")
    else:
        lines.append("Подтверждённых записей об оповещении заказчика нет; факт оповещения неизвестен.")

    lines.extend(("", SECTIONS[5]))
    if misp_notices:
        lines.append(f"Получено записей MISP за период: {len(misp_notices)}.")
        for notice in misp_notices:
            lines.append(
                f"• {_single_line(notice.title)} ({_single_line(notice.external_id)}): "
                f"получение {_single_line(notice.received_status)}; "
                f"обработка L1 {_single_line(notice.l1_status)}; "
                f"передача L2 {_single_line(notice.l2_status)}."
            )
    else:
        lines.append("В БД нет сообщений MISP, полученных за период; доступность MISP указана в разделе 7.")

    lines.extend(("", SECTIONS[6]))
    by_name = {entry.name.lower(): entry for entry in integrations}
    for name in sorted(set(by_name) | {"splunk", "thehive", "misp"}):
        state = by_name.get(name)
        if state is None:
            lines.append(f"• {name}: состояние неизвестно, проверка не зарегистрирована.")
            continue
        lines.append(
            f"• {name}: текущий статус {_single_line(state.status)}; "
            f"проверка {_fmt(state.last_checked_at, tz)}; "
            f"последнее поступление {_fmt(state.last_received_at, tz)}."
        )
    lines.append("Текущий статус интеграций не является исторической оценкой полноты логов за смену.")

    lines.extend(("", SECTIONS[7]))
    if not (open_investigations or open_actions or dead_letters):
        lines.append("На момент формирования открытых задач в БД не найдено.")
    else:
        lines.append(
            f"Открытые расследования: {len(open_investigations)}; "
            f"действия без подтверждённого успеха: {len(open_actions)}; "
            f"задачи в очереди ошибок: {len(dead_letters)}."
        )
        for inv in sorted(open_investigations, key=lambda i: i.id):
            overdue = " (срок истёк)" if inv.due_at and _utc(inv.due_at) < as_of else ""
            lines.append(f"• Расследование {inv.id}: {_single_line(inv.status)}{overdue}; срок {_fmt(inv.due_at, tz)}.")
        for action in sorted(open_actions, key=lambda a: a.id):
            lines.append(f"• Действие {action.id}: {_single_line(action.kind)}, статус {_single_line(action.status)}.")
        for task in sorted(dead_letters, key=lambda d: d.id):
            lines.append(f"• Очередь ошибок: алерт {task.alert_id}, статус {_single_line(task.status)}.")

    lines.extend(("", SECTIONS[8]))
    lines.append(f"Статус смены: {_single_line(shift.status)}.")
    lines.append(f"Передающий: {_single_line(shift.outgoing_name) if shift.outgoing_name else 'не указан'}.")
    lines.append(f"Принимающий: {_single_line(shift.incoming_name) if shift.incoming_name else 'не указан'}.")
    lines.append("Подтверждение передачи отдельной записью отсутствует в модели; имена и статус смены не подтверждают факт передачи.")
    if late_alerts:
        lines.append("После окончания смены поступили алерты с временем события в её интервале; при утверждении нужен новый вариант отчёта.")

    return {"content": "\n".join(lines) + "\n", "counters": counters}


def export_txt_bytes(content: str) -> bytes:
    return content.encode("utf-8-sig")


def export_docx_bytes(content: str) -> bytes:
    """Export the exact generated content as an editable DOCX."""
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor

    document = Document()
    section = document.sections[0]
    section.top_margin = section.bottom_margin = Inches(0.75)
    section.left_margin = section.right_margin = Inches(0.8)
    normal = document.styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10)
    normal.font.color.rgb = RGBColor(0, 0, 0)
    normal.paragraph_format.space_after = Pt(4)
    normal.paragraph_format.line_spacing = 1.12
    title = document.styles["Title"]
    title.font.name = "Arial"
    title.font.size = Pt(15)
    title.font.bold = True
    title.font.color.rgb = RGBColor(0, 0, 0)
    title.paragraph_format.space_after = Pt(11)
    title.paragraph_format.keep_with_next = True
    heading = document.styles["Heading 1"]
    heading.font.name = "Arial"
    heading.font.size = Pt(11)
    heading.font.bold = True
    heading.font.color.rgb = RGBColor(0, 0, 0)
    heading.paragraph_format.space_before = Pt(10)
    heading.paragraph_format.space_after = Pt(4)
    heading.paragraph_format.keep_with_next = True
    for number, line in enumerate(content.splitlines()):
        if number == 0:
            document.add_heading(line, 0)
        elif line in SECTIONS:
            document.add_heading(line, level=1)
        elif line:
            paragraph = document.add_paragraph(line)
            if line.startswith("• "):
                paragraph.paragraph_format.left_indent = Pt(13)
                paragraph.paragraph_format.first_line_indent = Pt(-9)
    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()
