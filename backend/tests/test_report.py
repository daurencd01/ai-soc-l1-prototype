from datetime import datetime, timezone
from io import BytesIO

from docx import Document
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app.models import (
    Alert,
    Case,
    EmbeddedEvent,
    Investigation,
    MispNotice,
    Report,
    Shift,
    Tenant,
)
from app.report import SECTIONS, TITLE, build_report, export_docx_bytes, export_txt_bytes, next_report_version


def dt(day: int, hour: int) -> datetime:
    return datetime(2026, 10, day, hour, tzinfo=timezone.utc)


def test_shift_report_uses_event_time_deduplicates_incidents_and_isolates_tenants():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Tenant(id="tenant-a", name="A"), Tenant(id="tenant-b", name="B")])
        # Local time in Asia/Qyzylorda: 18 Oct 19:00 to 19 Oct 09:00.
        shift = Shift(
            id="shift-a", tenant_id="tenant-a", starts_at=dt(18, 14), ends_at=dt(19, 4),
            timezone="Asia/Qyzylorda", status="open",
        )
        inv = Investigation(
            id="investigation-a", tenant_id="tenant-a", correlation_key="host-a:root",
            status="completed", verdict="true_positive", priority="high",
            playbook_key="root_ssh", playbook_version="1", summary="Подтверждённый тестовый инцидент",
        )
        db.add_all([shift, inv])
        db.flush()
        db.add_all([
            Alert(
                id="a1", tenant_id="tenant-a", investigation_id=inv.id, source="splunk",
                source_event_id="s1", rule="root_ssh", title="Первый", event_at=dt(18, 15),
                received_at=dt(18, 16),
            ),
            Alert(
                id="a2", tenant_id="tenant-a", investigation_id=inv.id, source="splunk",
                source_event_id="s2", rule="root_ssh", title="Поздний", event_at=dt(19, 3),
                received_at=dt(19, 5),
            ),
            Alert(
                id="end-boundary", tenant_id="tenant-a", source="splunk",
                source_event_id="s3", rule="other", title="После смены", event_at=dt(19, 4),
                received_at=dt(19, 5),
            ),
            Alert(
                id="foreign", tenant_id="tenant-b", source="splunk", source_event_id="s4",
                rule="other", title="Чужой заказчик", event_at=dt(18, 16), received_at=dt(18, 16),
            ),
            EmbeddedEvent(
                id="log-a", tenant_id="tenant-a", alert_id="a1", source_event_id="log-1",
                event_at=dt(18, 15), data={"message": "one log"},
            ),
            EmbeddedEvent(
                id="log-b", tenant_id="tenant-b", alert_id="foreign", source_event_id="log-2",
                event_at=dt(18, 16), data={"message": "foreign log"},
            ),
            Case(
                id="case-a", tenant_id="tenant-a", investigation_id=inv.id,
                external_id="demo-1", status="succeeded", title="Кейс",
            ),
            MispNotice(
                id="notice-a", tenant_id="tenant-a", external_id="misp-1", title="Бюллетень",
                received_status="received", l1_status="processed", l2_status="transferred",
                received_at=dt(18, 18),
            ),
        ])
        db.commit()

        result = build_report(db, "tenant-a", shift, version=1, generated_at=dt(19, 6))
        counts = result["counters"]
        content = result["content"]
        assert counts["total_events"] == 2
        assert counts["embedded_logs"] == 1
        assert counts["connections"] is None
        assert counts["investigations"] == 1
        assert counts["confirmed_incidents"] == 1
        assert counts["late_alerts"] == 1
        assert counts["case_records"] == 1
        assert counts["confirmed_escalations"] == 1
        assert counts["misp_notices"] == 1
        assert counts["misp_l1_statuses"] == {"processed": 1}
        assert counts["misp_l2_statuses"] == {"transferred": 1}
        assert content.startswith(TITLE)
        assert all(content.count(section) == 1 for section in SECTIONS)
        assert "19.10.2026 09:00" in content
        assert "Чужой заказчик" not in content
        assert "состояние неизвестно" in content
        assert "Передающий: не указан" in content
        assert "Версия: 1." in content

        assert next_report_version(db, "tenant-a", shift.id) == 1
        db.add(Report(
            id="report-1", tenant_id="tenant-a", shift_id=shift.id, version=1,
            status="approved", content=content, counters=counts, approved_by="admin",
        ))
        db.commit()
        assert next_report_version(db, "tenant-a", shift.id) == 2


def test_report_rejects_cross_tenant_shift_and_exports_exact_content():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        shift = Shift(
            id="shift-a", tenant_id="tenant-a", starts_at=dt(18, 14), ends_at=dt(19, 4),
            timezone="Asia/Qyzylorda", status="open",
        )
        try:
            build_report(db, "tenant-b", shift)
        except ValueError as exc:
            assert "другому заказчику" in str(exc)
        else:
            raise AssertionError("Cross-tenant shift was accepted")

    text = TITLE + "\n\n" + SECTIONS[0] + "\nПроверка.\n"
    assert export_txt_bytes(text).decode("utf-8-sig") == text
    document = Document(BytesIO(export_docx_bytes(text)))
    assert document.paragraphs[0].text == TITLE
    assert SECTIONS[0] in [p.text for p in document.paragraphs]
    assert "Проверка." in [p.text for p in document.paragraphs]
