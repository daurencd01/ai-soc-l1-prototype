"""Case UI links require explicit, safe configuration and confirmed writes."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.case_views import case_reference, list_case_views
from app.config import Settings
from app.db import Base
from app.models import Case, CaseWrite, Investigation, Tenant


def _config(mode: str = "CONNECTED", base: str = "https://hive.example.test",
            template: str = "https://hive.example.test/ui/case/{case_id}") -> Settings:
    return Settings(_env_file=None, mode=mode, thehive_base_url=base,
                    thehive_case_url_template=template)


def test_case_reference_requires_confirmed_connected_case_and_approved_template():
    config = _config()
    assert case_reference("id/with?chars#", "confirmed", config) == (
        "https://hive.example.test/ui/case/id%2Fwith%3Fchars%23")
    assert case_reference("id", "unknown", config) is None
    assert case_reference(None, "confirmed", config) is None
    assert case_reference("id", "confirmed", _config(mode="DEMO")) is None
    assert case_reference("id", "confirmed", _config(template="")) is None
    assert case_reference("..", "confirmed", config) is None


def test_case_reference_rejects_external_hosts_unsafe_schemes_and_templates():
    bad_templates = [
        "https://evil.example.test/ui/{case_id}",
        "http://hive.example.test/ui/{case_id}",
        "javascript:alert({case_id})",
        "https://user:pass@hive.example.test/ui/{case_id}",
        "https://hive.example.test:8443/ui/{case_id}",
        "https://hive.example.test/ui/{case_id}?token=x",
        "https://hive.example.test/ui/{case_id}#fragment",
        "https://hive.example.test/ui/{case_id}/{case_id}",
        "https://hive.example.test/ui/{case_id}/{other}",
        "https://hive.example.test/ui/{case_id}\n",
        "https://hive.example.test\\@evil.example.test/ui/{case_id}",
    ]
    for template in bad_templates:
        assert case_reference("id", "confirmed", _config(template=template)) is None
    assert case_reference("id", "confirmed", _config(
        base="http://hive.example.test", template="http://hive.example.test/ui/{case_id}")) is None
    assert case_reference("id", "confirmed", _config(
        base="http://127.0.0.1:9000", template="http://127.0.0.1:9000/ui/{case_id}")) == (
            "http://127.0.0.1:9000/ui/id")


def test_case_list_only_links_confirmed_external_case(monkeypatch):
    monkeypatch.setattr("app.case_views.settings", lambda: _config())
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            tenant = Tenant(name="case-link", deployment_mode="CONNECTED")
            db.add(tenant)
            db.flush()
            inv = Investigation(tenant_id=tenant.id, correlation_key="case-link", playbook_key="generic",
                                playbook_version="1")
            db.add(inv)
            db.flush()
            case = Case(tenant_id=tenant.id, investigation_id=inv.id, external_id="case-123",
                        status="open", title="Linked")
            db.add(case)
            db.flush()
            write = CaseWrite(tenant_id=tenant.id, investigation_id=inv.id, case_id=case.id,
                              sequence=0, kind="create_case", idempotency_key="case-link-write",
                              request_data={}, status="succeeded")
            db.add(write)
            db.commit()
            tenant_id, write_id = tenant.id, write.id
        with Session(engine) as db:
            assert list_case_views(db, tenant_id)[0]["case_reference"] == (
                "https://hive.example.test/ui/case/case-123")
            db.get(CaseWrite, write_id).status = "unknown"
            db.commit()
        with Session(engine) as db:
            assert list_case_views(db, tenant_id)[0]["case_reference"] is None
    finally:
        engine.dispose()
