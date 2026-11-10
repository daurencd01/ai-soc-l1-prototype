from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.case_builder import build_case_plan


NOW = datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)


def investigation(**changes):
    values = dict(id="inv-1", tenant_id="tenant-1", verdict="true_positive", priority="high",
                  summary="Подозрительный вход root", rationale="Отказы, затем успешный вход и новый процесс.",
                  playbook_key="root_ssh", playbook_version="1.0.0", analyzer="deterministic_demo",
                  missing_data=["Проверить владельца хоста"], recommended_actions=["create_case", "review"])
    return SimpleNamespace(**(values | changes))


def alert(**changes):
    values = dict(id="alert-1", tenant_id="tenant-1", investigation_id="inv-1", source="splunk",
                  source_event_id="event-1", title="Root SSH", rule="root_ssh", event_at=NOW,
                  raw={"src_ip": "203.0.113.41", "host": "demo-db-01",
                       "raw_event_reference": "https://splunk.example/app/search/job-1?token=private"})
    return SimpleNamespace(**(values | changes))


def evidence(evidence_id="ev-1", **changes):
    values = dict(id=evidence_id, tenant_id="tenant-1", investigation_id="inv-1", kind="embedded_event",
                  source="splunk", summary="18 отказов входа", event_at=NOW - timedelta(minutes=7),
                  collected_at=NOW + timedelta(minutes=1), data={})
    return SimpleNamespace(**(values | changes))


def decision(**changes):
    values = dict(tenant_id="tenant-1", investigation_id="inv-1", evidence_ids=["ev-1"])
    return SimpleNamespace(**(values | changes))


def test_case_plan_has_grounded_chronology_claims_and_safe_observable():
    observations = [evidence(), evidence("ev-2", summary="Текст password=secret-123 Authorization: Basic c2VjcmV0 в журнале",
                                         event_at=NOW + timedelta(minutes=3),
                                         data={"observable_type": "domain", "observable": "Example.Org"})]
    plan = build_case_plan(investigation(), [alert()], observations, decision=decision(),
                           evidence_for_ids=["ev-1"], evidence_against_ids=["ev-2"],
                           mitre_techniques=["T1078"], mitre_grounded=True)
    assert plan == build_case_plan(investigation(), [alert()], observations, decision=decision(),
                                   evidence_for_ids=["ev-1"], evidence_against_ids=["ev-2"],
                                   mitre_techniques=["T1078"], mitre_grounded=True)
    payload = plan.create_case
    assert payload["severity"] == "high"
    assert "classification:tp" in payload["tags"]
    assert "event-1" in payload["description"]
    assert "https://splunk.example/app/search/job-1" in payload["description"]
    assert "token=private" not in payload["description"]
    assert "secret-123" not in str(plan)
    assert "c2VjcmV0" not in str(plan)
    assert "T1078" in payload["description"]
    assert plan.metadata["interval_start"] == (NOW - timedelta(minutes=7)).isoformat()
    assert plan.metadata["interval_end"] == (NOW + timedelta(minutes=3)).isoformat()
    page = plan.steps[0][1]["content"]
    assert page.index("18 отказов") < page.index("алерт splunk:event-1")
    assert "За исходную гипотезу" in page and "Против исходной гипотезы" in page
    observables = [item for kind, item in plan.steps if kind == "observable"]
    assert {item["data"] for item in observables} == {"203.0.113.41", "example.org"}
    assert [kind for kind, _ in plan.steps].count("task") == 2


def test_case_plan_rejects_cross_tenant_and_unknown_evidence_references():
    with pytest.raises(ValueError, match="другого заказчика"):
        build_case_plan(investigation(), [alert()], [evidence(tenant_id="tenant-2")])
    with pytest.raises(ValueError, match="отсутствующее доказательство"):
        build_case_plan(investigation(), [alert()], [evidence()], evidence_for_ids=["missing"])
    with pytest.raises(ValueError, match="не принадлежит"):
        build_case_plan(investigation(), [alert()], [evidence()], decision=decision(tenant_id="tenant-2"))


def test_case_plan_does_not_publish_untrusted_links_or_unsubstantiated_mitre():
    bad = alert(raw={"src_ip": "not-an-ip", "url": "https://example.com/?token=secret",
                     "raw_event_reference": "javascript:alert(1)", "domain": "-bad.example"})
    plan = build_case_plan(investigation(analyzer="local_model"), [bad],
                           [evidence(data={"observable_type": "shell", "observable": "rm -rf /"})],
                           mitre_techniques=["T1078"])
    assert "javascript:" not in plan.create_case["description"]
    assert "secret" not in str(plan)
    assert "MITRE ATT&CK (предварительно): не назначено" in plan.create_case["description"]
    assert not [item for kind, item in plan.steps if kind == "observable"]
    assert "Вывод модели — рекомендация" in plan.create_case["description"]


def test_case_plan_bounds_large_inputs_and_requires_valid_classification():
    long_alerts = [alert(id=f"alert-{index}", source_event_id=f"event-{index}",
                         event_at=NOW + timedelta(seconds=index), raw={"src_ip": "203.0.113.41"})
                   for index in range(80)]
    many_evidence = [evidence(f"ev-{index}", summary="x" * 5_000,
                              event_at=NOW + timedelta(seconds=index)) for index in range(80)]
    plan = build_case_plan(investigation(), long_alerts, many_evidence)
    assert len(plan.create_case["description"]) <= 10_000
    assert len(plan.steps[0][1]["content"]) <= 20_000
    assert len(plan.metadata["source_alert_ids"]) == 50
    assert [kind for kind, _ in plan.steps].count("observable") == 1
    with pytest.raises(ValueError, match="Классификация"):
        build_case_plan(investigation(verdict="not_a_verdict"), [alert()], [evidence()])
