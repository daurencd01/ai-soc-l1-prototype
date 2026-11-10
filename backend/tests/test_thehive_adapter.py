"""TheHive 5.7 compatibility and single-step write reconciliation."""

from types import SimpleNamespace

import httpx
import pytest

import app.adapters as adapters
from app.adapters import AdapterAmbiguousError, AdapterError, DemoTheHive, RealTheHive


def real_adapter():
    adapter = object.__new__(RealTheHive)
    adapter.base = "https://thehive.example.invalid"
    adapter.key = "test-token"
    adapter._verified_version = None
    return adapter


def test_thehive_write_requires_configured_and_detected_57(monkeypatch):
    adapter = real_adapter()
    calls = []
    monkeypatch.setattr(adapter, "_request", lambda *args: calls.append(args) or {})
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version=""))
    with pytest.raises(AdapterError, match="THEHIVE_API_VERSION"):
        adapter.create_case("Case", "Description", "key-1")
    assert calls == []

    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="6.0"))
    with pytest.raises(AdapterError, match="THEHIVE_API_VERSION"):
        adapter.create_case("Case", "Description", "key-1")
    assert calls == []

    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))
    monkeypatch.setattr(adapter, "_request", lambda *args: calls.append(args) or {"version": "6.0.0"})
    with pytest.raises(AdapterError, match="не подтверждена"):
        adapter.create_case("Case", "Description", "key-1")
    assert [call[1] for call in calls] == ["/api/v1/status"]


def test_thehive_version_checked_before_case_write_and_cached(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))
    calls = []

    def request(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/status":
            return {"version": "5.7.8"}
        if path == "/api/v1/query":
            return []
        return {"_id": "~case-1"}

    monkeypatch.setattr(adapter, "_request", request)
    assert adapter.create_case("Case", "Description", "key-1") == "~case-1"
    assert calls[0][:2] == ("GET", "/api/v1/status")
    assert calls[-1][:2] == ("POST", "/api/v1/case")
    assert adapter.health() is True
    assert sum(path == "/api/v1/status" for _, path, _ in calls) == 1


def test_thehive_create_uses_frozen_case_severity_tags_and_interval(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))
    calls = []

    def request(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/status":
            return {"version": "5.7.3"}
        if path == "/api/v1/query":
            return []
        return {"_id": "~case-2"}

    monkeypatch.setattr(adapter, "_request", request)
    assert adapter.create_case("Case", "Description", "key-2", severity=3,
                               tags=["soc-l1", "classification:tp"],
                               start_date=1_762_000_000_000,
                               end_date=1_762_000_060_000) == "~case-2"
    payload = calls[-1][2]
    assert payload == {"title": "Case", "description": "Description", "severity": 3,
                       "tags": ["soc-key:key-2", "soc-l1", "classification:tp"], "flag": False,
                       "startDate": 1_762_000_000_000, "endDate": 1_762_000_060_000}
    with pytest.raises(AdapterError, match="критичность"):
        adapter.create_case("Case", "Description", "key-3", severity=5)


def test_thehive_case_readback_requires_exact_idempotency_tag(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapter, "_request", lambda *args: [{"_id": "~case-1", "tags": ["other"]}])
    with pytest.raises(AdapterError, match="ключа связи"):
        adapter.find_case("case-key-1")
    monkeypatch.setattr(adapter, "_request", lambda *args: [{"_id": "~case-1", "tags": ["soc-key:case-key-1"]}])
    assert adapter.find_case("case-key-1") == "~case-1"


def test_thehive_step_write_reconciles_exact_case_and_payload(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))
    calls = []
    remote = []

    def request(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/status":
            return {"version": "5.7.3"}
        if path == "/api/v1/query":
            assert body["query"][:2] == [{"_name": "getCase", "idOrName": "~case-1"},
                                          {"_name": "pages"}]
            return remote
        assert path == "/api/v1/case/~case-1/page"
        remote.append({"_id": "~page-1", **body})
        return {"_id": "~page-1"}

    monkeypatch.setattr(adapter, "_request", request)
    payload = {"title": "Evidence", "category": "SOC L1", "content": "one evidence item"}
    assert adapter.write_case_step("~case-1", "evidence_page", payload, "ev-1") == "~page-1"
    assert adapter.write_case_step("~case-1", "evidence_page", payload, "ev-1") == "~page-1"
    assert sum(path == "/api/v1/case/~case-1/page" for _, path, _ in calls) == 1
    assert remote[0]["title"].endswith("[soc-step:ev-1]")
    with pytest.raises(AdapterError, match="отличающимися"):
        adapter.find_case_step("~case-1", "evidence_page",
                               {**payload, "content": "different"}, "ev-1")


def test_thehive_write_without_external_id_is_ambiguous(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))

    def request(method, path, body=None):
        if path == "/api/v1/status":
            return {"version": "5.7.3"}
        return [] if path == "/api/v1/query" else {}

    monkeypatch.setattr(adapter, "_request", request)
    with pytest.raises(AdapterAmbiguousError, match="требуется сверка"):
        adapter.write_case_step("~case-1", "task", {"title": "Investigate"}, "task-1")
    with pytest.raises(AdapterAmbiguousError, match="требуется сверка"):
        adapter.create_case("Title", "Description", "case-key-1")


def test_demo_thehive_tracks_case_steps_and_status():
    adapter = DemoTheHive()
    key = "test-demo-case-steps"
    case_id = f"demo-case:{key}"
    assert adapter.find_case(key) is None
    assert adapter.create_case("Case", "Description", key) == case_id
    payload = {"dataType": "ip", "data": "192.0.2.7", "message": "Observed IP"}
    first = adapter.write_case_step(case_id, "observable", payload, "obs-1")
    assert adapter.find_case_step(case_id, "observable", payload, "obs-1") == first
    assert adapter.write_case_step(case_id, "observable", payload, "obs-1") == first
    with pytest.raises(AdapterError, match="других данных"):
        adapter.write_case_step(case_id, "observable", {**payload, "data": "192.0.2.8"}, "obs-1")
    adapter.update_status(case_id, "Resolved")
    assert adapter.case_status(case_id) == "Resolved"
    assert DemoTheHive().case_status(case_id) == "Resolved"


def test_thehive_response_stream_is_bounded(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 2_000_001))

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(adapters.httpx, "Client", client_factory)
    with pytest.raises(AdapterError, match="лимит ответа"):
        real_adapter()._request("GET", "/api/v1/status")


def test_thehive_comment_is_private_and_reconciles_by_exact_case_and_marker(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))
    calls = []
    remote = []

    def request(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/status":
            return {"version": "5.7.8"}
        if path == "/api/v1/query":
            assert body["query"] == [{"_name": "getCase", "idOrName": "~case-1"},
                                     {"_name": "comments"}]
            return remote
        assert path == "/api/v1/case/~case-1/comment"
        remote.append({"_id": "~comment-1", **body})
        return {"_id": "~comment-1"}

    monkeypatch.setattr(adapter, "_request", request)
    payload = {"message": "Analyst review requested", "external": False}
    assert adapter.write_case_step("~case-1", "comment", payload, "comment-1") == "~comment-1"
    assert adapter.write_case_step("~case-1", "comment", payload, "comment-1") == "~comment-1"
    assert sum(path == "/api/v1/case/~case-1/comment" for _, path, _ in calls) == 1
    assert remote[0]["external"] is False
    with pytest.raises(AdapterError, match="Публичный"):
        adapter.write_case_step("~case-1", "comment",
                                {"message": "public", "external": True}, "comment-2")
    with pytest.raises(AdapterError, match="отличающимися"):
        adapter.find_case_step("~case-1", "comment",
                               {"message": "different", "external": False}, "comment-1")


def test_thehive_case_field_patch_is_allowlisted_and_read_back(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapters, "settings", lambda: SimpleNamespace(thehive_api_version="5.7"))
    case = {"_id": "~case-1", "title": "Old", "severity": 2}
    patches = []

    def request(method, path, body=None):
        if path == "/api/v1/status":
            return {"version": "5.7.8"}
        assert path == "/api/v1/case/~case-1"
        if method == "PATCH":
            patches.append(body)
            case.update(body)
            return {}
        return dict(case)

    monkeypatch.setattr(adapter, "_request", request)
    adapter.update_case_fields("~case-1", {"title": "New", "severity": 3})
    adapter.update_case_fields("~case-1", {"title": "New", "severity": 3})
    assert patches == [{"title": "New", "severity": 3}]
    with pytest.raises(AdapterError, match="Неподдерживаемые"):
        adapter.update_case_fields("~case-1", {"tags": []})
    with pytest.raises(AdapterError, match="Неподдерживаемые"):
        adapter.update_case_fields("~case-1", {"status": "Resolved"})
    with pytest.raises(AdapterError, match="критичность"):
        adapter.update_case_fields("~case-1", {"severity": []})


def test_thehive_case_status_rejects_wrong_case_id(monkeypatch):
    adapter = real_adapter()
    monkeypatch.setattr(adapter, "_request", lambda *_: {"_id": "~another", "status": "Resolved"})
    with pytest.raises(AdapterError, match="ID кейса"):
        adapter.case_status("~case-1")


def test_thehive_retries_reads_but_never_mutations(monkeypatch):
    attempts = {"GET": 0, "PATCH": 0}

    def responder(request):
        attempts[request.method] += 1
        if request.method == "GET" and attempts["GET"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if request.method == "PATCH":
            return httpx.Response(503)
        return httpx.Response(200, json={"version": "5.7.8"})

    original_client = httpx.Client
    transport = httpx.MockTransport(responder)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(adapters.httpx, "Client", client_factory)
    monkeypatch.setattr(adapters, "sleep", lambda _: None)
    assert real_adapter()._request("GET", "/api/v1/status") == {"version": "5.7.8"}
    with pytest.raises(httpx.HTTPStatusError):
        real_adapter()._request("PATCH", "/api/v1/case/~case-1", {"status": "Resolved"})
    assert attempts == {"GET": 2, "PATCH": 1}
