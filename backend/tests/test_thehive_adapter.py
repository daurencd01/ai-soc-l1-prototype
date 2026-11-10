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
