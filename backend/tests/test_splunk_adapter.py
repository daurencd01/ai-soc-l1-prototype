"""Splunk export contract checks without a live Splunk server."""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from app import adapters


@pytest.fixture
def splunk(monkeypatch):
    monkeypatch.setattr(
        adapters,
        "settings",
        lambda: SimpleNamespace(
            splunk_base_url="https://splunk.example:8089/",
            splunk_token="test-token",
        ),
    )
    return adapters.RealSplunk()


def _mock_client(monkeypatch, handler):
    """Keep the real HTTPX streaming behavior but route requests in process."""
    client_type = httpx.Client
    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        return client_type(*args, transport=transport, **kwargs)

    monkeypatch.setattr(adapters.httpx, "Client", client_factory)


def test_export_posts_supported_form_fields_and_reads_final_result(monkeypatch, splunk):
    def handle(request):
        assert request.method == "POST"
        assert request.url.path == "/services/search/v2/jobs/export"
        assert request.headers["authorization"] == "Bearer test-token"
        assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
        assert parse_qs(request.content.decode()) == {
            "search": ["search index=security | head 2"],
            "output_mode": ["json"],
        }
        return httpx.Response(200, text=json.dumps({"preview": False, "result": {"id": "one"}}) + "\n")

    _mock_client(monkeypatch, handle)
    assert splunk._export("search index=security | head 2", max_rows=2) == [{"id": "one"}]


def test_export_ignores_preview_and_non_error_messages(monkeypatch, splunk):
    frames = [
        {"preview": True, "result": {"id": "not-final"}},
        {"messages": [{"type": "INFO", "text": "Search started"}]},
        {"messages": [{"type": "WARN", "text": "Some fields were unavailable"}]},
        {"preview": False, "result": {"id": "final"}},
    ]
    _mock_client(monkeypatch, lambda request: httpx.Response(
        200, text="\n".join(json.dumps(frame) for frame in frames) + "\n"
    ))

    assert splunk._export("search index=security") == [{"id": "final"}]


@pytest.mark.parametrize("message_type", ["ERROR", "FATAL"])
def test_export_raises_on_splunk_error_messages(monkeypatch, splunk, message_type):
    frame = {"messages": [{"type": message_type, "text": "Search failed"}]}
    _mock_client(monkeypatch, lambda request: httpx.Response(200, text=json.dumps(frame) + "\n"))

    with pytest.raises(adapters.AdapterError):
        splunk._export("search index=security")


def test_export_raises_on_malformed_nonempty_frame(monkeypatch, splunk):
    body = '{"preview": false, "result": {"id": "one"}}\nnot-json\n'
    _mock_client(monkeypatch, lambda request: httpx.Response(200, text=body))

    with pytest.raises(adapters.AdapterError):
        splunk._export("search index=security")


def test_export_stops_reading_when_response_exceeds_byte_limit(monkeypatch, splunk):
    class CountingStream(httpx.SyncByteStream):
        def __init__(self):
            self.delivered = 0
            self.total = 4_000_000

        def __iter__(self):
            while self.delivered < self.total:
                chunk = b"x" * min(32_768, self.total - self.delivered)
                self.delivered += len(chunk)
                yield chunk

        def close(self):
            pass

    source = CountingStream()
    _mock_client(monkeypatch, lambda request: httpx.Response(200, stream=source))

    with pytest.raises(adapters.AdapterError, match="лимит"):
        splunk._export("search index=security")
    assert source.delivered <= 2_100_000, "The body must be rejected before HTTPX buffers all 4 MB"


def _job_response(result_count: int, *, finalized: bool = False) -> dict:
    return {"entry": [{"content": {"dispatchState": "DONE", "isDone": "1",
                                   "isFailed": "0", "isFinalized": "1" if finalized else "0",
                                   "resultCount": str(result_count)}}]}


def test_rule_search_creates_bounded_job_and_pages_with_source_ids(monkeypatch, splunk):
    splunk.page_size = 10
    splunk.templates = {"root_ssh": "search index=auth earliest={earliest} latest={latest}"}
    rows = [{"event_id": f"event-{n}", "kind": "ssh_login_failure", "raw_event_reference": "https://splunk.example/event"}
            for n in range(12)]
    requests = []

    def handle(request):
        requests.append(request)
        if request.method == "POST":
            form = parse_qs(request.content.decode())
            assert request.url.path == "/services/search/jobs"
            assert form["exec_mode"] == ["blocking"] and form["output_mode"] == ["json"]
            assert form["allow_partial_results"] == ["false"]
            assert form["max_count"] == ["21"] and int(form["max_time"][0]) > 0
            assert "index=auth" in form["search"][0]
            assert 'host="host-a"' in form["search"][0]
            assert form["search"][0].endswith("| head 21")
            return httpx.Response(200, json={"sid": "1700.1"})
        if request.url.path == "/services/search/jobs/1700.1":
            return httpx.Response(200, json=_job_response(len(rows)))
        assert request.url.path == "/services/search/v2/jobs/1700.1/results"
        offset = int(request.url.params["offset"])
        count = int(request.url.params["count"])
        return httpx.Response(200, json={"results": rows[offset:offset + count]})

    _mock_client(monkeypatch, handle)
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    found = splunk.related_events_for_rule("root_ssh", "host-a", now - timedelta(minutes=5), now)
    assert len(found) == 12
    assert [row["_soc_splunk_result_offset"] for row in found] == list(range(12))
    assert {row["_soc_splunk_search_sid"] for row in found} == {"1700.1"}
    assert found[0]["_soc_splunk_job_url"].endswith("/services/search/v2/jobs/1700.1/results")
    assert found[0]["raw_event_reference"] == "https://splunk.example/event"
    assert [int(request.url.params["offset"]) for request in requests if request.url.path.endswith("/results")] == [0, 10]


def test_related_search_fails_closed_if_result_set_exceeds_evidence_limit(monkeypatch, splunk):
    def handle(request):
        if request.method == "POST":
            return httpx.Response(200, json={"sid": "1700.2"})
        if request.url.path.endswith("/1700.2"):
            return httpx.Response(200, json=_job_response(21))
        pytest.fail("A truncated result set must not be fetched as complete evidence")

    _mock_client(monkeypatch, handle)
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    with pytest.raises(adapters.AdapterError, match="больше разрешённого лимита"):
        splunk.related_events("host-a", now - timedelta(minutes=5), now)


def test_search_rejects_incomplete_page_even_when_job_reports_done(monkeypatch, splunk):
    def handle(request):
        if request.method == "POST":
            return httpx.Response(200, json={"sid": "1700.5"})
        if request.url.path.endswith("/1700.5"):
            return httpx.Response(200, json=_job_response(2))
        return httpx.Response(200, json={"results": [{"event_id": "only-one"}]})

    _mock_client(monkeypatch, handle)
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    with pytest.raises(adapters.AdapterError, match="Некорректная страница"):
        splunk.related_events("host-a", now - timedelta(minutes=5), now)


def test_search_rejects_finalized_job_and_unsafe_template(monkeypatch, splunk):
    calls = []

    def handle(request):
        calls.append(request.url.path)
        return (httpx.Response(200, json={"sid": "1700.3"}) if request.method == "POST"
                else httpx.Response(200, json=_job_response(0, finalized=True)))

    _mock_client(monkeypatch, handle)
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    with pytest.raises(adapters.AdapterError, match="не завершён полностью"):
        splunk.related_events("host-a", now - timedelta(minutes=5), now)
    assert len(calls) == 2
    for template in (
        "search index=auth earliest={earliest} latest={latest} | outputlookup x",
        "search index=* earliest={earliest} latest={latest}",
        "search index=auth earliest={earliest} latest={latest} {entity}",
    ):
        with pytest.raises(adapters.AdapterError):
            splunk._base_search(template, now - timedelta(minutes=5), now)


def test_search_retries_only_idempotent_reads_with_jitter(monkeypatch, splunk):
    calls = {"post": 0, "status": 0}
    waits = []
    monkeypatch.setattr(adapters, "sleep", waits.append)
    monkeypatch.setattr(adapters, "uniform", lambda start, end: 0.05)

    def handle(request):
        if request.method == "POST":
            calls["post"] += 1
            return httpx.Response(200, json={"sid": "1700.4"})
        if request.url.path.endswith("/1700.4"):
            calls["status"] += 1
            return (httpx.Response(429) if calls["status"] == 1
                    else httpx.Response(200, json=_job_response(0)))
        return httpx.Response(200, json={"results": []})

    _mock_client(monkeypatch, handle)
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    assert splunk.related_events("host-a", now - timedelta(minutes=5), now) == []
    assert calls == {"post": 1, "status": 2}
    assert waits == [pytest.approx(0.25)]


def test_poll_uses_its_bounded_template_and_stable_source_fields(monkeypatch, splunk):
    splunk.templates = {"_poll": "search index=soc_alerts earliest={earliest} latest={latest}"}
    searches = []

    def handle(request):
        if request.method == "POST":
            searches.append(parse_qs(request.content.decode())["search"][0])
            assert parse_qs(request.content.decode())["max_count"] == ["2001"]
            return httpx.Response(200, json={"sid": "1700.6"})
        if request.url.path.endswith("/1700.6"):
            return httpx.Response(200, json=_job_response(1))
        return httpx.Response(200, json={"results": [{"_cd": "1:42", "_time": "2026-11-10T00:00:00Z"}]})

    _mock_client(monkeypatch, handle)
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    rows = splunk.poll(now - timedelta(minutes=5), now)
    assert searches[0].startswith("search index=soc_alerts earliest=")
    assert searches[0].endswith("| head 2001")
    assert rows[0]["_cd"] == "1:42"
    assert rows[0]["_soc_splunk_search_sid"] == "1700.6"


def test_entity_quoting_and_window_fail_closed(splunk):
    assert adapters._spl_value('host"*') == '"host\\"\\*"'
    with pytest.raises(adapters.AdapterError):
        adapters._spl_value("host\n| delete")
    with pytest.raises(adapters.AdapterError):
        adapters._spl_value("host\u202e")
    with pytest.raises(adapters.AdapterError):
        adapters._spl_value("host\u2028| delete")
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    with pytest.raises(adapters.AdapterError, match="интервал"):
        splunk._base_search(splunk.default_template, now - timedelta(days=2), now)


def test_search_stops_when_stream_exceeds_wall_clock_deadline(monkeypatch, splunk):
    clock = [1.0]
    monkeypatch.setattr(adapters, "monotonic", lambda: clock[0])

    class LateStream(httpx.SyncByteStream):
        def __iter__(self):
            clock[0] = 3.0
            yield b'{"results": []}'

        def close(self):
            pass

    _mock_client(monkeypatch, lambda request: httpx.Response(200, stream=LateStream()))
    with httpx.Client() as client:
        with pytest.raises(adapters.AdapterError, match="время"):
            splunk._request_json(client, "GET", "/services/search/jobs/sid", 2.0)
