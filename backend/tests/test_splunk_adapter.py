"""Splunk export contract checks without a live Splunk server."""

import json
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
