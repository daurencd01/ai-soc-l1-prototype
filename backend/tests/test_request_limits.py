"""Ingress limits reject oversized bodies and repeated guesses before parsing."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

import app.request_limits as limits


def request_for(chunks: list[bytes], headers: list[tuple[bytes, bytes]] | None = None):
    received = 0

    async def receive():
        nonlocal received
        part = chunks[received]
        received += 1
        return {"type": "http.request", "body": part, "more_body": received < len(chunks)}

    request = Request({"type": "http", "method": "POST", "path": "/test",
                       "headers": headers or []}, receive)
    return request, lambda: received


def test_streaming_limit_stops_before_reading_remaining_chunks():
    request, count = request_for([b"abcdefg", b"hijklmn", b"unread"])
    with pytest.raises(HTTPException) as error:
        asyncio.run(limits.read_bounded_body(request, limit=10))
    assert error.value.status_code == 413
    assert count() == 2


def test_content_length_rejected_before_stream_and_exact_limit_allowed():
    oversized, count = request_for([b"unread"], [(b"content-length", b"20")])
    with pytest.raises(HTTPException) as error:
        asyncio.run(limits.read_bounded_body(oversized, limit=10))
    assert error.value.status_code == 413 and count() == 0
    allowed, count = request_for([b"12345", b"67890"])
    assert asyncio.run(limits.read_bounded_body(allowed, limit=10)) == b"1234567890"
    assert count() == 2


def test_demo_login_limit_counts_failures_and_isolates_usernames(monkeypatch):
    monkeypatch.setattr(limits, "settings", lambda: SimpleNamespace(mode="DEMO"))
    limiter = limits.LoginRateLimiter()
    for _ in range(limits.LOGIN_ATTEMPTS):
        limiter.assert_allowed("alice")
        limiter.record_failure("alice")
    with pytest.raises(HTTPException) as error:
        limiter.assert_allowed("alice")
    assert error.value.status_code == 429
    assert error.value.headers["Retry-After"] == str(limits.LOGIN_WINDOW_SECONDS)
    limiter.assert_allowed("bob")


def test_connected_login_limit_fails_closed_if_redis_unavailable(monkeypatch):
    import redis

    monkeypatch.setattr(limits, "settings", lambda: SimpleNamespace(
        mode="CONNECTED", redis_url="redis://127.0.0.1:1/0"))
    monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: (_ for _ in ()).throw(
        redis.ConnectionError("offline")))
    with pytest.raises(HTTPException) as error:
        limits.LoginRateLimiter().assert_allowed("alice")
    assert error.value.status_code == 503
