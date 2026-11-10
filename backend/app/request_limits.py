"""Bound request bodies and slow repeated login guesses before password hashing."""

from __future__ import annotations

from hashlib import sha256
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request

from .config import settings


WEBHOOK_BODY_LIMIT = 1_000_000
LOGIN_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 300


async def read_bounded_body(request: Request, limit: int = WEBHOOK_BODY_LIMIT) -> bytes:
    """Stop reading as soon as the size cap is crossed, including chunked bodies."""
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > limit:
                raise HTTPException(413, "Слишком большой запрос")
        except ValueError:
            raise HTTPException(400, "Некорректная длина запроса") from None
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > limit:
            raise HTTPException(413, "Слишком большой запрос")
        content.extend(chunk)
    return bytes(content)


class LoginRateLimiter:
    """Per-user fixed window; Redis is mandatory in CONNECTED, local memory in DEMO."""

    _SCRIPT = """
    local n = redis.call('INCR', KEYS[1])
    if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    return n
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._local: dict[str, tuple[float, int]] = {}

    @staticmethod
    def _key(username: str) -> str:
        # Bound key size and avoid storing the username itself in Redis.
        return "soc:login:" + sha256(username.strip().casefold()[:100].encode()).hexdigest()

    def _local_count(self, key: str, *, failed: bool) -> int:
        now = monotonic()
        with self._lock:
            if len(self._local) >= 10_000:
                self._local = {name: value for name, value in self._local.items() if value[0] > now}
                if len(self._local) >= 10_000 and key not in self._local:
                    raise HTTPException(429, "Слишком много попыток входа",
                                        headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)})
            expires, count = self._local.get(key, (now + LOGIN_WINDOW_SECONDS, 0))
            if expires <= now:
                expires, count = now + LOGIN_WINDOW_SECONDS, 0
            if failed:
                count += 1
                self._local[key] = (expires, count)
            return count

    def _count(self, username: str, *, failed: bool) -> int:
        key = self._key(username)
        if settings().mode.upper() == "CONNECTED":
            import redis

            try:
                client = redis.Redis.from_url(settings().redis_url, socket_connect_timeout=1,
                                              socket_timeout=1)
                attempts = (int(client.eval(self._SCRIPT, 1, key, LOGIN_WINDOW_SECONDS)) if failed
                            else int(client.get(key) or 0))
            except redis.RedisError:
                raise HTTPException(503, "Проверка частоты входа недоступна") from None
        else:
            attempts = self._local_count(key, failed=failed)
        return attempts

    def assert_allowed(self, username: str) -> None:
        if self._count(username, failed=False) >= LOGIN_ATTEMPTS:
            raise HTTPException(429, "Слишком много попыток входа",
                                headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)})

    def record_failure(self, username: str) -> None:
        self._count(username, failed=True)


login_limiter = LoginRateLimiter()
