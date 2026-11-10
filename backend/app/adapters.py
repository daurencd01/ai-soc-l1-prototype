"""Bounded external clients. All returned data is evidence, never instructions."""
from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime, timedelta
from functools import lru_cache
from hashlib import sha256
from math import isfinite
from random import uniform
from threading import BoundedSemaphore, RLock
from time import monotonic, sleep
from unicodedata import category
from urllib.parse import quote, urlsplit
import httpx
import json
import re
from .config import settings


class AdapterError(RuntimeError):
    pass


class AdapterAmbiguousError(AdapterError):
    """A remote write may have succeeded, but its result cannot be confirmed."""


class SplunkAdapter(ABC):
    @abstractmethod
    def related_events(self, entity: str, earliest: datetime, latest: datetime) -> list[dict]: ...

    @abstractmethod
    def poll(self, earliest: datetime, latest: datetime) -> list[dict]: ...

    @abstractmethod
    def close_alert(self, source_event_id: str, idempotency_key: str) -> dict: ...

    @abstractmethod
    def health(self) -> bool: ...


class DemoSplunk(SplunkAdapter):
    def related_events(self, entity: str, earliest: datetime, latest: datetime) -> list[dict]:
        if entity == "demo-parser-error-01":
            return [{"kind": "ssh_login_failure", "event_id": "demo-auth-parser-01",
                     "result": "denied", "user": "root", "host": entity,
                     "src_ip": "10.10.1.44", "auth_method": "publickey",
                     "_time": (earliest + timedelta(hours=1)).isoformat()}]
        return []

    def poll(self, earliest: datetime, latest: datetime) -> list[dict]:
        return []

    def close_alert(self, source_event_id: str, idempotency_key: str) -> dict:
        return {"external_id": f"demo-close:{source_event_id}", "demo": True}

    def health(self) -> bool:
        return True


def _spl_value(value: str) -> str:
    """Literal value for a fixed SPL template; refuse control chars and broad wildcards."""
    if len(value) > 128 or any(category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in value):
        raise AdapterError("Недопустимое значение поиска")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('*', '\\*') + '"'


_SPLUNK_RULE_FIELDS: dict[str, tuple[str, ...]] = {
    "root_ssh": ("host", "src", "src_ip", "user"),
    "vpn_country": ("peer", "device", "tunnel", "user", "src", "src_ip"),
    "ipsec_failure": ("peer", "device", "tunnel", "src", "src_ip"),
    "brute_force": ("user", "src", "src_ip", "host"),
    "powershell": ("host", "user", "src", "src_ip"),
}
_SPLUNK_RETRYABLE = frozenset({429, 502, 503, 504})


@lru_cache(maxsize=8)
def _splunk_search_slots(limit: int) -> BoundedSemaphore:
    """Limit searches across adapter instances in this worker process."""
    return BoundedSemaphore(limit)


class RealSplunk(SplunkAdapter):
    def __init__(self) -> None:
        configured = settings()
        self.base = configured.splunk_base_url.rstrip("/")
        self.token = configured.splunk_token
        if not self.base or not self.token:
            raise AdapterError("Splunk не настроен")
        parsed = urlsplit(self.base)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise AdapterError("Некорректный адрес Splunk")
        self.search_timeout = int(getattr(configured, "splunk_search_timeout_seconds", 30))
        self.max_concurrent = int(getattr(configured, "splunk_max_concurrent_searches", 2))
        self.page_size = int(getattr(configured, "splunk_page_size", 100))
        self.max_window = int(getattr(configured, "splunk_max_window_seconds", 86400))
        if (not 5 <= self.search_timeout <= 120 or not 1 <= self.max_concurrent <= 8
                or not 10 <= self.page_size <= 500 or not 3600 <= self.max_window <= 604800):
            raise AdapterError("Некорректные лимиты поиска Splunk")
        try:
            templates = json.loads(getattr(configured, "splunk_rule_templates_json", "{}"))
        except (TypeError, ValueError) as exc:
            raise AdapterError("Некорректные шаблоны поиска Splunk") from exc
        if (not isinstance(templates, dict) or any(
                key not in {*_SPLUNK_RULE_FIELDS, "_poll"} or not isinstance(value, str)
                for key, value in templates.items())):
            raise AdapterError("Некорректные шаблоны поиска Splunk")
        self.templates = templates
        self.default_template = getattr(configured, "splunk_search_template",
                                        "search index=main earliest={earliest} latest={latest}")

    def _export(self, search: str, max_rows: int = 200) -> list[dict]:
        max_bytes = 10_000_000 if max_rows > 200 else 2_000_000
        rows = []
        pending = b""

        def consume(line: bytes) -> None:
            if not line.strip():
                return
            try:
                item = json.loads(line)
            except (UnicodeDecodeError, ValueError) as exc:
                raise AdapterError("Некорректный ответ Splunk") from exc
            if not isinstance(item, dict):
                raise AdapterError("Некорректный ответ Splunk")
            messages = item.get("messages")
            if isinstance(messages, list):
                if any(isinstance(message, dict) and str(message.get("type", "")).upper() in {"ERROR", "FATAL"}
                       for message in messages):
                    raise AdapterError("Splunk сообщил об ошибке поиска")
            if item.get("preview") is True:
                return
            result = item.get("result")
            if isinstance(result, dict) and len(rows) < max_rows:
                rows.append(result)
            elif isinstance(item.get("results"), list):
                for row in item["results"]:
                    if len(rows) >= max_rows:
                        break
                    if isinstance(row, dict):
                        rows.append(row)

        with httpx.Client(timeout=httpx.Timeout(20, connect=5), verify=True) as client:
            with client.stream("POST", f"{self.base}/services/search/v2/jobs/export",
                               headers={"Authorization": f"Bearer {self.token}"},
                               data={"search": search, "output_mode": "json"}) as response:
                response.raise_for_status()
                received = 0
                for chunk in response.iter_bytes(chunk_size=16_384):
                    received += len(chunk)
                    if received > max_bytes:
                        raise AdapterError("Превышен лимит ответа Splunk")
                    pending += chunk
                    *lines, pending = pending.split(b"\n")
                    for line in lines:
                        consume(line)
                if pending:
                    consume(pending)
        return rows

    def _base_search(self, template: str, earliest: datetime, latest: datetime) -> str:
        """Render only operator-configured index searches with numeric time bounds."""
        if (earliest.tzinfo is None or latest.tzinfo is None or latest <= earliest
                or (latest - earliest).total_seconds() > self.max_window):
            raise AdapterError("Недопустимый интервал поиска Splunk")
        if not isinstance(template, str) or len(template) > 1024 or any(
                category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in template):
            raise AdapterError("Некорректный шаблон SPL")
        if (template.count("{earliest}") != 1 or template.count("{latest}") != 1
                or not re.search(r"\bearliest=\{earliest\}(?=\s|$)", template)
                or not re.search(r"\blatest=\{latest\}(?=\s|$)", template)):
            raise AdapterError("Некорректный шаблон SPL")
        base = re.sub(r"\s*\|\s*head\s+\d+\s*$", "", template, flags=re.IGNORECASE).strip()
        if ("{" in base.replace("{earliest}", "").replace("{latest}", "")
                or "}" in base.replace("{earliest}", "").replace("{latest}", "")
                or any(char in base for char in "|`[];")):
            raise AdapterError("Шаблон SPL содержит неподдерживаемую команду")
        if not re.match(r"^search\s+", base, flags=re.IGNORECASE) or not re.search(
                r"\bindex=[A-Za-z0-9_-]+\b", base):
            raise AdapterError("Шаблон SPL должен ограничивать индекс")
        return base.format(earliest=int(earliest.timestamp()), latest=int(latest.timestamp()))

    def _request_json(self, client: httpx.Client, method: str, path: str, deadline: float,
                      *, data: dict | None = None, params: dict | None = None,
                      max_bytes: int = 2_000_000) -> tuple[dict, int]:
        """Read a bounded response; retry only idempotent GET requests."""
        attempts = 3 if method == "GET" else 1
        for attempt in range(attempts):
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise AdapterError("Превышено время поиска Splunk")
            retry = False
            try:
                with client.stream(method, f"{self.base}{path}",
                                   headers={"Authorization": f"Bearer {self.token}"},
                                   data=data, params=params,
                                   timeout=httpx.Timeout(remaining, connect=min(5, remaining))) as response:
                    if method == "GET" and response.status_code in _SPLUNK_RETRYABLE and attempt + 1 < attempts:
                        retry = True
                    else:
                        response.raise_for_status()
                        chunks = []
                        size = 0
                        for chunk in response.iter_bytes(chunk_size=16_384):
                            if monotonic() >= deadline:
                                raise AdapterError("Превышено время поиска Splunk")
                            size += len(chunk)
                            if size > max_bytes:
                                raise AdapterError("Превышен лимит ответа Splunk")
                            chunks.append(chunk)
                if not retry:
                    try:
                        payload = json.loads(b"".join(chunks))
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise AdapterError("Некорректный JSON Splunk") from exc
                    if not isinstance(payload, dict):
                        raise AdapterError("Некорректный ответ Splunk")
                    messages = payload.get("messages")
                    if isinstance(messages, list) and any(
                            isinstance(item, dict) and str(item.get("type", "")).upper() in {"ERROR", "FATAL"}
                            for item in messages):
                        raise AdapterError("Splunk сообщил об ошибке поиска")
                    return payload, size
            except httpx.HTTPStatusError as exc:
                raise AdapterError(f"Splunk HTTP {exc.response.status_code}") from exc
            except httpx.RequestError as exc:
                if method != "GET" or attempt + 1 == attempts:
                    raise AdapterError("Соединение со Splunk прервалось") from exc
                retry = True
            if retry:
                delay = min(0.2 * (2 ** attempt) + uniform(0, 0.1), max(deadline - monotonic(), 0))
                if delay > 0:
                    sleep(delay)
        raise AdapterError("Splunk не ответил после повторов")

    def _search_job(self, search: str, max_rows: int, *, strict_limit: bool) -> list[dict]:
        """Create one bounded blocking job, verify completion, then page results."""
        if not 1 <= max_rows <= 2000 or len(search) > 4096:
            raise AdapterError("Некорректный лимит поиска Splunk")
        deadline = monotonic() + self.search_timeout
        slots = _splunk_search_slots(self.max_concurrent)
        if not slots.acquire(timeout=self.search_timeout):
            raise AdapterError("Лимит параллельных поисков Splunk")
        try:
            with httpx.Client(verify=True) as client:
                created, _ = self._request_json(client, "POST", "/services/search/jobs", deadline,
                    data={"search": search, "exec_mode": "blocking", "output_mode": "json",
                          "allow_partial_results": "false", "max_time": str(max(1, int(self.search_timeout * 0.7))),
                          "max_count": str(max_rows + 1), "timeout": "600"}, max_bytes=64_000)
                sid = created.get("sid")
                if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,256}", sid):
                    raise AdapterError("Splunk не вернул корректный search id")
                encoded_sid = quote(sid, safe="")
                job_path = f"/services/search/jobs/{encoded_sid}"
                status, _ = self._request_json(client, "GET", job_path, deadline,
                                               params={"output_mode": "json"}, max_bytes=128_000)
                entries = status.get("entry")
                content = entries[0].get("content") if isinstance(entries, list) and len(entries) == 1 \
                    and isinstance(entries[0], dict) else None
                if not isinstance(content, dict):
                    raise AdapterError("Splunk не вернул состояние задания")
                def flag(value: object) -> bool:
                    return value is True or value == 1 or (isinstance(value, str) and value.lower() in {"1", "true"})
                if (content.get("dispatchState") != "DONE" or not flag(content.get("isDone"))
                        or flag(content.get("isFailed")) or flag(content.get("isFinalized"))):
                    raise AdapterError("Поиск Splunk не завершён полностью")
                result_count = content.get("resultCount")
                total = (int(result_count) if isinstance(result_count, str) and result_count.isdecimal()
                         or isinstance(result_count, int) and not isinstance(result_count, bool) else None)
                if total is None or not 0 <= total <= max_rows + 1:
                    raise AdapterError("Splunk не подтвердил полноту результатов")
                if strict_limit and total > max_rows:
                    raise AdapterError("Связанных событий больше разрешённого лимита")
                result_path = f"/services/search/v2/jobs/{encoded_sid}/results"
                rows: list[dict] = []
                total_bytes = 0
                while len(rows) < min(total, max_rows):
                    offset = len(rows)
                    count = min(self.page_size, max_rows - offset, total - offset)
                    page, size = self._request_json(client, "GET", result_path, deadline,
                        params={"output_mode": "json", "count": count, "offset": offset})
                    total_bytes += size
                    if total_bytes > 10_000_000:
                        raise AdapterError("Превышен общий лимит ответа Splunk")
                    results = page.get("results")
                    if not isinstance(results, list) or len(results) != count or any(
                            not isinstance(item, dict) for item in results):
                        raise AdapterError("Некорректная страница результатов Splunk")
                    for index, item in enumerate(results):
                        row = dict(item)
                        row["_soc_splunk_search_sid"] = sid
                        row["_soc_splunk_result_offset"] = offset + index
                        row["_soc_splunk_job_url"] = f"{self.base}{result_path}"
                        rows.append(row)
                return rows
        finally:
            slots.release()

    def related_events_for_rule(self, rule: str | None, entity: str, earliest: datetime,
                                latest: datetime) -> list[dict]:
        """Use a per-rule base search and an allowlisted entity filter."""
        template = self.templates.get(rule, self.default_template) if rule else self.default_template
        base = self._base_search(template, earliest, latest)
        fields = _SPLUNK_RULE_FIELDS.get(rule, ("host", "src", "src_ip", "user"))
        literal = _spl_value(entity)
        terms = " OR ".join(f"{field}={literal}" for field in fields)
        return self._search_job(f"{base} | search ({terms}) | head 21", 20, strict_limit=True)

    def related_events(self, entity: str, earliest: datetime, latest: datetime) -> list[dict]:
        return self.related_events_for_rule(None, entity, earliest, latest)

    def poll(self, earliest: datetime, latest: datetime) -> list[dict]:
        base = self._base_search(self.templates.get("_poll", self.default_template), earliest, latest)
        return self._search_job(f"{base} | head 2001", 2000, strict_limit=False)

    def close_alert(self, source_event_id: str, idempotency_key: str) -> dict:
        # Core Splunk alerts have no generic "close" operation. ES/SOAR need separate adapters.
        raise AdapterError("Закрытие базового алерта Splunk не поддерживается; нужен отдельный адаптер ES/SOAR")

    def health(self) -> bool:
        with httpx.Client(timeout=5, verify=True) as client:
            response = client.get(f"{self.base}/services/server/info", headers={"Authorization": f"Bearer {self.token}"})
            response.raise_for_status()
        return True


class TheHiveAdapter(ABC):
    @abstractmethod
    def create_case(self, title: str, description: str, key: str, *, severity: int = 2,
                    tags: list[str] | None = None, start_date: int | None = None,
                    end_date: int | None = None) -> str: ...

    @abstractmethod
    def add_evidence(self, case_id: str, evidence: list[dict]) -> None: ...

    @abstractmethod
    def add_task(self, case_id: str, title: str) -> None: ...

    @abstractmethod
    def update_status(self, case_id: str, status: str) -> None: ...

    @abstractmethod
    def update_case_fields(self, case_id: str, changes: dict) -> None: ...

    @abstractmethod
    def case_fields(self, case_id: str, names: list[str]) -> dict: ...

    @abstractmethod
    def case_statuses(self) -> list[dict]: ...

    @abstractmethod
    def case_status(self, case_id: str) -> str | None: ...

    @abstractmethod
    def find_case(self, key: str) -> str | None: ...

    @abstractmethod
    def write_case_step(self, case_id: str, kind: str, payload: dict, key: str) -> str: ...

    @abstractmethod
    def find_case_step(self, case_id: str, kind: str, payload: dict, key: str) -> str | None: ...

    @abstractmethod
    def health(self) -> bool: ...


class DemoTheHive(TheHiveAdapter):
    """Process-local TheHive simulator; the SOC database remains the durable record."""

    _cases: dict[str, dict] = {}
    _lock = RLock()

    def create_case(self, title: str, description: str, key: str, *, severity: int = 2,
                    tags: list[str] | None = None, start_date: int | None = None,
                    end_date: int | None = None) -> str:
        case_id = f"demo-case:{key}"
        with self._lock:
            self._cases.setdefault(case_id, {"key": key, "title": title, "description": description,
                                             "severity": severity, "tags": list(tags or []),
                                             "start_date": start_date, "end_date": end_date,
                                             "status": "Open", "steps": {}})
        return case_id

    def add_evidence(self, case_id: str, evidence: list[dict]) -> None:
        content = "\n".join(f"{e.get('id')}: {e.get('summary')}" for e in evidence[:50])
        if content:
            key = sha256((case_id + ":page:" + content).encode()).hexdigest()[:32]
            self.write_case_step(case_id, "evidence_page",
                                 {"title": "Доказательства SOC L1", "category": "SOC L1", "content": content}, key)
        for e in evidence[:20]:
            data = e.get("data") if isinstance(e.get("data"), dict) else {}
            value = data.get("observable")
            if value:
                key = sha256((case_id + ":observable:" + str(e.get("id"))).encode()).hexdigest()[:32]
                self.write_case_step(case_id, "observable", {"dataType": data.get("observable_type", "ip"),
                                     "data": str(value), "message": str(e.get("summary", ""))[:500]}, key)

    def add_task(self, case_id: str, title: str) -> None:
        key = sha256((case_id + ":task:" + title).encode()).hexdigest()[:32]
        self.write_case_step(case_id, "task", {"title": title}, key)

    def update_status(self, case_id: str, status: str) -> None:
        if status not in {row["value"] for row in self.case_statuses()}:
            raise AdapterError("Недоступный статус демонстрационного кейса")
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                # A process restart drops simulator state. The durable local Case row
                # confirms the case identity, but cannot reconstruct external writes.
                raise AdapterError("Демонстрационный кейс не найден после перезапуска симулятора")
            case["status"] = status

    def update_case_fields(self, case_id: str, changes: dict) -> None:
        fields = validate_case_fields(changes)
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise AdapterError("Демонстрационный кейс не найден")
            case.update(fields)

    def case_fields(self, case_id: str, names: list[str]) -> dict:
        _case_field_names(names)
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise AdapterError("Демонстрационный кейс не найден")
            return {name: case.get(name, case.get({"startDate": "start_date",
                                                  "endDate": "end_date"}.get(name, name))) for name in names}

    def case_statuses(self) -> list[dict]:
        return [{"value": "Open", "stage": "New", "hidden": False},
                {"value": "Resolved", "stage": "Closed", "hidden": False}]

    def case_status(self, case_id: str) -> str | None:
        with self._lock:
            case = self._cases.get(case_id)
            return str(case["status"]) if case else None

    def find_case(self, key: str) -> str | None:
        case_id = f"demo-case:{key}"
        with self._lock:
            return case_id if case_id in self._cases else None

    def write_case_step(self, case_id: str, kind: str, payload: dict, key: str) -> str:
        body, _ = _case_step_body(kind, payload, key)
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise AdapterError("Демонстрационный кейс не найден")
            step_id = f"{case_id}:{kind}:{key}"
            existing = case["steps"].get((kind, key))
            if existing and existing["payload"] != body:
                raise AdapterError("Ключ операции TheHive уже использован для других данных")
            case["steps"].setdefault((kind, key), {"id": step_id, "payload": deepcopy(body)})
            return step_id

    def find_case_step(self, case_id: str, kind: str, payload: dict, key: str) -> str | None:
        body, _ = _case_step_body(kind, payload, key)
        with self._lock:
            case = self._cases.get(case_id)
            step = case["steps"].get((kind, key)) if case else None
            if step and step["payload"] != body:
                raise AdapterError("Ключ операции TheHive уже использован для других данных")
            return str(step["id"]) if step else None

    def health(self) -> bool:
        return True


_CASE_STEP_RELATION = {"evidence_page": "pages", "observable": "observables",
                       "task": "tasks", "comment": "comments"}


def _case_field_names(names: list[str]) -> None:
    if (not isinstance(names, list) or not names or len(names) > 6
            or any(not isinstance(name, str) or name not in {"title", "description", "summary", "severity",
                                    "startDate", "endDate"} for name in names)):
        raise AdapterError("Неподдерживаемые поля кейса TheHive")


def validate_case_fields(changes: dict) -> dict:
    """Validate the small set of case fields the SOC may replace safely."""
    limits = {"title": 512, "description": 1_048_576, "summary": 1_048_576}
    if not isinstance(changes, dict) or not changes or set(changes) - (set(limits) | {"severity", "startDate", "endDate"}):
        raise AdapterError("Неподдерживаемые поля кейса TheHive")
    result = {}
    for field, value in changes.items():
        if field in limits:
            if not isinstance(value, str) or not value.strip() or len(value) > limits[field]:
                raise AdapterError("Некорректное текстовое поле кейса TheHive")
        elif field == "severity":
            if isinstance(value, bool) or not isinstance(value, int) or value not in {1, 2, 3, 4}:
                raise AdapterError("Недопустимая критичность кейса TheHive")
        elif isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise AdapterError("Недопустимое время кейса TheHive")
        result[field] = value
    if ("startDate" in result and "endDate" in result
            and result["endDate"] < result["startDate"]):
        raise AdapterError("Недопустимый временной интервал кейса TheHive")
    return result


def _case_step_body(kind: str, payload: dict, key: str) -> tuple[dict, str]:
    """Build a TheHive 5 payload with a stable marker for scoped readback."""
    if kind not in _CASE_STEP_RELATION or not isinstance(payload, dict):
        raise AdapterError("Неподдерживаемая операция записи в кейс")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", key):
        raise AdapterError("Неверный ключ идемпотентности операции TheHive")
    marker = f"soc-step:{key}"
    if kind == "evidence_page":
        content = payload.get("content")
        if not isinstance(content, str) or not content.strip() or len(content) > 100_000:
            raise AdapterError("Некорректное содержимое страницы доказательств")
        title = str(payload.get("title") or "Доказательства SOC L1")[:380]
        return {"title": f"{title} [{marker}]", "category": str(payload.get("category") or "SOC L1")[:100],
                "content": content}, marker
    if kind == "observable":
        data_type = payload.get("dataType")
        data = payload.get("data")
        if data_type not in {"ip", "domain", "url", "hash", "fqdn"} or not isinstance(data, str) or not data or len(data) > 2048:
            raise AdapterError("Неподдерживаемый observable TheHive")
        message = str(payload.get("message") or "")[:350]
        return {"dataType": data_type, "data": data,
                "message": f"{message} [{marker}]"}, marker
    if kind == "comment":
        message = payload.get("message")
        if not isinstance(message, str) or not message.strip() or len(message) > 100_000:
            raise AdapterError("Некорректный комментарий кейса TheHive")
        if payload.get("external", False) is not False:
            raise AdapterError("Публичный комментарий кейса запрещён")
        return {"message": f"{message} [{marker}]", "external": False}, marker
    title = str(payload.get("title") or "").strip()
    if not title:
        raise AdapterError("Задача TheHive требует заголовок")
    return {"title": f"{title[:380]} [{marker}]"}, marker


class RealTheHive(TheHiveAdapter):
    def __init__(self) -> None:
        self.base = settings().thehive_base_url.rstrip("/")
        self.key = settings().thehive_api_key
        self._verified_version: str | None = None
        if not self.base or not self.key:
            raise AdapterError("TheHive не настроен")

    def _request(self, method: str, path: str, body: dict | None = None) -> dict | list:
        # POST /query is read-only. Retry only reads; a mutation with a lost
        # response must be reconciled, never sent blindly a second time.
        read_only = method == "GET" or (method == "POST" and path == "/api/v1/query")
        attempts = 3 if read_only else 1
        with httpx.Client(timeout=httpx.Timeout(15, connect=5), verify=True) as client:
            for attempt in range(attempts):
                try:
                    with client.stream(method, f"{self.base}{path}", json=body,
                                       headers={"Authorization": f"Bearer {self.key}",
                                                "Accept": "application/json"}) as response:
                        response.raise_for_status()
                        chunks = bytearray()
                        for chunk in response.iter_bytes(chunk_size=16_384):
                            if len(chunks) + len(chunk) > 2_000_000:
                                raise AdapterError("Превышен лимит ответа TheHive")
                            chunks.extend(chunk)
                        if not chunks:
                            return {}
                        try:
                            result = json.loads(chunks)
                        except (UnicodeDecodeError, ValueError) as exc:
                            raise AdapterError("Некорректный JSON TheHive") from exc
                        if not isinstance(result, (dict, list)):
                            raise AdapterError("Некорректный ответ TheHive")
                        return result
                except httpx.HTTPStatusError as exc:
                    if (not read_only or attempt + 1 == attempts
                            or exc.response.status_code not in {408, 429, 500, 502, 503, 504}):
                        raise
                    retry_after = exc.response.headers.get("Retry-After", "")
                    try:
                        parsed_delay = float(retry_after)
                        if not isfinite(parsed_delay):
                            raise ValueError("non-finite Retry-After")
                        delay = min(max(parsed_delay, 0.0), 1.0)
                    except ValueError:
                        delay = 0.1 * (2 ** attempt) + uniform(0.0, 0.05)
                except httpx.RequestError:
                    if not read_only or attempt + 1 == attempts:
                        raise
                    delay = 0.1 * (2 ** attempt) + uniform(0.0, 0.05)
                sleep(delay)
        raise AdapterError("Повторный запрос TheHive не завершился")

    def _verify_version(self) -> str:
        # The tested query and case-write contract is TheHive 5.7 only. Do not infer
        # compatibility from the presence of /api/v1/status: newer majors use it too.
        configured = str(getattr(settings(), "thehive_api_version", "") or "").strip()
        if configured != "5.7":
            raise AdapterError("Укажите THEHIVE_API_VERSION=5.7 после проверки версии сервера; другие версии требуют отдельного адаптера")
        if self._verified_version:
            return self._verified_version
        status = self._request("GET", "/api/v1/status")
        version = status.get("version") if isinstance(status, dict) else None
        if not isinstance(version, str) or not re.fullmatch(r"5\.7\.\d+(?:[-+][A-Za-z0-9_.-]+)?", version):
            raise AdapterError("Версия TheHive не подтверждена как совместимая 5.7; записи запрещены")
        self._verified_version = version
        return version

    def create_case(self, title: str, description: str, key: str, *, severity: int = 2,
                    tags: list[str] | None = None, start_date: int | None = None,
                    end_date: int | None = None) -> str:
        self._verify_version()
        if isinstance(severity, bool) or severity not in {1, 2, 3, 4}:
            raise AdapterError("Недопустимая критичность кейса TheHive")
        if tags is not None and (not isinstance(tags, list) or any(
                not isinstance(tag, str) or not tag or len(tag) > 128 for tag in tags)):
            raise AdapterError("Недопустимые теги кейса TheHive")
        if any(value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0)
               for value in (start_date, end_date)) or (start_date and end_date and end_date < start_date):
            raise AdapterError("Недопустимый временной интервал кейса TheHive")
        found = self.find_case(key)
        if found:
            return found
        body = {"title": title, "description": description, "severity": severity,
                "tags": list(dict.fromkeys([f"soc-key:{key}", *(tags or [])])), "flag": False}
        if start_date is not None:
            body["startDate"] = start_date
        if end_date is not None:
            body["endDate"] = end_date
        result = self._request("POST", "/api/v1/case", body)
        case_id = (result.get("_id") or result.get("id")) if isinstance(result, dict) else None
        if not isinstance(case_id, str) or not case_id:
            raise AdapterAmbiguousError("TheHive принял создание кейса, но не подтвердил ID; требуется сверка")
        return case_id

    def find_case(self, key: str) -> str | None:
        # Search by stable tag before retry after an ambiguous network outcome.
        result = self._request("POST", "/api/v1/query", {"query": [{"_name": "listCase"},
            {"_name": "filter", "_in": {"_field": "tags", "_values": [f"soc-key:{key}"]}}]})
        if not isinstance(result, list):
            raise AdapterError("TheHive не вернул список кейсов")
        if len(result) > 1:
            raise AdapterError("TheHive вернул несколько кейсов с одним ключом идемпотентности")
        if result:
            tags = result[0].get("tags") if isinstance(result[0], dict) else None
            if not isinstance(tags, list) or f"soc-key:{key}" not in tags:
                raise AdapterError("TheHive вернул кейс без подтверждённого ключа связи")
            case_id = result[0].get("_id") or result[0].get("id")
            if not case_id:
                raise AdapterError("TheHive не вернул ID найденного кейса")
            return str(case_id)
        return None

    def find_case_step(self, case_id: str, kind: str, payload: dict, key: str) -> str | None:
        self._verify_version()
        expected, marker = _case_step_body(kind, payload, key)
        # The related-object query constrains a matching marker to this exact case.
        rows = self._request("POST", "/api/v1/query", {"query": [
            {"_name": "getCase", "idOrName": case_id},
            {"_name": _CASE_STEP_RELATION[kind]},
        ]})
        if not isinstance(rows, list):
            raise AdapterError("TheHive не вернул список операций кейса")
        marker_field = "message" if kind in {"observable", "comment"} else "title"
        matches = [row for row in rows if isinstance(row, dict)
                   and f"[{marker}]" in str(row.get(marker_field) or "")]
        if len(matches) > 1:
            raise AdapterError("В TheHive найдены дубли одного шага кейса")
        if not matches:
            return None
        row = matches[0]
        for field, value in expected.items():
            if row.get(field) != value:
                raise AdapterError("Маркер шага TheHive найден с отличающимися данными")
        step_id = row.get("_id") or row.get("id")
        if not isinstance(step_id, str) or not step_id:
            raise AdapterError("TheHive не вернул ID найденного шага кейса")
        return step_id

    def write_case_step(self, case_id: str, kind: str, payload: dict, key: str) -> str:
        self._verify_version()
        expected, _ = _case_step_body(kind, payload, key)
        found = self.find_case_step(case_id, kind, payload, key)
        if found:
            return found
        endpoint = {"evidence_page": "page", "observable": "observable", "task": "task",
                    "comment": "comment"}[kind]
        result = self._request("POST", f"/api/v1/case/{quote(case_id, safe='')}/{endpoint}", expected)
        step_id = (result.get("_id") or result.get("id")) if isinstance(result, dict) else None
        if not isinstance(step_id, str) or not step_id:
            raise AdapterAmbiguousError("TheHive принял запись, но не подтвердил ID шага; требуется сверка")
        return step_id

    def add_evidence(self, case_id: str, evidence: list[dict]) -> None:
        text = "\n".join(f"{e.get('id')}: {e.get('summary')}" for e in evidence[:50])
        if text:
            key = sha256((case_id + ":page:" + text).encode()).hexdigest()[:32]
            self.write_case_step(case_id, "evidence_page",
                                 {"title": "Доказательства SOC L1", "category": "SOC L1", "content": text}, key)
        for e in evidence[:20]:
            data = e.get("data") if isinstance(e.get("data"), dict) else {}
            value = data.get("observable")
            if value:
                key = sha256((case_id + ":observable:" + str(e.get("id"))).encode()).hexdigest()[:32]
                self.write_case_step(case_id, "observable", {"dataType": data.get("observable_type", "ip"),
                                     "data": str(value), "message": str(e.get("summary", ""))[:500]}, key)

    def add_task(self, case_id: str, title: str) -> None:
        key = sha256((case_id + ":task:" + title).encode()).hexdigest()[:32]
        self.write_case_step(case_id, "task", {"title": title}, key)

    def update_status(self, case_id: str, status: str) -> None:
        self._verify_version()
        self._request("PATCH", f"/api/v1/case/{quote(case_id, safe='')}", {"status": status})

    def update_case_fields(self, case_id: str, changes: dict) -> None:
        """Replace allowlisted fields and confirm them by reading the same case."""
        self._verify_version()
        fields = validate_case_fields(changes)
        path = f"/api/v1/case/{quote(case_id, safe='')}"
        before = self._request("GET", path)
        if not isinstance(before, dict) or before.get("_id") != case_id:
            raise AdapterError("TheHive не подтвердил ID кейса для изменения")
        pending = {field: value for field, value in fields.items() if before.get(field) != value}
        if not pending:
            return
        self._request("PATCH", path, pending)
        after = self._request("GET", path)
        if (not isinstance(after, dict) or after.get("_id") != case_id
                or any(after.get(field) != value for field, value in fields.items())):
            raise AdapterAmbiguousError("Изменение полей кейса TheHive не подтверждено чтением")

    def case_fields(self, case_id: str, names: list[str]) -> dict:
        _case_field_names(names)
        row = self._request("GET", f"/api/v1/case/{quote(case_id, safe='')}")
        if not isinstance(row, dict) or row.get("_id") != case_id:
            raise AdapterError("TheHive не подтвердил ID кейса")
        return {name: row.get(name) for name in names}

    def case_statuses(self) -> list[dict]:
        rows = self._request("POST", "/api/v1/query", {"query": [{"_name": "listCaseStatus"}]})
        if not isinstance(rows, list):
            raise AdapterError("TheHive не вернул список статусов")
        return [{"value": item["value"], "stage": str(item.get("stage") or ""),
                 "hidden": bool(item.get("hidden"))} for item in rows
                if isinstance(item, dict) and isinstance(item.get("value"), str)]

    def case_status(self, case_id: str) -> str | None:
        row = self._request("GET", f"/api/v1/case/{quote(case_id, safe='')}")
        if not isinstance(row, dict) or row.get("_id") != case_id:
            raise AdapterError("TheHive не подтвердил ID кейса")
        return row.get("status") if isinstance(row.get("status"), str) else None

    def health(self) -> bool:
        self._verify_version()
        return True


class MispAdapter(ABC):
    @abstractmethod
    def search_indicator(self, value: str) -> list[dict]: ...

    @abstractmethod
    def notices(self) -> list[dict]: ...

    @abstractmethod
    def health(self) -> bool: ...


class DemoMisp(MispAdapter):
    def search_indicator(self, value: str) -> list[dict]:
        return []

    def notices(self) -> list[dict]:
        return [{"Event": {"uuid": "demo-misp-notice-001",
                           "info": "DEMO: учебное сообщение об индикаторах"}}]

    def health(self) -> bool:
        return True


class RealMisp(MispAdapter):
    def __init__(self) -> None:
        self.base = settings().misp_base_url.rstrip("/")
        self.key = settings().misp_api_key
        if not self.base or not self.key:
            raise AdapterError("MISP не настроен")

    def _post(self, path: str, body: dict) -> dict:
        with httpx.Client(timeout=httpx.Timeout(15, connect=5), verify=True) as client:
            response = client.post(f"{self.base}{path}", json=body,
                                   headers={"Authorization": self.key, "Accept": "application/json", "Content-Type": "application/json"})
            response.raise_for_status()
            if len(response.content) > 2_000_000:
                raise AdapterError("Превышен лимит ответа MISP")
            return response.json()

    def search_indicator(self, value: str) -> list[dict]:
        if len(value) > 256:
            raise AdapterError("Индикатор слишком длинный")
        response = self._post("/attributes/restSearch", {"value": value, "limit": 20, "to_ids": True, "returnFormat": "json"})
        return response.get("response", {}).get("Attribute", [])[:20]

    def notices(self) -> list[dict]:
        response = self._post("/events/restSearch", {"limit": 20, "metadata": True})
        return response.get("response", [])[:20]

    def health(self) -> bool:
        self._post("/events/restSearch", {"limit": 1, "metadata": True})
        return True


def adapters() -> tuple[SplunkAdapter, TheHiveAdapter, MispAdapter]:
    return splunk_adapter(), thehive_adapter(), misp_adapter()


def splunk_adapter() -> SplunkAdapter:
    return DemoSplunk() if settings().mode.upper() == "DEMO" else RealSplunk()


def thehive_adapter() -> TheHiveAdapter:
    return DemoTheHive() if settings().mode.upper() == "DEMO" else RealTheHive()


def misp_adapter() -> MispAdapter:
    return DemoMisp() if settings().mode.upper() == "DEMO" else RealMisp()
