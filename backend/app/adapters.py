"""Bounded external clients. All returned data is evidence, never instructions."""
from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
from threading import RLock
from urllib.parse import quote
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
        return []

    def poll(self, earliest: datetime, latest: datetime) -> list[dict]:
        return []

    def close_alert(self, source_event_id: str, idempotency_key: str) -> dict:
        return {"external_id": f"demo-close:{source_event_id}", "demo": True}

    def health(self) -> bool:
        return True


def _spl_value(value: str) -> str:
    """Literal value for a fixed SPL template; refuse control chars and broad wildcards."""
    if len(value) > 128 or any(ord(c) < 32 for c in value):
        raise AdapterError("Недопустимое значение поиска")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('*', '\\*') + '"'


class RealSplunk(SplunkAdapter):
    def __init__(self) -> None:
        self.base = settings().splunk_base_url.rstrip("/")
        self.token = settings().splunk_token
        if not self.base or not self.token:
            raise AdapterError("Splunk не настроен")

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

    def related_events(self, entity: str, earliest: datetime, latest: datetime) -> list[dict]:
        # Operators can change the index in configuration, but never submit raw SPL through the UI/LLM.
        base = settings().splunk_search_template
        if base.count("{earliest}") != 1 or base.count("{latest}") != 1 or "{entity}" in base:
            raise AdapterError("Некорректный шаблон SPL")
        search = base.format(earliest=int(earliest.timestamp()), latest=int(latest.timestamp()))
        search = re.sub(r"\|\s*head\s+\d+\s*$", "", search, flags=re.IGNORECASE)
        search += f" | search (src={_spl_value(entity)} OR user={_spl_value(entity)} OR host={_spl_value(entity)}) | head 200"
        return self._export(search)

    def poll(self, earliest: datetime, latest: datetime) -> list[dict]:
        search = settings().splunk_search_template.format(earliest=int(earliest.timestamp()), latest=int(latest.timestamp()))
        search = re.sub(r"\|\s*head\s+\d+\s*$", "", search, flags=re.IGNORECASE)
        return self._export(search + " | head 2000", max_rows=2000)

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
    def create_case(self, title: str, description: str, key: str) -> str: ...

    @abstractmethod
    def add_evidence(self, case_id: str, evidence: list[dict]) -> None: ...

    @abstractmethod
    def add_task(self, case_id: str, title: str) -> None: ...

    @abstractmethod
    def update_status(self, case_id: str, status: str) -> None: ...

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

    def create_case(self, title: str, description: str, key: str) -> str:
        case_id = f"demo-case:{key}"
        with self._lock:
            self._cases.setdefault(case_id, {"key": key, "title": title, "description": description,
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


_CASE_STEP_RELATION = {"evidence_page": "pages", "observable": "observables", "task": "tasks"}


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
        with httpx.Client(timeout=httpx.Timeout(15, connect=5), verify=True) as client:
            with client.stream(method, f"{self.base}{path}", json=body,
                               headers={"Authorization": f"Bearer {self.key}", "Accept": "application/json"}) as response:
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

    def create_case(self, title: str, description: str, key: str) -> str:
        self._verify_version()
        found = self.find_case(key)
        if found:
            return found
        result = self._request("POST", "/api/v1/case", {"title": title, "description": description,
                         "severity": 2, "tags": [f"soc-key:{key}"], "flag": False})
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
        marker_field = "message" if kind == "observable" else "title"
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
        endpoint = {"evidence_page": "page", "observable": "observable", "task": "task"}[kind]
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

    def case_statuses(self) -> list[dict]:
        rows = self._request("POST", "/api/v1/query", {"query": [{"_name": "listCaseStatus"}]})
        if not isinstance(rows, list):
            raise AdapterError("TheHive не вернул список статусов")
        return [{"value": item["value"], "stage": str(item.get("stage") or ""),
                 "hidden": bool(item.get("hidden"))} for item in rows
                if isinstance(item, dict) and isinstance(item.get("value"), str)]

    def case_status(self, case_id: str) -> str | None:
        row = self._request("GET", f"/api/v1/case/{quote(case_id, safe='')}")
        if not isinstance(row, dict):
            raise AdapterError("TheHive не вернул кейс")
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
