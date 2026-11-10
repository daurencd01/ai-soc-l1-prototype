"""Versioned playbook registry. Add a JSON definition and register a rule function."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import isfinite
from typing import Callable, Literal
from pydantic import BaseModel, Field, field_validator
from .classification import Classification, EvidenceClaim, action_lane, classification_for_lane


class Verdict(BaseModel):
    verdict: str
    classification: Classification | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    priority: str
    summary: str
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_for: list[EvidenceClaim] = Field(default_factory=list)
    evidence_against: list[EvidenceClaim] = Field(default_factory=list)
    missing_data: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    auto_close_eligible: bool = False

    @field_validator("confidence", mode="before")
    @classmethod
    def numeric_confidence(cls, value: object) -> object:
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise ValueError("confidence должен быть числом")
        return value

    def model_post_init(self, __context: object) -> None:
        if self.verdict not in {"true_positive", "false_positive", "needs_review"}:
            raise ValueError("Недопустимый вердикт")
        if self.classification is None:
            self.classification = classification_for_lane(self.verdict)
        if self.verdict != action_lane(self.classification):
            raise ValueError("Категория не соответствует разрешённому маршруту действий")
        if self.priority not in {"low", "medium", "high", "critical"}:
            raise ValueError("Недопустимый приоритет")
        if any(a not in {"create_case", "close_alert", "review", "notify_customer", "disable_account_demo", "isolate_host_demo"} for a in self.recommended_actions):
            raise ValueError("Недопустимое действие")
        if (self.classification != "FP" and self.auto_close_eligible) or any(
            claim.evidence_id not in self.evidence_ids for claim in self.evidence_for + self.evidence_against
        ):
            raise ValueError("Недопустимое основание или допуск к автозакрытию")


@dataclass(frozen=True)
class Playbook:
    key: str
    version: str
    title: str
    required: tuple[str, ...]
    evidence_steps: tuple[str, ...]
    decision_rule: Callable[[dict, list[dict], bool], Verdict]


def _evidence_ids(evidence: list[dict]) -> list[str]:
    return [e["id"] for e in evidence]


def _review(summary: str, reason: str, evidence: list[dict], missing: list[str] | None = None, priority: str = "medium") -> Verdict:
    return Verdict(verdict="needs_review", priority=priority, summary=summary, rationale=reason,
                   evidence_ids=_evidence_ids(evidence), missing_data=missing or [], recommended_actions=["review"])


def _observed_nonincident(classification: Literal["BENIGN_TRUE_POSITIVE", "NOISE"],
                          summary: str, reason: str, evidence: list[dict],
                          support: list[tuple[str, str]]) -> Verdict:
    """Record a grounded observation without mislabelling it FP or closing it."""
    known_ids = set(_evidence_ids(evidence))
    claims = [EvidenceClaim(evidence_id=evidence_id, reason=claim_reason)
              for evidence_id, claim_reason in dict(support).items() if evidence_id in known_ids]
    if not claims:
        return _review(summary, "Нет проверяемых ссылок на подтверждающие доказательства.", evidence)
    return Verdict(verdict="needs_review", classification=classification, priority="low",
                   summary=summary, rationale=reason, evidence_ids=_evidence_ids(evidence),
                   evidence_for=claims,
                   recommended_actions=["review"])


def _approved(evidence: list[dict], required_scope: tuple[str, ...]) -> bool:
    return any(e["kind"] in {"active_exception", "approved_maintenance"}
               and all(e.get("data", {}).get("scope", {}).get(key) for key in required_scope)
               for e in evidence)


def _matching_policy_ids(evidence: list[dict], data: dict,
                         required_scope: tuple[str, ...]) -> list[str]:
    """Use only active policy evidence whose scope matches the current alert."""
    return [item["id"] for item in evidence if
        item.get("kind") in {"active_exception", "approved_maintenance"}
        and isinstance(item.get("data"), dict)
        and isinstance(item["data"].get("scope"), dict)
        and all(data.get(key) and item["data"]["scope"].get(key) == data[key]
                for key in required_scope)
        and isinstance(item.get("id"), str)]


def _scoped_approval(evidence: list[dict], data: dict, required_scope: tuple[str, ...]) -> bool:
    return bool(_matching_policy_ids(evidence, data, required_scope))


def _event_time(value: object) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "", 1).isdigit()):
        try:
            number = float(value)
        except (OverflowError, ValueError):
            return None
        if not isfinite(number):
            return None
        try:
            return datetime.fromtimestamp(number, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _auth_timeline(evidence: list[dict]) -> list[tuple[str, datetime, dict]]:
    """Read dated event records, never the raw-alert summary evidence."""
    result: list[tuple[str, datetime, dict]] = []
    for item in evidence:
        evidence_kind = item.get("kind")
        if evidence_kind not in {"embedded_event", "related_event"}:
            continue
        envelope = item.get("data")
        if not isinstance(envelope, dict):
            continue
        if evidence_kind == "embedded_event":
            event = envelope.get("data")
        else:
            # A Splunk search result may already be a normalized event row.
            event = envelope.get("data") if isinstance(envelope.get("data"), dict) else envelope
        if not isinstance(event, dict):
            continue
        event_at = _event_time(envelope.get("event_at") or envelope.get("_time"))
        if isinstance(event.get("kind"), str) and event_at:
            normalized = dict(event)
            normalized.setdefault("src_ip", event.get("src") or event.get("source_ip"))
            normalized["_evidence_id"] = item.get("id")
            result.append((event["kind"], event_at, normalized))
    return result


def _event_count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 5:
        value = int(value)
    if isinstance(value, int) and 1 <= value <= 10_000:
        return value
    return 1 if value is None else 0


def _known_peer_ids(evidence: list[dict], peer: str, tunnel: str, device: str) -> list[str]:
    return [e["id"] for e in evidence if e["kind"] == "asset" and e.get("data", {}).get("kind") == "vpn_peer"
               and e.get("data", {}).get("value") == peer
               and e.get("data", {}).get("attributes", {}).get("allowed") is True
               and e.get("data", {}).get("attributes", {}).get("tunnel") == tunnel
               and e.get("data", {}).get("attributes", {}).get("device") == device
               and isinstance(e.get("id"), str)]


def _known_peer(evidence: list[dict], peer: str, tunnel: str, device: str) -> bool:
    return bool(_known_peer_ids(evidence, peer, tunnel, device))


def root_ssh(data: dict, ev: list[dict], context_ok: bool) -> Verdict:
    host, source, method = data.get("host"), data.get("src_ip"), data.get("auth_method")
    if not all(isinstance(value, str) and value for value in (host, source, method)):
        return _review("Вход root по SSH: неполные данные", "Нужны хост, источник и метод аутентификации.", ev,
                       [key for key in ("host", "src_ip", "auth_method")
                        if not isinstance(data.get(key), str) or not data[key]])
    timeline = _auth_timeline(ev)
    successes = [at for kind, at, event in timeline
                 if kind == "ssh_login_success" and event.get("user") == "root"
                 and event.get("src_ip") == source and event.get("host") == host
                 and event.get("method") in (None, method)]
    if not successes:
        detector_event_id = data.get("detector_event_id")
        if isinstance(detector_event_id, str) and detector_event_id and data.get("success") is True and context_ok:
            matching = []
            for item in ev:
                event = item.get("data")
                if not isinstance(event, dict):
                    continue
                if item.get("kind") == "embedded_event":
                    event = event.get("data")
                if isinstance(event, dict) and event.get("event_id") == detector_event_id:
                    matching.append((item, event))
            authoritative_denials = [(item, event) for item, event in matching
                if item.get("kind") == "related_event" and item.get("source") == "splunk"
                and event.get("kind") == "ssh_login_failure" and event.get("result") == "denied"
                and event.get("user") == "root" and event.get("host") == host
                and event.get("src_ip") == source and event.get("auth_method") == method]
            if len(authoritative_denials) == 1 and all(
                    event.get("kind") != "ssh_login_success" and event.get("result") != "success"
                    for _, event in matching):
                correction_id = authoritative_denials[0][0].get("id")
                if isinstance(correction_id, str):
                    return Verdict(verdict="false_positive", classification="FP", priority="low",
                                   summary="Ложный детект успешного входа root",
                                   rationale="Повторный поиск Splunk по идентификатору исходного события подтверждает отказ входа; совпадающего успешного входа нет.",
                                   evidence_ids=_evidence_ids(ev),
                                   evidence_against=[EvidenceClaim(evidence_id=correction_id,
                                       reason="Исходное событие с тем же event_id имеет результат denied.")],
                                   recommended_actions=["close_alert"], auto_close_eligible=True)
        return _review("Вход root по SSH: успех не подтверждён", "Нет совпадающего события успешного входа root.", ev)
    for success_at in sorted(successes):
        failures = sum(_event_count(event.get("count")) for kind, at, event in timeline
                       if kind == "ssh_login_failure" and event.get("user") == "root"
                       and event.get("src_ip") == source and (not event.get("host") or event.get("host") == host)
                       and success_at - timedelta(minutes=15) <= at < success_at)
        suspicious_process = any(kind == "process_start" and event.get("host") == host
                                 and event.get("user") == "root"
                                 and event.get("approved_task") is False
                                 and success_at < at <= success_at + timedelta(minutes=15)
                                 for kind, at, event in timeline)
        if failures >= 5 or suspicious_process:
            return Verdict(verdict="true_positive", priority="high", summary="Подозрительный вход root по SSH",
                           rationale="Совпадающие события подтверждают серию отказов перед входом или подозрительный процесс после него.",
                           evidence_ids=_evidence_ids(ev), recommended_actions=["create_case"])
    if len(successes) != 1:
        return _review("Вход root по SSH: несколько успешных входов",
                       "Для автоматического закрытия требуется разобрать каждый вход отдельно.", ev)
    success_at = successes[0]
    if (type(data.get("prior_failures")) is not int or data["prior_failures"] != 0
            or not isinstance(data.get("post_activity"), list) or data["post_activity"]):
        return _review("Вход root по SSH: нет полной истории активности",
                       "Сводка истории неполна или противоречит собранным событиям.", ev,
                       ["Предыдущие ошибки входа", "Последующая активность"])
    relevant_events = [(kind, at, event) for kind, at, event in timeline
                       if kind in {"ssh_login_failure", "process_start"}
                       and event.get("host") in (None, host) and event.get("src_ip") in (None, source)
                       and success_at - timedelta(minutes=15) <= at <= success_at + timedelta(minutes=15)]
    if any(kind == "ssh_login_failure" and event.get("user") == "root" and at < success_at
           or kind == "process_start" and at > success_at and event.get("approved_task") is not True
           for kind, at, event in relevant_events):
        return _review("Вход root по SSH: события требуют проверки",
                       "Обнаружены связанные события, которые не позволяют закрыть алерт автоматически.", ev)
    if _scoped_approval(ev, data, ("host", "src_ip", "auth_method")) and context_ok:
        support = [(event["_evidence_id"], "Вложенное событие подтверждает успешный вход root с указанного источника.")
                   for kind, at, event in timeline if kind == "ssh_login_success" and at == success_at
                   and event.get("user") == "root" and event.get("host") == host
                   and event.get("src_ip") == source and isinstance(event.get("_evidence_id"), str)]
        support += [(item_id, "Действующее согласование совпадает по хосту, источнику и методу входа.")
                    for item_id in _matching_policy_ids(ev, data, ("host", "src_ip", "auth_method"))]
        return _observed_nonincident("BENIGN_TRUE_POSITIVE", "Согласованный вход root по SSH",
                                     "Вход действительно произошёл. Действующее согласование покрывает хост и источник; в собранных событиях нет противоречащих признаков.", ev,
                                     support)
    return _review("Вход root по SSH требует проверки", "Нет действующего согласования и достаточных признаков для окончательного вердикта.", ev,
                   ["Подтвердить владельца доступа и последующую активность"])


def vpn_country(data: dict, ev: list[dict], context_ok: bool) -> Verdict:
    kind = data.get("vpn_type")
    stage = data.get("stage")
    if kind not in {"user", "ipsec"}:
        return _review("VPN: не определён тип соединения", "Нельзя смешивать пользовательский VPN и site-to-site IPsec.", ev, ["vpn_type"])
    if stage != "established":
        return _review("VPN: сессия не подтверждена", "Зафиксирована стадия согласования, а не подтверждённая сессия.", ev, ["Подтверждение установленной сессии"])
    if kind == "ipsec":
        if not all(data.get(k) for k in ("peer", "device", "tunnel")):
            return _review("IPsec: недостаточно сведений о туннеле", "Нужны peer, устройство и туннель.", ev, ["peer", "device", "tunnel"])
        established = [(event["_evidence_id"], "Вложенное событие подтверждает установленную IPsec-сессию указанного peer и туннеля.")
                       for event_kind, _, event in _auth_timeline(ev)
                       if event_kind in {"ipsec_ike_established", "ipsec_child_sa_established"}
                       and event.get("peer") == data["peer"] and event.get("tunnel") == data["tunnel"]
                       and isinstance(event.get("_evidence_id"), str)]
        peer_ids = _known_peer_ids(ev, data["peer"], data["tunnel"], data["device"])
        if peer_ids and established and context_ok:
            support = established + [(item_id, "Инвентарь подтверждает разрешённый peer, устройство и туннель.")
                                     for item_id in peer_ids]
            return _observed_nonincident("BENIGN_TRUE_POSITIVE", "Разрешённый site-to-site туннель",
                                         "Сессия действительно установлена; подтверждены известный peer и разрешённая конфигурация туннеля.", ev,
                                         support)
        return _review("Новый или неподтверждённый IPsec peer", "Разрешённость конфигурации не подтверждена.", ev, ["Проверка peer и туннеля"], "high")
    user = data.get("user")
    if not user or user == data.get("src_ip") or _looks_ip(user):
        return _review("VPN: личность пользователя не установлена", "IP в поле user не подтверждает личность.", ev, ["Проверенная учётная запись"])
    if data.get("unapproved_country") and data.get("identity_verified") and context_ok:
        return Verdict(verdict="true_positive", priority="high", summary="Подтверждённый вход VPN из новой страны",
                       rationale="Установленная пользовательская сессия из несогласованной страны и подтверждённая личность.",
                       evidence_ids=_evidence_ids(ev), recommended_actions=["create_case"])
    return _review("VPN из новой страны требует проверки", "Не хватает подтверждения конфигурации, личности или геолокации.", ev)


def _looks_ip(value: str) -> bool:
    from ipaddress import ip_address
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def ipsec_failure(data: dict, ev: list[dict], context_ok: bool) -> Verdict:
    count = int(data.get("failure_count") or 0)
    if not all(data.get(k) for k in ("peer", "device", "tunnel")) or count < 1:
        return _review("IPsec: неполные сведения о неудачных согласованиях", "Не хватает peer, устройства, туннеля или частоты.", ev)
    if data.get("later_success") and not data.get("peer_allowed"):
        return Verdict(verdict="true_positive", priority="high", summary="Неизвестный IPsec peer после серии ошибок установил туннель",
                       rationale="Последующий успех неизвестного peer требует немедленной проверки.", evidence_ids=_evidence_ids(ev),
                       recommended_actions=["create_case"])
    repeated = [(event["_evidence_id"], "Вложенное событие подтверждает повторные неудачные IPsec-согласования peer.")
                for event_kind, _, event in _auth_timeline(ev) if event_kind == "ipsec_ike_failed"
                and event.get("peer") == data["peer"] and _event_count(event.get("count")) >= 3
                and isinstance(event.get("_evidence_id"), str)]
    peer_ids = _known_peer_ids(ev, data["peer"], data["tunnel"], data["device"])
    policy_ids = _matching_policy_ids(ev, data, ("peer", "device", "tunnel"))
    if (count >= 3 and repeated and peer_ids and policy_ids
            and not data.get("later_success") and context_ok):
        support = repeated + [(item_id, "Инвентарь подтверждает разрешённый peer и туннель.") for item_id in peer_ids]
        support += [(item_id, "Действующее согласование покрывает peer, устройство и туннель.") for item_id in policy_ids]
        return _observed_nonincident("NOISE", "Повторные неудачные IPsec-согласования известного peer",
                                     "Повторные отказы действительно произошли в утверждённое окно; успешная сессия не обнаружена. Подавление требует отдельной политики.", ev,
                                     support)
    return _review("Неудачные IPsec-согласования требуют проверки", "Серия ошибок сама по себе не различает сбой настройки и атаку.", ev,
                   ["Причина ошибки и последующие успешные сессии"])


def brute_force(data: dict, ev: list[dict], context_ok: bool) -> Verdict:
    user = data.get("user")
    if not isinstance(user, str) or not user or not isinstance(data.get("src_ip"), str):
        return _review("Перебор: корреляция не подтверждена", "Нужны пользователь и подтверждённый успешный вход.", ev)
    timeline = _auth_timeline(ev)
    successes = [(at, event.get("src_ip")) for kind, at, event in timeline
                 if kind == "login_success" and event.get("user") == user
                 and event.get("src_ip") == data.get("src_ip")]
    if not successes:
        return _review("Перебор: корреляция не подтверждена", "Нет совпадающего события успешного входа.", ev)
    count = 0
    sources: set[str] = set()
    success_source = None
    for success_at, candidate_source in sorted(successes):
        failures = [(event["src_ip"], _event_count(event.get("count"))) for kind, at, event in timeline
                    if kind == "login_failure" and event.get("user") == user
                    and isinstance(event.get("src_ip"), str) and event["src_ip"]
                    and success_at - timedelta(minutes=15) <= at < success_at]
        candidate_count = sum(amount for _, amount in failures)
        candidate_sources = {source for source, amount in failures if amount > 0}
        if candidate_count >= 5 and candidate_source in candidate_sources:
            count, sources, success_source = candidate_count, candidate_sources, candidate_source
            break
    if success_source is None:
        return _review("Перебор: недостаточно попыток или источников", "Не подтверждена серия неудачных входов.", ev)
    if (_scoped_approval(ev, data, ("user", "src_ip")) and data.get("approved_test") is True
            and sources == {success_source} and context_ok):
        support = [(event["_evidence_id"], "Вложенное событие подтверждает серию неудачных входов из того же источника.")
                   for kind, at, event in timeline if kind == "login_failure"
                   and event.get("user") == user and event.get("src_ip") == success_source
                   and success_at - timedelta(minutes=15) <= at < success_at
                   and isinstance(event.get("_evidence_id"), str)]
        support += [(event["_evidence_id"], "Вложенное событие подтверждает успешный вход после серии отказов.")
                    for kind, at, event in timeline if kind == "login_success" and at == success_at
                    and event.get("user") == user and event.get("src_ip") == success_source
                    and isinstance(event.get("_evidence_id"), str)]
        support += [(item_id, "Действующее согласование совпадает по пользователю и источнику теста.")
                    for item_id in _matching_policy_ids(ev, data, ("user", "src_ip"))]
        return _observed_nonincident("BENIGN_TRUE_POSITIVE", "Согласованное тестирование входа",
                                     "Серия попыток и успешный вход действительно произошли в утверждённое окно теста.", ev,
                                     support)
    priority = "critical" if data.get("account_critical") else "high"
    return Verdict(verdict="true_positive", priority=priority, summary="Перебор паролей с последующим входом",
                   rationale=f"Связаны {count} неудачных попыток из {len(sources)} источников и успешный вход пользователя.",
                   evidence_ids=_evidence_ids(ev), recommended_actions=["create_case"])


def powershell(data: dict, ev: list[dict], context_ok: bool) -> Verdict:
    required = ("command_line", "parent_process", "user", "host")
    if any(not data.get(k) for k in required):
        return _review("PowerShell: неполные данные процесса", "Для оценки нужны команда, родитель, пользователь и хост.", ev,
                       [k for k in required if not data.get(k)])
    command = data["command_line"].lower()
    suspicious = any(x in command for x in ("encodedcommand", "-enc ", "downloadstring", "invoke-expression", "iex(", "frombase64string"))
    timeline = _auth_timeline(ev)
    network = bool(data.get("network_events")) or any(kind == "network_connection"
               and event.get("host") in {None, data["host"]} for kind, _, event in timeline)
    if _scoped_approval(ev, data, ("host", "user", "command_line")) and data.get("admin_task") and not network and context_ok:
        parent = str(data["parent_process"]).lower()
        process = [(event["_evidence_id"], "Вложенное событие подтверждает запуск PowerShell от ожидаемого родителя.")
                   for kind, _, event in timeline if kind == "process_start"
                   and str(event.get("parent") or event.get("parent_process") or "").lower() == parent
                   and str(event.get("child") or event.get("process_name") or "").lower() == "powershell.exe"
                   and event.get("script_signed") is True
                   and isinstance(event.get("_evidence_id"), str)]
        if not process:
            return _review("PowerShell: выполнение задачи не подтверждено",
                           "Нет совпадающего события запуска подписанного скрипта от ожидаемого родителя.", ev)
        support = process + [(item_id, "Согласованное окно покрывает хост, пользователя и команду.")
                             for item_id in _matching_policy_ids(ev, data, ("host", "user", "command_line"))]
        return _observed_nonincident("BENIGN_TRUE_POSITIVE", "Согласованная задача PowerShell",
                                     "Команда действительно выполнена; задача администратора покрыта действующим согласованием, сетевые признаки отсутствуют.", ev,
                                     support)
    if suspicious and network:
        return Verdict(verdict="true_positive", priority="high", summary="Подозрительный PowerShell с сетевой активностью",
                       rationale="Опасный шаблон команды подтверждён связанным сетевым событием.",
                       evidence_ids=_evidence_ids(ev), recommended_actions=["create_case"])
    return _review("PowerShell требует ручного анализа", "Команда и контекст не подтверждают безопасный или вредоносный сценарий.", ev,
                   ["Дополнительные процессные и сетевые события"])


def generic(data: dict, ev: list[dict], context_ok: bool) -> Verdict:
    return _review("Неизвестное правило: требуется проверка", "Общий плейбук собрал доступный контекст, но правила решения отсутствуют.", ev,
                   ["Назначить плейбук и проверить событие"])


REGISTRY: dict[str, Playbook] = {
    "root_ssh": Playbook("root_ssh", "1.0.0", "Root SSH access", ("host", "src_ip", "auth_method"),
        ("asset", "maintenance", "exceptions", "prior_failures", "post_activity", "related_events", "misp"), root_ssh),
    "vpn_country": Playbook("vpn_country", "1.0.0", "VPN из новой страны", ("vpn_type", "stage"),
        ("peer", "device", "tunnel", "user", "related_events", "misp"), vpn_country),
    "ipsec_failure": Playbook("ipsec_failure", "1.0.0", "Неудачные IPsec-согласования", ("peer", "device", "tunnel", "failure_count"),
        ("frequency", "duration", "sources", "targets", "later_success", "maintenance"), ipsec_failure),
    "brute_force": Playbook("brute_force", "1.0.0", "Перебор паролей с последующим входом", ("user", "success_at", "failure_count"),
        ("user", "sources", "timeline", "criticality", "approved_test", "related_events"), brute_force),
    "powershell": Playbook("powershell", "1.0.0", "Подозрительный PowerShell", ("command_line", "parent_process", "user", "host"),
        ("process", "network", "asset", "maintenance", "related_events"), powershell),
    "generic": Playbook("generic", "1.0.0", "Общий плейбук", (),
        ("entities", "asset", "related_events", "misp"), generic),
}


def register(playbook: Playbook) -> None:
    if playbook.key in REGISTRY:
        raise ValueError("Плейбук уже зарегистрирован")
    REGISTRY[playbook.key] = playbook


def select_playbook(rule: str) -> Playbook:
    return REGISTRY.get(rule, REGISTRY["generic"])
