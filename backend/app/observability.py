"""Structured operational events containing identifiers, never raw SOC records."""

from datetime import datetime, timezone
import json
import logging
import sys


_FIELDS = frozenset({"correlation_id", "event_id", "tenant_id", "action", "classification",
                     "status", "method", "route", "http_status", "error_type"})
_logger = logging.getLogger("soc.events")
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)


def log_event(name: str, **fields: str | int | None) -> None:
    """Emit one bounded JSON line; callers pass internal IDs and fixed labels only."""
    if not isinstance(name, str) or not name or len(name) > 80 or not name.replace("_", "").isalnum():
        raise ValueError("Некорректный тип события журнала")
    if any(key not in _FIELDS for key in fields):
        raise ValueError("Недопустимое поле структурированного журнала")
    safe: dict[str, str | int | None] = {}
    for key, value in fields.items():
        if value is None or isinstance(value, int) and not isinstance(value, bool):
            safe[key] = value
        elif isinstance(value, str) and len(value) <= 200 and all(ord(char) >= 32 for char in value):
            safe[key] = value
        else:
            raise ValueError("Недопустимое значение структурированного журнала")
    _logger.info(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "name": name, **safe},
                            ensure_ascii=False, separators=(",", ":")))
