import json
import logging

import pytest

from app.observability import log_event


def test_structured_event_contains_only_allowlisted_identifiers():
    rows = []

    class Capture(logging.Handler):
        def emit(self, record):
            rows.append(record.getMessage())

    logger = logging.getLogger("soc.events")
    handler = Capture()
    old_level, old_disabled = logger.level, logger.disabled
    old_global_disable = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    logger.disabled = False
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        log_event("triage_completed", correlation_id="inv-1", event_id="alert-1",
                  classification="TP", status="needs_review")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.disabled = old_disabled
        logging.disable(old_global_disable)
    record = json.loads(rows[0])
    assert record["name"] == "triage_completed"
    assert record["correlation_id"] == "inv-1" and record["event_id"] == "alert-1"
    assert set(record) == {"at", "name", "correlation_id", "event_id", "classification", "status"}


def test_raw_event_fields_and_control_characters_are_rejected():
    with pytest.raises(ValueError):
        log_event("ingest", raw={"password": "secret"})
    with pytest.raises(ValueError):
        log_event("ingest", event_id="abc\nBearer secret")
