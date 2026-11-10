"""An audit receipt never claims that an unverified external action succeeded."""

from app.main import audit_outcome
from app.models import Audit


def test_audit_outcomes_distinguish_external_result_from_recorded_event():
    def event(operation: str, detail: dict | None = None) -> Audit:
        return Audit(tenant_id="tenant", actor="worker", operation=operation,
                     subject_type="action", subject_id="action", detail=detail or {})

    assert audit_outcome(event("action_succeeded")) == "succeeded"
    assert audit_outcome(event("action_failed_or_unknown", {"status": "unknown"})) == "unknown"
    assert audit_outcome(event("auto_close_attempted")) == "attempted"
    assert audit_outcome(event("manual_close_denied")) == "denied"
    assert audit_outcome(event("integration_error")) == "failed"
    assert audit_outcome(event("decision")) == "recorded"
