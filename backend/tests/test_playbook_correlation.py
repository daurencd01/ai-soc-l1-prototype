from datetime import datetime, timedelta, timezone

import pytest

from app.playbooks import brute_force, root_ssh


BASE = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def event(kind: str, minute: int, **fields: object) -> dict:
    return {
        "id": f"{kind}:{minute}",
        "kind": "embedded_event",
        "data": {"event_at": (BASE + timedelta(minutes=minute)).isoformat(),
                 "data": {"kind": kind, **fields}},
    }


def approval(**scope: str) -> dict:
    return {"id": "policy", "kind": "approved_maintenance", "data": {"scope": scope}}


def root_alert(**overrides: object) -> dict:
    return {"host": "host-a", "src_ip": "192.0.2.1", "user": "root",
            "auth_method": "publickey", "prior_failures": 0, "post_activity": [], **overrides}


def root_success(**overrides: object) -> dict:
    return event("ssh_login_success", 0, user="root", src_ip="192.0.2.1", host="host-a", **overrides)


def brute_alert(**overrides: object) -> dict:
    return {"user": "analyst", "src_ip": "192.0.2.2", "failure_count": 30,
            "success_at": BASE.isoformat(), "approved_test": False, **overrides}


def brute_success(**overrides: object) -> dict:
    return event("login_success", 0, user="analyst", src_ip="192.0.2.2", **overrides)


def test_root_summary_cannot_invent_attack_or_success():
    raw = root_alert(prior_failures=30, post_activity=["unapproved command"])
    assert root_ssh(raw, [root_success()], True).verdict == "needs_review"
    assert root_ssh(raw, [event("ssh_login_failure", -2, user="root",
                                src_ip="192.0.2.1", count=30)], True).verdict == "needs_review"


@pytest.mark.parametrize("failure", [
    event("ssh_login_failure", -2, user="other", src_ip="192.0.2.1", count=30),
    event("ssh_login_failure", -2, user="root", src_ip="192.0.2.99", count=30),
    event("ssh_login_failure", 2, user="root", src_ip="192.0.2.1", count=30),
])
def test_root_failures_must_match_identity_source_and_order(failure):
    decision = root_ssh(root_alert(prior_failures=30), [failure, root_success()], True)
    assert decision.verdict == "needs_review"


def test_root_matching_events_override_benign_summary_and_scope_controls_close():
    failures = event("ssh_login_failure", -2, user="root", src_ip="192.0.2.1", count=18)
    matching = approval(host="host-a", src_ip="192.0.2.1", auth_method="publickey")
    assert root_ssh(root_alert(), [failures, root_success(), matching], True).verdict == "true_positive"
    allowed = root_ssh(root_alert(), [root_success(), matching], True)
    assert allowed.verdict == "false_positive" and allowed.auto_close_eligible
    other_source = approval(host="host-a", src_ip="192.0.2.99", auth_method="publickey")
    assert root_ssh(root_alert(), [root_success(), other_source], True).verdict == "needs_review"


def test_root_checks_later_success_and_does_not_auto_close_multiple_logins():
    second_success = event("ssh_login_success", 3, user="root", src_ip="192.0.2.1", host="host-a")
    matching = approval(host="host-a", src_ip="192.0.2.1", auth_method="publickey")
    assert root_ssh(root_alert(), [root_success(), second_success, matching], True).verdict == "needs_review"
    failures = event("ssh_login_failure", 2, user="root", src_ip="192.0.2.1", count=8)
    assert root_ssh(root_alert(), [root_success(), failures, second_success], True).verdict == "true_positive"


def test_root_process_on_same_host_needs_user_attribution():
    host_only = event("process_start", 2, host="host-a", approved_task=False)
    matched = event("process_start", 2, host="host-a", user="root", approved_task=False)
    assert root_ssh(root_alert(), [root_success(), host_only], True).verdict == "needs_review"
    assert root_ssh(root_alert(), [root_success(), matched], True).verdict == "true_positive"


def test_brute_summary_cannot_invent_failure_or_success():
    raw = brute_alert(failure_count=100)
    unrelated = event("login_failure", -2, user="other", src_ip="192.0.2.2", count=100)
    assert brute_force(raw, [brute_success(), unrelated], True).verdict == "needs_review"
    matched = event("login_failure", -2, user="analyst", src_ip="192.0.2.2", count=100)
    assert brute_force(raw, [matched], True).verdict == "needs_review"


@pytest.mark.parametrize("failure", [
    event("login_failure", -20, user="analyst", src_ip="192.0.2.2", count=30),
    event("login_failure", 1, user="analyst", src_ip="192.0.2.2", count=30),
    event("login_failure", -2, user="other", src_ip="192.0.2.2", count=30),
    event("login_failure", -2, user="analyst", src_ip="192.0.2.99", count=30),
])
def test_brute_correlation_requires_same_user_recent_prior_failures_and_success_source(failure):
    assert brute_force(brute_alert(), [failure, brute_success()], True).verdict == "needs_review"


def test_brute_uses_event_counts_and_requires_policy_scope_for_test_closure():
    matched = event("login_failure", -3, user="analyst", src_ip="192.0.2.2", count=30)
    policy = approval(user="analyst", src_ip="192.0.2.2")
    raw = brute_alert(failure_count=0, approved_test=True)
    allowed = brute_force(raw, [matched, brute_success(), policy], True)
    assert allowed.verdict == "false_positive" and allowed.auto_close_eligible
    wrong_scope = approval(user="analyst", src_ip="192.0.2.99")
    assert brute_force(raw, [matched, brute_success(), wrong_scope], True).verdict == "true_positive"


def test_brute_uses_dated_splunk_event_rows():
    related = [
        {"id": "failure", "kind": "related_event", "data": {
            "kind": "login_failure", "user": "analyst", "src": "192.0.2.2",
            "count": 7, "_time": (BASE - timedelta(minutes=2)).timestamp()}},
        {"id": "success", "kind": "related_event", "data": {
            "kind": "login_success", "user": "analyst", "src": "192.0.2.2",
            "_time": BASE.timestamp()}},
    ]
    assert brute_force(brute_alert(failure_count=0, success_at=None), related, True).verdict == "true_positive"


def test_brute_checks_later_success_when_first_success_has_no_prior_failures():
    timeline = [brute_success(),
                event("login_failure", 2, user="analyst", src_ip="192.0.2.2", count=10),
                event("login_success", 3, user="analyst", src_ip="192.0.2.2")]
    assert brute_force(brute_alert(failure_count=0), timeline, True).verdict == "true_positive"
