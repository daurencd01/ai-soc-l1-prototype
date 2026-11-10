"""Five distinct SOC categories and their safe action lanes."""

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzer import OllamaTriage, _validated_verdict
from app.classification import action_lane
from app.playbooks import Verdict, brute_force, ipsec_failure, powershell, root_ssh, vpn_country


AT = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def event(evidence_id: str, kind: str, *, at: datetime = AT, **data) -> dict:
    return {"id": evidence_id, "kind": "embedded_event", "data": {
        "event_at": at.isoformat(), "data": {"kind": kind, **data}}}


def approval(kind: str, **scope) -> dict:
    return {"id": "approval", "kind": kind, "data": {"scope": scope}}


def test_action_lane_never_treats_observed_benign_or_noise_as_fp():
    assert {item: action_lane(item) for item in (
        "TP", "FP", "BENIGN_TRUE_POSITIVE", "NOISE", "INCONCLUSIVE"
    )} == {
        "TP": "true_positive", "FP": "false_positive",
        "BENIGN_TRUE_POSITIVE": "needs_review", "NOISE": "needs_review",
        "INCONCLUSIVE": "needs_review",
    }
    with pytest.raises(ValueError, match="Категория"):
        Verdict(verdict="false_positive", classification="BENIGN_TRUE_POSITIVE", priority="low",
                summary="x", rationale="x")
    with pytest.raises(ValueError, match="автозакрытию"):
        Verdict(verdict="needs_review", classification="NOISE", priority="low",
                summary="x", rationale="x", auto_close_eligible=True)


def test_approved_root_login_is_benign_true_positive_not_false_positive():
    data = {"host": "srv", "src_ip": "10.0.0.1", "auth_method": "key",
            "prior_failures": 0, "post_activity": []}
    evidence = [event("login", "ssh_login_success", user="root", host="srv",
                      src_ip="10.0.0.1", method="key"),
                approval("active_exception", host="srv", src_ip="10.0.0.1", auth_method="key")]
    result = root_ssh(data, evidence, True)
    assert result.classification == "BENIGN_TRUE_POSITIVE"
    assert result.verdict == "needs_review"
    assert result.auto_close_eligible is False
    assert "close_alert" not in result.recommended_actions
    assert {claim.evidence_id for claim in result.evidence_for} == {"login", "approval"}


def test_known_ipsec_session_is_benign_and_repeated_failures_are_noise():
    known_peer = {"id": "peer", "kind": "asset", "data": {"kind": "vpn_peer", "value": "peer1",
                  "attributes": {"allowed": True, "tunnel": "tun1", "device": "fw1"}}}
    session = vpn_country({"vpn_type": "ipsec", "stage": "established", "peer": "peer1",
                           "device": "fw1", "tunnel": "tun1"},
                          [known_peer, event("session", "ipsec_ike_established", peer="peer1", tunnel="tun1")], True)
    assert session.classification == "BENIGN_TRUE_POSITIVE"
    assert session.verdict == "needs_review"
    assert {claim.evidence_id for claim in session.evidence_for} == {"session", "peer"}

    failures = ipsec_failure({"failure_count": 8, "peer": "peer1", "device": "fw1",
                              "tunnel": "tun1", "later_success": False},
                             [known_peer, approval("approved_maintenance", peer="peer1",
                                                   device="fw1", tunnel="tun1"),
                              event("failure", "ipsec_ike_failed", peer="peer1", count=8)], True)
    assert failures.classification == "NOISE"
    assert failures.verdict == "needs_review"
    assert failures.auto_close_eligible is False
    assert "close_alert" not in failures.recommended_actions
    assert {claim.evidence_id for claim in failures.evidence_for} == {"failure", "peer", "approval"}


def test_raw_summary_and_allowlist_without_source_events_do_not_prove_benign_or_noise():
    known_peer = {"id": "peer", "kind": "asset", "data": {"kind": "vpn_peer", "value": "peer1",
                  "attributes": {"allowed": True, "tunnel": "tun1", "device": "fw1"}}}
    session = vpn_country({"vpn_type": "ipsec", "stage": "established", "peer": "peer1",
                           "device": "fw1", "tunnel": "tun1"}, [known_peer], True)
    assert session.classification == "INCONCLUSIVE" and not session.auto_close_eligible

    failures = ipsec_failure({"failure_count": 8, "peer": "peer1", "device": "fw1",
                              "tunnel": "tun1", "later_success": False},
                             [known_peer, approval("approved_maintenance", peer="peer1",
                                                   device="fw1", tunnel="tun1")], True)
    assert failures.classification == "INCONCLUSIVE" and not failures.auto_close_eligible


def test_approved_brute_force_test_and_admin_command_are_observed_not_fp():
    data = {"user": "alice", "src_ip": "10.0.0.2", "approved_test": True}
    evidence = [event("fail", "login_failure", at=AT - timedelta(minutes=1),
                      user="alice", src_ip="10.0.0.2", count=5),
                event("success", "login_success", user="alice", src_ip="10.0.0.2"),
                approval("active_exception", user="alice", src_ip="10.0.0.2")]
    result = brute_force(data, evidence, True)
    assert result.classification == "BENIGN_TRUE_POSITIVE"
    assert result.auto_close_eligible is False
    assert {claim.evidence_id for claim in result.evidence_for} == {"fail", "success", "approval"}

    command = {"host": "srv", "user": "admin", "command_line": "Get-Process",
               "parent_process": "explorer.exe", "admin_task": True, "network_events": []}
    approved = approval("approved_maintenance", host="srv", user="admin",
                        command_line="Get-Process")
    result = powershell(command, [approved, event("process", "process_start",
                                                parent="explorer.exe", child="powershell.exe",
                                                script_signed=True)], True)
    assert result.classification == "BENIGN_TRUE_POSITIVE"
    assert result.verdict == "needs_review"
    assert {claim.evidence_id for claim in result.evidence_for} == {"process", "approval"}


def proposal(classification: str, *, auto_close_candidate: bool = True,
             evidence_for: list[dict] | None = None, actions: list[str] | None = None) -> OllamaTriage:
    return OllamaTriage.model_validate({
        "classification": classification, "confidence": 0.75, "severity": "low",
        "summary": "Объяснение", "evidence_for": evidence_for if evidence_for is not None else [
            {"evidence_id": "e1", "reason": "Проверенный факт"}],
        "evidence_against": [], "missing_evidence": [], "related_event_ids": [],
        "mitre_techniques": [], "recommended_actions": actions or ["review"],
        "auto_close_candidate": auto_close_candidate,
    })


@pytest.mark.parametrize("classification", ["BENIGN_TRUE_POSITIVE", "NOISE", "INCONCLUSIVE"])
def test_model_keeps_non_fp_category_without_close_permission(classification):
    baseline = Verdict(verdict="needs_review", classification=classification,
                       priority="low", summary="x", rationale="x", evidence_ids=["e1"])
    result = _validated_verdict(proposal(classification), baseline, {"e1"}, set(), "local:7b", "d" * 64)
    assert result.classification == classification
    assert result.verdict == "needs_review"
    assert result.auto_close_eligible is False
    assert result.recommended_actions == ["review"]
    assert result.evidence_for[0].evidence_id == "e1"
    assert result.confidence == 0.75


def test_model_auto_close_candidate_must_agree_with_grounded_fp_baseline():
    baseline = Verdict(verdict="false_positive", priority="low", summary="x", rationale="x",
                       evidence_ids=["e1"], auto_close_eligible=True)
    rejected = _validated_verdict(proposal("FP", auto_close_candidate=False,
                                           actions=["close_alert"]),
                                  baseline, {"e1"}, set(), "local:7b", "d" * 64)
    assert rejected.classification == "FP"
    assert rejected.auto_close_eligible is False

    supported = _validated_verdict(proposal("FP", actions=["close_alert"]),
                                   baseline, {"e1"}, set(), "local:7b", "d" * 64)
    assert supported.auto_close_eligible is True


def test_confidence_is_bounded_and_deterministic_results_have_no_model_score():
    deterministic = Verdict(verdict="needs_review", priority="low", summary="x", rationale="x")
    assert deterministic.confidence is None
    for confidence in (-0.01, 1.01, True, "0.5"):
        with pytest.raises(ValueError):
            Verdict(verdict="needs_review", priority="low", summary="x", rationale="x",
                    confidence=confidence)


def test_model_conclusive_classification_requires_grounded_evidence():
    baseline = Verdict(verdict="needs_review", priority="low", summary="x", rationale="x")
    with pytest.raises(ValueError, match="не обоснован"):
        _validated_verdict(proposal("BENIGN_TRUE_POSITIVE", evidence_for=[]), baseline,
                           {"e1"}, set(), "local:7b", "d" * 64)
