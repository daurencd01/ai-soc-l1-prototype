"""Canonical SOC categories, separate from the legacy action lane.

Only FP may enter the false-positive close lane. An observed, approved action
is benign, not a false alarm; low-value repeated events are noise. Both remain
in the review lane until an independently approved disposition policy acts.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Classification = Literal["TP", "FP", "BENIGN_TRUE_POSITIVE", "NOISE", "INCONCLUSIVE"]
LegacyVerdict = Literal["true_positive", "false_positive", "needs_review"]


class EvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_id: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=1, max_length=500)


def action_lane(classification: Classification) -> LegacyVerdict:
    """Map a classification to the existing action gate, fail closed by design."""
    if classification == "TP":
        return "true_positive"
    if classification == "FP":
        return "false_positive"
    return "needs_review"


def classification_for_lane(verdict: LegacyVerdict) -> Classification:
    """Compatibility for pre-classification records and callers."""
    return {"true_positive": "TP", "false_positive": "FP", "needs_review": "INCONCLUSIVE"}[verdict]
