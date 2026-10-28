"""Deterministic risk assessment for GDPR Art. 33/34, structured after EDPB Guidelines 9/2022.

The outcome is decided by explicit, auditable rules (never by a language model).
Every point in the score is returned as a factor with its legal basis.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .models import Incident

NONE = "NO_NOTIFICATION"
AUTHORITY = "NOTIFY_AUTHORITY"
AUTHORITY_AND_SUBJECTS = "NOTIFY_AUTHORITY_AND_SUBJECTS"

DEADLINE_HOURS = 72

SENSITIVITY = {
    "basic_identity": 1,
    "contact": 1,
    "location": 2,
    "national_id": 3,
    "financial": 3,
    "credentials": 3,
    "health": 4,
    "special_category": 4,
    "criminal": 4,
}

EDPB = "EDPB Guidelines 9/2022"


@dataclass
class Factor:
    name: str
    points: int
    basis: str


@dataclass
class Assessment:
    outcome: str
    score: int
    factors: list[Factor] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    deadline: datetime | None = None
    hours_left: float = 0.0
    late: bool = False
    art34_exception: str = ""

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "score": self.score,
            "factors": [f.__dict__ for f in self.factors],
            "reasons": self.reasons,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "hours_left": round(self.hours_left, 1),
            "late": self.late,
            "art34_exception": self.art34_exception,
        }


def deadline_for(discovered_at: datetime) -> datetime:
    """Art. 33(1): not later than 72 hours after having become aware."""
    return discovered_at + timedelta(hours=DEADLINE_HOURS)


def assess(inc: Incident, now: datetime | None = None) -> Assessment:
    now = now or datetime.now(timezone.utc)
    deadline = deadline_for(inc.discovered_at)
    hours_left = (deadline - now).total_seconds() / 3600
    late = hours_left < 0

    result = Assessment(outcome=NONE, score=0, deadline=deadline, hours_left=hours_left, late=late)

    # Rule 1: strong encryption, confidentiality only (Art. 34(3)(a), EDPB 9/2022 section on encryption).
    if inc.encrypted and inc.breach_type == "confidentiality":
        result.reasons.append(
            "Data were encrypted with state of the art encryption and the key was not compromised, "
            "so a risk to individuals is unlikely (Art. 33(1), Art. 34(3)(a); " + EDPB + ")."
        )
        result.reasons.append("Document the breach in the internal register (Art. 33(5)).")
        result.factors.append(Factor("encryption", 0, "Art. 34(3)(a)"))
        return _finish(result, late)

    # Rule 2: short availability loss without malicious activity (EDPB 9/2022, availability examples).
    if (
        inc.breach_type == "availability"
        and inc.data_restored
        and inc.restored_within_hours is not None
        and inc.restored_within_hours <= 4
        and inc.exposure == "none"
        and not inc.malicious
    ):
        result.reasons.append(
            f"Temporary loss of availability, restored within {inc.restored_within_hours:g} h, no sign of "
            "unauthorised access or malicious activity: risk unlikely (Art. 33(1); " + EDPB + ")."
        )
        result.reasons.append("Document the breach in the internal register (Art. 33(5)).")
        result.factors.append(Factor("short outage", 0, "Art. 33(1)"))
        return _finish(result, late)

    score = 0

    # Nature, sensitivity and volume of data.
    top = max(SENSITIVITY[c] for c in inc.data_categories)
    extra = min(2, len(set(inc.data_categories)) - 1)
    result.factors.append(
        Factor("data sensitivity", top + extra, "Art. 33(1), Recital 75, Art. 9; " + EDPB + " section IV.B.2")
    )
    score += top + extra

    if inc.subjects_count >= 10_000:
        vol = 3
    elif inc.subjects_count >= 1_000:
        vol = 2
    elif inc.subjects_count >= 100:
        vol = 1
    else:
        vol = 0
    result.factors.append(Factor("number of individuals", vol, EDPB + " section IV.B.7"))
    score += vol

    # Type of breach and exposure.
    exposure_points = {"public": 3, "third_party": 2, "misdirected_external": 1, "internal": 0, "none": -1}[inc.exposure]
    result.factors.append(Factor("exposure: " + inc.exposure, exposure_points, EDPB + " section IV.B.1"))
    score += exposure_points

    if inc.breach_type == "integrity":
        result.factors.append(Factor("integrity breach", 1, EDPB + " section IV.B.1"))
        score += 1
    if inc.breach_type == "availability" and not inc.data_restored:
        result.factors.append(Factor("data not restored", 2, EDPB + " section IV.B.1"))
        score += 2

    if inc.malicious:
        result.factors.append(Factor("malicious intent", 2, EDPB + " section IV.B.1"))
        score += 2
    if not inc.identifiable:
        result.factors.append(Factor("individuals not identifiable", -2, EDPB + " section IV.B.3"))
        score -= 2
    if inc.vulnerable_subjects:
        result.factors.append(Factor("vulnerable individuals (e.g. children)", 2, EDPB + " section IV.B.5, Recital 75"))
        score += 2
    if inc.recipients_confirmed_deleted:
        result.factors.append(Factor("recipients confirmed deletion", -2, EDPB + " section IV.B.1"))
        score -= 2

    score = max(score, 0)
    result.score = score

    if score <= 1:
        result.outcome = NONE
        result.reasons.append(
            f"Risk score {score}: a risk to the rights and freedoms of individuals is unlikely (Art. 33(1))."
        )
        result.reasons.append("Document the breach in the internal register (Art. 33(5)).")
    elif score <= 7:
        result.outcome = AUTHORITY
        result.reasons.append(
            f"Risk score {score}: the breach is likely to result in a risk, notify the supervisory authority "
            "within 72 hours (Art. 33(1))."
        )
    else:
        result.outcome = AUTHORITY_AND_SUBJECTS
        result.reasons.append(
            f"Risk score {score}: the breach is likely to result in a high risk, notify the supervisory authority "
            "(Art. 33(1)) and the affected individuals without undue delay (Art. 34(1))."
        )
        if inc.mitigation_removes_high_risk:
            result.outcome = AUTHORITY
            result.art34_exception = "Art. 34(3)(b)"
            result.reasons.append(
                "Subsequent measures ensure that the high risk is no longer likely to materialise, so "
                "communication to individuals is not required (Art. 34(3)(b)). The DPO must be able to "
                "evidence these measures."
            )
    return _finish(result, late)


def _finish(result: Assessment, late: bool) -> Assessment:
    if late and result.outcome != NONE:
        result.reasons.append(
            "The 72 hour deadline has passed: the notification must state the reasons for the delay (Art. 33(1))."
        )
    return result
