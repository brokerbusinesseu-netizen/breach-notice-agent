"""Twelve synthetic scenarios with the expected outcome decided from GDPR Art. 33/34 and EDPB 9/2022."""
from datetime import datetime, timedelta, timezone

import pytest

from app.models import Incident
from app.risk import AUTHORITY, AUTHORITY_AND_SUBJECTS, NONE, assess

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def inc(**kw) -> Incident:
    base = dict(
        incident_id="T-001", title="Test incident", description="synthetic", organisation="Org (SYNTHETIC)",
        dpo_email="dpo@example.test", breach_type="confidentiality",
        discovered_at=NOW - timedelta(hours=1), data_categories=["basic_identity"],
        subjects_count=1, exposure="internal",
    )
    base.update(kw)
    return Incident(**base)


SCENARIOS = [
    ("lost laptop, strong encryption", dict(encrypted=True, exposure="third_party", subjects_count=5000,
        data_categories=["basic_identity", "financial"]), NONE),
    ("misdirected e-mail, deletion confirmed", dict(exposure="misdirected_external",
        data_categories=["basic_identity", "contact"], recipients_confirmed_deleted=True), NONE),
    ("misdirected e-mail, no confirmation", dict(exposure="misdirected_external",
        data_categories=["basic_identity", "contact"]), AUTHORITY),
    ("short outage, no malice", dict(breach_type="availability", data_restored=True, restored_within_hours=2,
        exposure="none", subjects_count=500), NONE),
    ("pseudonymised data, not identifiable", dict(exposure="third_party", identifiable=False), NONE),
    ("unencrypted laptop found by third party", dict(exposure="third_party", subjects_count=300,
        data_categories=["basic_identity", "contact"]), AUTHORITY),
    ("integrity: wrong records, internal", dict(breach_type="integrity",
        data_categories=["basic_identity", "contact"], subjects_count=40), AUTHORITY),
    ("public bucket with credentials", dict(exposure="public", subjects_count=200,
        data_categories=["credentials", "contact"]), AUTHORITY_AND_SUBJECTS),
    ("ransomware on clinic server, no restore", dict(breach_type="availability", malicious=True,
        exposure="third_party", subjects_count=4200, data_restored=False,
        data_categories=["basic_identity", "contact", "health", "national_id"]), AUTHORITY_AND_SUBJECTS),
    ("database leak: financial and national id", dict(exposure="public", malicious=True, subjects_count=20000,
        data_categories=["financial", "national_id", "basic_identity"]), AUTHORITY_AND_SUBJECTS),
    ("location leak of children", dict(exposure="public", vulnerable_subjects=True, subjects_count=100,
        data_categories=["basic_identity", "location"]), AUTHORITY_AND_SUBJECTS),
    ("ransomware, quick restore, no sign of exfiltration", dict(breach_type="availability",
        malicious=True, data_restored=True, restored_within_hours=2, exposure="none",
        subjects_count=800, data_categories=["health"]), AUTHORITY),
]


@pytest.mark.parametrize("name,kw,expected", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_scenario(name, kw, expected):
    a = assess(inc(**kw), NOW)
    assert a.outcome == expected, (name, a.score, [f.__dict__ for f in a.factors])
    assert a.reasons, "every outcome carries a reasoned basis"


def test_art34_3b_mitigation_downgrades_subject_notice():
    a = assess(inc(exposure="public", subjects_count=200, data_categories=["credentials", "contact"],
                   mitigation_removes_high_risk=True), NOW)
    assert a.outcome == AUTHORITY and a.art34_exception == "Art. 34(3)(b)"


def test_deadline_is_72_hours_and_flags_late():
    on_time = assess(inc(discovered_at=NOW - timedelta(hours=10), exposure="public",
                         data_categories=["credentials"], subjects_count=200), NOW)
    assert round(on_time.hours_left) == 62 and not on_time.late
    late = assess(inc(discovered_at=NOW - timedelta(hours=80), exposure="public",
                      data_categories=["credentials"], subjects_count=200), NOW)
    assert late.late and any("reasons for the delay" in r for r in late.reasons)


def test_naive_datetime_rejected():
    with pytest.raises(ValueError):
        inc(discovered_at=datetime(2026, 10, 28, 9, 0))
