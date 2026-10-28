"""Input model for a personal data breach (synthetic data only in the demo)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Category = Literal[
    "basic_identity",
    "contact",
    "location",
    "national_id",
    "financial",
    "credentials",
    "health",
    "special_category",
    "criminal",
]

Exposure = Literal["public", "third_party", "misdirected_external", "internal", "none"]


class Incident(BaseModel):
    incident_id: str = Field(pattern=r"^[A-Za-z0-9._-]{3,40}$")
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=3, max_length=4000)
    organisation: str = Field(min_length=2, max_length=200)
    dpo_email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    breach_type: Literal["confidentiality", "integrity", "availability"]
    discovered_at: datetime
    data_categories: list[Category] = Field(min_length=1)
    subjects_count: int = Field(ge=0, le=100_000_000)
    exposure: Exposure
    encrypted: bool = False
    malicious: bool = False
    identifiable: bool = True
    vulnerable_subjects: bool = False
    recipients_confirmed_deleted: bool = False
    data_restored: bool = False
    restored_within_hours: float | None = Field(default=None, ge=0)
    mitigation_removes_high_risk: bool = False
    measures_taken: str = Field(default="", max_length=2000)
    delay_reason: str = Field(default="", max_length=1000)
    recipients: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("discovered_at")
    @classmethod
    def _needs_timezone(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("discovered_at must include a UTC offset, e.g. 2026-10-28T09:00:00+01:00")
        return v

    @field_validator("recipients")
    @classmethod
    def _recipient_format(cls, v: list[str]) -> list[str]:
        for r in v:
            if "@" not in r or any(c.isspace() for c in r):
                raise ValueError(f"invalid recipient address: {r!r}")
        return v
