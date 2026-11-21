"""Data structures shared by the sources, the priority engine and the reports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any

_ISO_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")


def parse_iso_date(value: str | None) -> date | None:
    """Parse the leading YYYY-MM-DD of a timestamp. Returns None when unusable."""
    if not value:
        return None
    match = _ISO_DATE.match(value.strip())
    if match is None:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


@dataclass(frozen=True)
class Priority:
    code: str
    label: str
    action: str
    rank: int

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "label": self.label, "action": self.action}


P0 = Priority("P0", "Emergency", "Patch or mitigate within 72 hours; treat as actively exploited.", 0)
P1 = Priority("P1", "Critical", "Patch within 7 days or apply the vendor mitigation now.", 1)
P2 = Priority("P2", "High", "Include in the next patch cycle (30 days).", 2)
P3 = Priority("P3", "Low", "Track; patch with routine maintenance.", 3)

PRIORITIES = {p.code: p for p in (P0, P1, P2, P3)}


@dataclass(frozen=True)
class SourceState:
    name: str
    status: str  # live | cache | stale | unavailable | skipped
    detail: str = ""
    age_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "age_seconds": None if self.age_seconds is None else round(self.age_seconds, 1),
        }

    @property
    def degraded(self) -> bool:
        return self.status in {"stale", "unavailable"}


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    date_added: str = ""
    due_date: str = ""
    required_action: str = ""
    ransomware: str = ""
    description: str = ""
    cwes: tuple[str, ...] = ()

    @property
    def asset(self) -> str:
        return " ".join(part for part in (self.vendor, self.product) if part) or "—"

    @property
    def ransomware_known(self) -> bool:
        return self.ransomware.strip().lower() == "known"


@dataclass(frozen=True)
class EpssScore:
    cve_id: str
    epss: float
    percentile: float | None = None
    date: str = ""


@dataclass(frozen=True)
class CvssScore:
    score: float
    severity: str = ""
    version: str = ""
    vector: str = ""


@dataclass
class Finding:
    cve_id: str
    kev: KevEntry | None = None
    epss: EpssScore | None = None
    cvss: CvssScore | None = None
    description: str = ""
    published: str = ""
    last_modified: str = ""
    priority: Priority | None = None
    rationale: str = ""
    gaps: list[str] = field(default_factory=list)

    # -- convenience -----------------------------------------------------
    @property
    def epss_value(self) -> float | None:
        return self.epss.epss if self.epss else None

    @property
    def cvss_value(self) -> float | None:
        return self.cvss.score if self.cvss else None

    @property
    def asset(self) -> str:
        if self.kev:
            return self.kev.asset
        if self.description:
            return _short(self.description, 60)
        return "—"

    @property
    def title(self) -> str:
        if self.kev and self.kev.name:
            return self.kev.name
        return _short(self.description, 120)

    def sort_key(self) -> tuple[Any, ...]:
        rank = self.priority.rank if self.priority else 9
        epss = -(self.epss_value or 0.0)
        return (rank, epss, self.cve_id)

    def to_dict(self, today: date | None = None) -> dict[str, Any]:
        today = today or date.today()
        due = parse_iso_date(self.kev.due_date) if self.kev else None
        days_left = (due - today).days if due else None
        return {
            "cve": self.cve_id,
            "priority": self.priority.to_dict() if self.priority else None,
            "rationale": self.rationale,
            "in_kev": self.kev is not None,
            "kev": None
            if self.kev is None
            else {
                "vendor": self.kev.vendor,
                "product": self.kev.product,
                "name": self.kev.name,
                "date_added": self.kev.date_added,
                "due_date": self.kev.due_date,
                "days_to_due": days_left,
                "ransomware": self.kev.ransomware,
                "required_action": self.kev.required_action,
                "cwes": list(self.kev.cwes),
                "description": self.kev.description,
            },
            "epss": None
            if self.epss is None
            else {
                "score": round(self.epss.epss, 6),
                "percentile": None
                if self.epss.percentile is None
                else round(self.epss.percentile, 6),
                "date": self.epss.date,
            },
            "cvss": None
            if self.cvss is None
            else {
                "base_score": self.cvss.score,
                "severity": self.cvss.severity,
                "version": self.cvss.version,
                "vector": self.cvss.vector,
            },
            "description": self.description,
            "published": self.published,
            "last_modified": self.last_modified,
            "data_gaps": list(self.gaps),
        }


def _short(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
