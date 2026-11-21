"""The priority model.

P0-P3 is a decision table, not a score. It follows the order CISA's own
remediation guidance uses (KEV membership and its due date first, then
exploitation likelihood from EPSS, then technical severity from CVSS):

    P0  in CISA KEV and due within 7 days (or overdue), or KEV + known
        ransomware use            -> patch/mitigate within 72 hours
    P1  in CISA KEV, or not in KEV with EPSS >= 10% and CVSS >= 9.0
                                  -> patch within 7 days
    P2  EPSS >= 1% or CVSS >= 7.0 -> next patch cycle (30 days)
    P3  everything else           -> routine maintenance

A CVE that no source knows is P3 with an explicit data gap, never silently
treated as safe.
"""

from __future__ import annotations

from datetime import date

from .model import P0, P1, P2, P3, Finding, Priority, parse_iso_date

EPSS_P1 = 0.10
EPSS_P2 = 0.01
CVSS_P1 = 9.0
CVSS_P2 = 7.0
DUE_SOON_DAYS = 7


def classify(finding: Finding, today: date | None = None) -> Priority:
    today = today or date.today()
    signals: list[str] = []

    if finding.kev is not None:
        entry = finding.kev
        due = parse_iso_date(entry.due_date)
        days_left = (due - today).days if due is not None else None
        signals.append(f"CISA KEV (added {entry.date_added or '?'})")
        if days_left is not None:
            if days_left < 0:
                signals.append(f"{-days_left}d past the federal due date")
            elif days_left == 0:
                signals.append("due today")
            else:
                signals.append(f"due in {days_left}d")
        if entry.ransomware_known:
            signals.append("known ransomware use")

        if entry.ransomware_known or (days_left is not None and days_left <= DUE_SOON_DAYS):
            priority = P0
        else:
            priority = P1
    else:
        signals.append("not in CISA KEV")
        epss = finding.epss_value
        cvss = finding.cvss_value
        if epss is not None and cvss is not None and epss >= EPSS_P1 and cvss >= CVSS_P1:
            priority = P1
        elif (epss is not None and epss >= EPSS_P2) or (cvss is not None and cvss >= CVSS_P2):
            priority = P2
        else:
            priority = P3

    if finding.epss is not None:
        signals.append(f"EPSS {finding.epss.epss * 100:.1f}%")
        if finding.epss.percentile is not None:
            signals.append(f"p{finding.epss.percentile * 100:.0f}")
    else:
        finding.gaps.append("EPSS: no score")

    if finding.cvss is not None:
        signals.append(f"CVSS {finding.cvss.score:g} {finding.cvss.severity}".strip())
    else:
        finding.gaps.append("NVD: no CVSS")
        if not finding.description:
            finding.gaps.append("NVD: no record")

    if finding.kev is None and finding.epss is None and finding.cvss is None:
        signals.append("no public data — verify the identifier")

    finding.priority = priority
    finding.rationale = " · ".join(signals)
    return priority


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for finding in findings:
        if finding.priority:
            summary[finding.priority.code] += 1
    summary["kev_listed"] = sum(1 for finding in findings if finding.kev is not None)
    summary["total"] = len(findings)
    return summary
