"""Output renderers: aligned tables for humans, Markdown for tickets, JSON for machines."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, Sequence

from . import __version__
from .model import Finding, KevEntry, Priority, SourceState, parse_iso_date

RESET = "\033[0m"
COLORS = {
    "P0": "\033[1;31m",
    "P1": "\033[1;33m",
    "P2": "\033[36m",
    "P3": "\033[2m",
    "muted": "\033[2m",
    "ok": "\033[32m",
    "warn": "\033[33m",
}
FORMATS = ("table", "json", "markdown")


def _paint(text: str, code: str | None, color: bool) -> str:
    if not color or not code:
        return text
    return f"{COLORS.get(code, '')}{text}{RESET}"


def _stamp(now: datetime | None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _pct(value: float | None) -> str:
    if value is None:
        return "—"
    if value >= 0.99:
        return f"{value * 100:.0f}%"
    if value >= 0.1:
        return f"{value * 100:.1f}%"
    return f"{value * 100:.2f}%"


def _cvss(finding: Finding) -> str:
    if finding.cvss is None:
        return "—"
    return f"{finding.cvss.score:g}"


def _due(finding: Finding) -> str:
    if not finding.kev or not finding.kev.due_date:
        return "—"
    due = parse_iso_date(finding.kev.due_date)
    if due is None:
        return finding.kev.due_date
    left = (due - datetime.now(timezone.utc).date()).days
    if left < 0:
        return f"{finding.kev.due_date} (-{-left}d)"
    return f"{finding.kev.due_date} ({left}d)"


def _signal(finding: Finding) -> str:
    parts: list[str] = []
    if finding.kev:
        parts.append("KEV")
        due = parse_iso_date(finding.kev.due_date)
        if due is not None:
            left = (due - datetime.now(timezone.utc).date()).days
            parts.append(f"due {'today' if left == 0 else f'{left}d' if left > 0 else f'{-left}d over'}")
        if finding.kev.ransomware_known:
            parts.append("ransomware")
    else:
        parts.append("not KEV")
    if finding.epss is not None:
        parts.append(f"EPSS {_pct(finding.epss.epss)}")
    if finding.cvss is not None:
        parts.append(f"CVSS {finding.cvss.score:g}")
    if finding.priority and finding.priority.code == "P3" and not (finding.epss or finding.cvss):
        parts.append("no data")
    return " · ".join(parts)


def sources_line(states: Sequence[SourceState]) -> str:
    chunks = []
    for state in states:
        label = {"kev": "KEV", "epss": "EPSS", "nvd": "NVD"}.get(state.name, state.name)
        if state.status == "skipped":
            chunks.append(f"{label}: skipped")
        elif state.status == "live":
            chunks.append(f"{label}: live" + (f" ({state.detail})" if state.detail else ""))
        elif state.status == "cache":
            age = f"{state.age_seconds / 3600:.1f}h old" if state.age_seconds else "cached"
            chunks.append(f"{label}: cache, {age}")
        elif state.status == "stale":
            age = f"{state.age_seconds / 3600:.1f}h old" if state.age_seconds else "stale"
            chunks.append(f"{label}: STALE, {age} — {state.detail}")
        else:
            chunks.append(f"{label}: UNAVAILABLE — {state.detail}")
    return " · ".join(chunks)


def _summary_line(findings: Sequence[Finding]) -> str:
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for finding in findings:
        if finding.priority:
            counts[finding.priority.code] += 1
    kev = sum(1 for finding in findings if finding.kev)
    return (
        f"P0 {counts['P0']} · P1 {counts['P1']} · P2 {counts['P2']} · P3 {counts['P3']}"
        f" · KEV listed {kev}/{len(findings)}"
    )


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------
def render_check(
    findings: Sequence[Finding],
    states: Sequence[SourceState],
    fmt: str = "table",
    *,
    color: bool = False,
    now: datetime | None = None,
) -> str:
    if fmt == "json":
        return _check_json(findings, states, now)
    if fmt == "markdown":
        return _check_markdown(findings, states, now)
    return _check_table(findings, states, color)


def _check_table(findings: Sequence[Finding], states: Sequence[SourceState], color: bool) -> str:
    header = ("PRI", "CVE", "KEV", "DUE", "EPSS", "CVSS", "ASSET", "SIGNAL")
    rows = []
    for finding in findings:
        rows.append(
            (
                finding.priority.code if finding.priority else "—",
                finding.cve_id,
                "yes" if finding.kev else "no",
                _due(finding),
                _pct(finding.epss_value),
                _cvss(finding),
                finding.asset,
                _signal(finding),
            )
        )
    widths = [
        max(len(str(header[i])), *(len(str(row[i])) for row in rows)) if rows else len(header[i])
        for i in range(len(header))
    ]
    lines = []
    lines.append(_paint(" · ".join([_stamp(None), sources_line(states)]), "muted", color))
    lines.append("")
    lines.append("  ".join(str(header[i]).ljust(widths[i]) for i in range(len(header))).rstrip())
    for row in rows:
        cells = []
        for i, value in enumerate(row):
            text = str(value).ljust(widths[i])
            if i == 0:
                text = _paint(text, row[0], color)
            cells.append(text)
        lines.append("  ".join(cells).rstrip())
    lines.append("")
    lines.append(_paint(_summary_line(findings), "ok" if not _has_urgent(findings) else "warn", color))
    return "\n".join(lines)


def _has_urgent(findings: Iterable[Finding]) -> bool:
    return any(f.priority and f.priority.code in {"P0", "P1"} for f in findings)


def _check_markdown(
    findings: Sequence[Finding], states: Sequence[SourceState], now: datetime | None
) -> str:
    lines = [
        f"# CVE triage — {len(findings)} identifier{'s' if len(findings) != 1 else ''}",
        "",
        f"_{_stamp(now)} · sources: {sources_line(states)}_",
        "",
        "| Priority | CVE | KEV | Due | EPSS | CVSS | Asset |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            "| {pri} | `{cve}` | {kev} | {due} | {epss} | {cvss} | {asset} |".format(
                pri=finding.priority.code if finding.priority else "—",
                cve=finding.cve_id,
                kev="yes" if finding.kev else "no",
                due=finding.kev.due_date if finding.kev else "—",
                epss=_pct(finding.epss_value),
                cvss=_cvss(finding),
                asset=finding.asset.replace("|", "\\|"),
            )
        )
    lines.append("")
    lines.append(f"**{_summary_line(findings)}**")
    lines.append("")

    actionable = [f for f in findings if f.priority and f.priority.code in {"P0", "P1"}]
    if actionable:
        lines.append("## Action items")
        lines.append("")
        for finding in actionable:
            lines.append(f"### {finding.priority.code} — {finding.cve_id}")
            lines.append("")
            if finding.title:
                lines.append(f"**{finding.title}**")
                lines.append("")
            lines.append(f"- Asset: {finding.asset}")
            if finding.kev:
                lines.append(
                    f"- CISA KEV: added {finding.kev.date_added}, federal due date {finding.kev.due_date}"
                    f"{', known ransomware use' if finding.kev.ransomware_known else ''}"
                )
            lines.append(
                f"- EPSS: {_pct(finding.epss_value)}"
                + (
                    f" (percentile {finding.epss.percentile * 100:.0f})"
                    if finding.epss and finding.epss.percentile is not None
                    else ""
                )
                + f" · CVSS: {_cvss(finding)} {finding.cvss.severity if finding.cvss else ''}".rstrip()
            )
            lines.append(f"- Action: {finding.priority.action}")
            if finding.kev and finding.kev.required_action:
                lines.append(f"- Required action (CISA): {finding.kev.required_action}")
            if finding.gaps:
                lines.append(f"- Data gaps: {', '.join(finding.gaps)}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _check_json(
    findings: Sequence[Finding], states: Sequence[SourceState], now: datetime | None
) -> str:
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for finding in findings:
        if finding.priority:
            counts[finding.priority.code] += 1
    document = {
        "tool": "kev-triage",
        "version": __version__,
        "command": "check",
        "generated_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds"),
        "sources": [state.to_dict() for state in states],
        "summary": {
            "total": len(findings),
            **counts,
            "kev_listed": sum(1 for finding in findings if finding.kev),
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# recent
# --------------------------------------------------------------------------
def render_recent(
    entries: Sequence[KevEntry],
    states: Sequence[SourceState],
    days: int,
    fmt: str = "table",
    *,
    color: bool = False,
    now: datetime | None = None,
) -> str:
    if fmt == "json":
        document = {
            "tool": "kev-triage",
            "version": __version__,
            "command": "recent",
            "generated_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds"),
            "days": days,
            "sources": [state.to_dict() for state in states],
            "count": len(entries),
            "entries": [
                {
                    "cve": entry.cve_id,
                    "vendor": entry.vendor,
                    "product": entry.product,
                    "name": entry.name,
                    "date_added": entry.date_added,
                    "due_date": entry.due_date,
                    "ransomware": entry.ransomware,
                    "required_action": entry.required_action,
                    "cwes": list(entry.cwes),
                }
                for entry in entries
            ],
        }
        return json.dumps(document, ensure_ascii=False, indent=2)

    if fmt == "markdown":
        lines = [
            f"# CISA KEV additions — last {days} day{'s' if days != 1 else ''}",
            "",
            f"_{_stamp(now)} · sources: {sources_line(states)} · {len(entries)} entries_",
            "",
            "| Added | CVE | Vendor | Product | Due | Ransomware |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for entry in entries:
            lines.append(
                f"| {entry.date_added} | `{entry.cve_id}` | {entry.vendor} | {entry.product} "
                f"| {entry.due_date} | {entry.ransomware or 'Unknown'} |"
            )
        lines.append("")
        return "\n".join(lines)

    header = ("ADDED", "CVE", "VENDOR / PRODUCT", "DUE", "RANSOMWARE")
    rows = [
        (
            entry.date_added,
            entry.cve_id,
            entry.asset,
            entry.due_date,
            entry.ransomware or "Unknown",
        )
        for entry in entries
    ]
    widths = [
        max(len(header[i]), *(len(str(row[i])) for row in rows)) if rows else len(header[i])
        for i in range(len(header))
    ]
    lines = [
        _paint(
            _stamp(now) + " · " + sources_line(states) + f" · {len(entries)} addition(s) in {days}d",
            "muted",
            color,
        ),
        "",
    ]
    lines.append("  ".join(header[i].ljust(widths[i]) for i in range(len(header))).rstrip())
    for row in rows:
        lines.append("  ".join(str(row[i]).ljust(widths[i]) for i in range(len(header))).rstrip())
    if not rows:
        lines.append(f"no CISA KEV additions in the last {days} days")
    return "\n".join(lines)


def priority_badge(priority: Priority | None) -> str:
    return priority.code if priority else "—"
