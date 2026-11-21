"""Wiring: fetch what each command needs and turn it into findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from . import cache as cache_module
from . import priority as priority_module
from . import sources
from .errors import SourceError, SourceUnavailable
from .model import Finding, KevEntry, SourceState


@dataclass
class TriageResult:
    findings: list[Finding] = field(default_factory=list)
    states: list[SourceState] = field(default_factory=list)
    catalog: sources.KevCatalog | None = None

    @property
    def degraded(self) -> bool:
        return any(state.degraded for state in self.states)


@dataclass
class RecentResult:
    entries: list[KevEntry] = field(default_factory=list)
    states: list[SourceState] = field(default_factory=list)
    days: int = 7


class TriageService:
    def __init__(
        self,
        *,
        cache_dir: Path | str | None = None,
        no_cache: bool = False,
        offline: bool = False,
        refresh: bool = False,
        use_nvd: bool = True,
    ) -> None:
        directory = None if no_cache else (cache_dir or _default_cache_dir())
        self.cache = cache_module.Cache(directory, enabled=not no_cache)
        self.offline = offline
        self.refresh = refresh
        self.use_nvd = use_nvd

    # -- commands --------------------------------------------------------
    def check(self, cve_ids: Sequence[str]) -> TriageResult:
        result = TriageResult()
        catalog: sources.KevCatalog | None = None

        try:
            catalog, state = sources.fetch_kev(
                self.cache, offline=self.offline, refresh=self.refresh
            )
            result.catalog = catalog
        except SourceError as exc:
            state = SourceState("kev", "unavailable", str(exc))
        result.states.append(state)

        epss_scores: dict = {}
        try:
            epss_scores, epss_state = sources.fetch_epss(
                self.cache, list(cve_ids), offline=self.offline, refresh=self.refresh
            )
        except SourceError as exc:
            epss_state = SourceState("epss", "unavailable", str(exc))
        result.states.append(epss_state)

        nvd = sources.NvdClient(
            self.cache, offline=self.offline, refresh=self.refresh
        )
        if not self.use_nvd:
            result.states.append(SourceState("nvd", "skipped", "--no-nvd"))

        nvd_states: list[SourceState] = []
        for cve_id in cve_ids:
            finding = Finding(cve_id=cve_id)
            if catalog is not None:
                finding.kev = catalog.get(cve_id)
            finding.epss = epss_scores.get(cve_id)

            if self.use_nvd:
                record, nvd_state = nvd.lookup(cve_id)
                nvd_states.append(nvd_state)
                if record.status == "found":
                    finding.cvss = record.cvss
                    finding.description = record.description
                    finding.published = record.published
                    finding.last_modified = record.last_modified
                else:
                    finding.gaps.append("NVD: CVE not found")

            if finding.kev is not None and not finding.description:
                finding.description = finding.kev.description
            priority_module.classify(finding)
            result.findings.append(finding)

        if self.use_nvd:
            result.states.append(_worst("nvd", nvd_states))

        result.findings.sort(key=lambda item: item.sort_key())

        if all(state.status == "unavailable" for state in result.states if state.status != "skipped"):
            raise SourceUnavailable("no data source is reachable")
        return result

    def recent(self, days: int = 7) -> RecentResult:
        catalog, state = sources.fetch_kev(
            self.cache, offline=self.offline, refresh=self.refresh
        )
        return RecentResult(entries=catalog.added_since(days), states=[state], days=days)


def _worst(name: str, states: Sequence[SourceState]) -> SourceState:
    if not states:
        return SourceState(name, "skipped", "")
    order = {"live": 0, "cache": 1, "skipped": 2, "stale": 3, "unavailable": 4}
    worst = max(states, key=lambda state: order.get(state.status, 9))
    live = sum(1 for state in states if state.status in {"live", "cache"})
    detail = f"{live}/{len(states)} lookups ok"
    if worst.detail and worst.status in {"stale", "unavailable"}:
        detail += f"; {worst.detail}"
    return SourceState(name, worst.status, detail, worst.age_seconds)


def _default_cache_dir() -> Path:
    from . import config

    return config.default_cache_dir()
