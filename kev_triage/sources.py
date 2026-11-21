"""Live data sources: CISA KEV, FIRST EPSS and NVD CVE API.

Every fetch is cache-first. When the network fails and a cached copy exists the
call succeeds with a ``stale`` source state, so a triage run degrades instead of
dying.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Iterable, Sequence

from . import config
from .cache import Cache
from .errors import SourceError, SourceNotFound, SourceUnavailable
from .model import CvssScore, EpssScore, KevEntry, SourceState, parse_iso_date


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def http_get_json(
    url: str,
    *,
    timeout: float | None = None,
    retries: int = 2,
    headers: dict[str, str] | None = None,
) -> Any:
    timeout = timeout or config.timeout()
    request_headers = {
        "User-Agent": config.user_agent(),
        "Accept": "application/json",
    }
    if headers:
        request_headers.update(headers)

    delay = 1.0
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
            return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code == 404:
                raise SourceNotFound(f"HTTP 404 from {_host(url)}") from exc
            retryable = exc.code in (408, 425, 429, 500, 502, 503, 504)
            if not retryable or attempt == retries:
                raise SourceError(f"HTTP {exc.code} from {_host(url)}") from exc
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            wait = delay
            if retry_after and retry_after.isdigit():
                wait = min(float(retry_after), 30.0)
            time.sleep(wait)
            delay *= 2
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            last_error = exc
            if attempt == retries:
                raise SourceError(f"cannot reach {_host(url)}: {exc}") from exc
            time.sleep(delay)
            delay *= 2
        except json.JSONDecodeError as exc:
            raise SourceError(f"invalid JSON from {_host(url)}") from exc
    raise SourceError(f"cannot reach {_host(url)}: {last_error}")


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc or url


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------
@dataclass
class KevCatalog:
    entries: dict[str, KevEntry]
    catalog_version: str = ""
    date_released: str = ""
    count: int = 0

    def get(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id.upper())

    def added_since(self, days: int, today: date | None = None) -> list[KevEntry]:
        """Entries whose ``dateAdded`` falls in the last ``days`` days (inclusive)."""
        today = today or date.today()
        cutoff = today - timedelta(days=max(0, days) - 1)
        found = []
        for entry in self.entries.values():
            added = parse_iso_date(entry.date_added)
            if added is not None and cutoff <= added <= today:
                found.append(entry)
        found.sort(key=lambda item: (item.date_added, item.cve_id), reverse=True)
        return found


def _parse_kev_payload(payload: dict[str, Any]) -> KevCatalog:
    entries: dict[str, KevEntry] = {}
    for raw in payload.get("vulnerabilities") or []:
        cve_id = str(raw.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor=str(raw.get("vendorProject") or "").strip(),
            product=str(raw.get("product") or "").strip(),
            name=str(raw.get("vulnerabilityName") or "").strip(),
            date_added=str(raw.get("dateAdded") or "").strip(),
            due_date=str(raw.get("dueDate") or "").strip(),
            required_action=str(raw.get("requiredAction") or "").strip(),
            ransomware=str(raw.get("knownRansomwareCampaignUse") or "").strip(),
            description=str(raw.get("shortDescription") or "").strip(),
            cwes=tuple(str(c) for c in (raw.get("cwes") or []) if c),
        )
    return KevCatalog(
        entries=entries,
        catalog_version=str(payload.get("catalogVersion") or ""),
        date_released=str(payload.get("dateReleased") or ""),
        count=int(payload.get("count") or len(entries)),
    )


def fetch_kev(
    cache: Cache,
    *,
    offline: bool = False,
    refresh: bool = False,
) -> tuple[KevCatalog, SourceState]:
    # One catalog per cache, whatever endpoint served it (each catalog is
    # self-describing through catalogVersion).
    key = "kev:catalog"

    if not refresh:
        cached = cache.get(key, config.KEV_TTL)
        if cached is not None:
            payload, age = cached
            catalog = _parse_kev_payload(payload)
            return catalog, SourceState(
                "kev", "cache", f"catalog {catalog.catalog_version}", age
            )

    if offline:
        stale = cache.get(key, None)
        if stale is not None:
            payload, age = stale
            catalog = _parse_kev_payload(payload)
            return catalog, SourceState("kev", "stale", f"offline, catalog {catalog.catalog_version}", age)
        raise SourceUnavailable("CISA KEV is not cached and --offline was given")

    try:
        payload = http_get_json(config.kev_url())
        if not isinstance(payload, dict) or "vulnerabilities" not in payload:
            raise SourceError("CISA KEV returned an unexpected payload")
        catalog = _parse_kev_payload(payload)
        cache.put(key, payload)
        return catalog, SourceState("kev", "live", f"catalog {catalog.catalog_version}", 0.0)
    except SourceError as exc:
        stale = cache.get(key, None)
        if stale is not None:
            old_payload, age = stale
            catalog = _parse_kev_payload(old_payload)
            return catalog, SourceState(
                "kev", "stale", f"{exc}; using catalog {catalog.catalog_version}", age
            )
        raise


# --------------------------------------------------------------------------
# FIRST EPSS
# --------------------------------------------------------------------------
def fetch_epss(
    cache: Cache,
    cve_ids: Sequence[str],
    *,
    offline: bool = False,
    refresh: bool = False,
) -> tuple[dict[str, EpssScore], SourceState]:
    scores: dict[str, EpssScore] = {}
    states: list[SourceState] = []
    failures: list[str] = []

    for chunk in _chunks(list(dict.fromkeys(cve_ids)), config.EPSS_BATCH_SIZE):
        key = "epss:" + ",".join(sorted(chunk))
        records: dict[str, Any] | None = None

        if not refresh:
            cached = cache.get(key, config.EPSS_TTL)
            if cached is not None:
                payload, age = cached
                records = {score.cve_id: score for score in _parse_epss_payload(payload)}
                states.append(SourceState("epss", "cache", f"{len(chunk)} CVE(s)", age))

        if records is None and offline:
            stale = cache.get(key, None)
            if stale is not None:
                payload, age = stale
                records = {score.cve_id: score for score in _parse_epss_payload(payload)}
                states.append(SourceState("epss", "stale", f"offline, {len(chunk)} CVE(s)", age))
            else:
                failures.append("offline and not cached")
                records = {}

        if records is None:
            query = urllib.parse.urlencode({"cve": ",".join(chunk)}, safe=",")
            url = f"{config.epss_url()}?{query}"
            try:
                payload = http_get_json(url)
                parsed = _parse_epss_payload(payload)
                records = {score.cve_id: score for score in parsed}
                cache.put(key, payload)
                states.append(SourceState("epss", "live", f"{len(chunk)} CVE(s)", 0.0))
            except SourceError as exc:
                stale = cache.get(key, None)
                if stale is not None:
                    payload, age = stale
                    records = {score.cve_id: score for score in _parse_epss_payload(payload)}
                    states.append(SourceState("epss", "stale", f"{exc}; {len(chunk)} CVE(s)", age))
                else:
                    failures.append(str(exc))
                    records = {}

        scores.update(records)

    if not states:
        detail = failures[0] if failures else "no data"
        raise SourceError(f"EPSS unavailable ({detail})")
    state = _merge_states("epss", states)
    if failures and not scores:
        state = SourceState("epss", "unavailable", failures[0])
    return scores, state


def _parse_epss_payload(payload: Any) -> list[EpssScore]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("data") or []
    else:
        return []
    out: list[EpssScore] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve_id = str(row.get("cve") or "").strip().upper()
        try:
            score = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        percentile: float | None
        try:
            percentile = float(row["percentile"]) if row.get("percentile") is not None else None
        except (TypeError, ValueError):
            percentile = None
        if cve_id:
            out.append(
                EpssScore(
                    cve_id=cve_id,
                    epss=score,
                    percentile=percentile,
                    date=str(row.get("date") or ""),
                )
            )
    return out


def _chunks(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _merge_states(name: str, states: Sequence[SourceState]) -> SourceState:
    order = {"live": 0, "cache": 1, "skipped": 2, "stale": 3, "unavailable": 4}
    worst = max(states, key=lambda state: order.get(state.status, 9))
    newest_age = None
    for state in states:
        if state.age_seconds is not None:
            newest_age = state.age_seconds if newest_age is None else min(newest_age, state.age_seconds)
    detail = worst.detail
    if len(states) > 1:
        detail = f"{len(states)} batches; {detail}"
    return SourceState(name, worst.status, detail, newest_age)


# --------------------------------------------------------------------------
# NVD CVE API (CVSS)
# --------------------------------------------------------------------------
@dataclass
class NvdRecord:
    cve_id: str
    cvss: CvssScore | None = None
    description: str = ""
    published: str = ""
    last_modified: str = ""
    status: str = "found"  # found | not_found


class NvdClient:
    """NVD 2.0 lookups, rate limited to what the API allows.

    Without an API key NVD permits 5 requests per 30 seconds, so the client
    spaces calls by ``min_interval`` seconds. Answers are cached for a day.
    """

    def __init__(
        self,
        cache: Cache,
        *,
        offline: bool = False,
        refresh: bool = False,
        min_interval: float | None = None,
    ) -> None:
        self.cache = cache
        self.offline = offline
        self.refresh = refresh
        self.min_interval = config.nvd_min_interval() if min_interval is None else min_interval
        self._last_call = 0.0
        self._used_network = 0

    # -- public ----------------------------------------------------------
    def lookup(self, cve_id: str) -> tuple[NvdRecord, SourceState]:
        key = f"nvd:{cve_id}"
        if not self.refresh:
            cached = self.cache.get(key, config.NVD_TTL)
            if cached is not None:
                payload, age = cached
                return _nvd_record(cve_id, payload), SourceState("nvd", "cache", "cached", age)

        if self.offline:
            stale = self.cache.get(key, None)
            if stale is not None:
                payload, age = stale
                return _nvd_record(cve_id, payload), SourceState("nvd", "stale", "offline", age)
            return (
                NvdRecord(cve_id, status="not_found"),
                SourceState("nvd", "unavailable", "offline and not cached"),
            )

        self._respect_rate_limit()
        url = f"{config.nvd_url()}?{urllib.parse.urlencode({'cveId': cve_id})}"
        headers = {}
        api_key = config.nvd_api_key()
        if api_key:
            headers["apiKey"] = api_key
        try:
            payload = http_get_json(url, headers=headers)
        except SourceNotFound:
            return (
                NvdRecord(cve_id, status="not_found"),
                SourceState("nvd", "live", "not found in NVD", 0.0),
            )
        except SourceError as exc:
            stale = self.cache.get(key, None)
            if stale is not None:
                old, age = stale
                return _nvd_record(cve_id, old), SourceState("nvd", "stale", str(exc), age)
            return NvdRecord(cve_id, status="not_found"), SourceState("nvd", "unavailable", str(exc))

        self._used_network += 1
        record = _nvd_record(cve_id, payload)
        if record.status == "found":
            self.cache.put(key, payload)
        return record, SourceState("nvd", "live", "fetched", 0.0)

    # -- internals -------------------------------------------------------
    def _respect_rate_limit(self) -> None:
        if self.min_interval <= 0:
            self._last_call = time.monotonic()
            return
        if self._used_network:
            elapsed = time.monotonic() - self._last_call
            remaining = self.min_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self._last_call = time.monotonic()


def _nvd_record(cve_id: str, payload: Any) -> NvdRecord:
    if not isinstance(payload, dict):
        return NvdRecord(cve_id, status="not_found")
    items = payload.get("vulnerabilities") or []
    if not items:
        return NvdRecord(cve_id, status="not_found")
    cve = items[0].get("cve") or {}
    description = ""
    for row in cve.get("descriptions") or []:
        if row.get("lang") == "en":
            description = str(row.get("value") or "")
            break
    if not description and cve.get("descriptions"):
        description = str(cve["descriptions"][0].get("value") or "")
    return NvdRecord(
        cve_id=str(cve.get("id") or cve_id),
        cvss=_extract_cvss(cve.get("metrics") or {}),
        description=description,
        published=str(cve.get("published") or ""),
        last_modified=str(cve.get("lastModified") or ""),
        status="found",
    )


_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _extract_cvss(metrics: dict[str, Any]) -> CvssScore | None:
    for key, version in _METRIC_KEYS:
        rows = metrics.get(key) or []
        if not rows:
            continue
        chosen = next((row for row in rows if row.get("type") == "Primary"), rows[0])
        data = chosen.get("cvssData") or {}
        try:
            score = float(data.get("baseScore"))
        except (TypeError, ValueError):
            continue
        severity = str(data.get("baseSeverity") or chosen.get("baseSeverity") or "").upper()
        return CvssScore(
            score=score,
            severity=severity or _severity_for(score),
            version=str(data.get("version") or version),
            vector=str(data.get("vectorString") or ""),
        )
    return None


def _severity_for(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
