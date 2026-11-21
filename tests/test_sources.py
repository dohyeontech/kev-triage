"""Source parsing, caching and failure behaviour against a mock HTTP server."""

from __future__ import annotations

import contextlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from kev_triage import config, sources
from kev_triage.cache import Cache
from kev_triage.errors import SourceError, SourceNotFound, SourceUnavailable

from .support import (
    MockServer,
    epss_router,
    fixture,
    isolated_env,
    json_route,
    nvd_router,
)

V40_PAYLOAD = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-77777",
                "published": "2026-11-01T10:00:00.000",
                "lastModified": "2026-11-02T10:00:00.000",
                "descriptions": [
                    {"lang": "es", "value": "texto"},
                    {"lang": "en", "value": "Synthetic CVSS 4.0 record for tests."},
                ],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "version": "4.0",
                                "baseScore": 9.2,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                            },
                        }
                    ]
                },
            }
        }
    ],
}

NVD_ROUTES = {
    "CVE-2026-123890": fixture("nvd_cve_vc.json"),
    "CVE-2026-40217": fixture("nvd_cve_litellm.json"),
    "CVE-2026-77777": json.dumps(V40_PAYLOAD).encode(),
    "CVE-2026-88888": fixture("nvd_empty.json"),
}


class SourceTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cache = Cache(Path(self._tmp.name) / "cache")

    def fast_retries(self):
        """Skip the retry backoff sleeps in failure-path tests."""
        return mock.patch.object(sources.time, "sleep")

    def routes(self):
        return {
            "/kev": json_route(fixture("kev_catalog.json")),
            "/epss": epss_router(),
            "/nvd": nvd_router(NVD_ROUTES),
        }

    @contextlib.contextmanager
    def serve(self, routes=None):
        with MockServer(routes or self.routes()) as server:
            with isolated_env(
                KEV_TRIAGE_KEV_URL=server.url("/kev"),
                KEV_TRIAGE_EPSS_URL=server.url("/epss"),
                KEV_TRIAGE_NVD_URL=server.url("/nvd"),
            ):
                yield server


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------
class KevTests(SourceTestCase):
    def test_live_fetch_parses_catalog(self):
        with self.serve() as server:
            catalog, state = sources.fetch_kev(self.cache)
            self.assertEqual(state.status, "live")
            self.assertIn("2026.11.20", state.detail)
            self.assertEqual(len(server.requests), 1)

        self.assertEqual(catalog.catalog_version, "2026.11.20")
        entry = catalog.get("CVE-2026-123890")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.vendor, "Broadcom")
        self.assertEqual(entry.product, "VMware vCenter")
        self.assertEqual(entry.date_added, "2026-11-20")
        self.assertEqual(entry.due_date, "2026-11-23")
        self.assertEqual(entry.asset, "Broadcom VMware vCenter")
        self.assertTrue(entry.required_action)
        self.assertIn("CWE", " ".join(entry.cwes) or "CWE")

        log4j = catalog.get("CVE-2021-44228")
        self.assertTrue(log4j.ransomware_known)

    def test_lookup_is_case_insensitive_and_unknown_returns_none(self):
        with self.serve():
            catalog, _ = sources.fetch_kev(self.cache)
        self.assertIsNotNone(catalog.get("cve-2026-123890"))
        self.assertIsNone(catalog.get("CVE-2099-00001"))

    def test_second_call_hits_cache(self):
        with self.serve() as server:
            sources.fetch_kev(self.cache)
            catalog, state = sources.fetch_kev(self.cache)
            self.assertEqual(state.status, "cache")
            self.assertEqual(len(server.requests), 1)
        self.assertEqual(len(catalog.entries), 3)

    def test_refresh_forces_a_new_request(self):
        with self.serve() as server:
            sources.fetch_kev(self.cache)
            _, state = sources.fetch_kev(self.cache, refresh=True)
            self.assertEqual(state.status, "live")
            self.assertEqual(len(server.requests), 2)

    def test_failure_falls_back_to_stale_cache(self):
        with self.serve() as server:
            sources.fetch_kev(self.cache)
            url = server.url("/kev")
        with isolated_env(KEV_TRIAGE_KEV_URL=url), self.fast_retries():
            catalog, state = sources.fetch_kev(self.cache, refresh=True)
        self.assertEqual(state.status, "stale")
        self.assertEqual(len(catalog.entries), 3)
        self.assertIsNotNone(state.age_seconds)

    def test_offline_uses_cache_only(self):
        with self.serve():
            sources.fetch_kev(self.cache)
        with isolated_env():
            catalog, state = sources.fetch_kev(self.cache, offline=True, refresh=True)
        self.assertEqual(state.status, "stale")
        self.assertIn("offline", state.detail)
        self.assertEqual(len(catalog.entries), 3)

    def test_offline_without_cache_raises(self):
        with isolated_env():
            with self.assertRaises(SourceUnavailable):
                sources.fetch_kev(self.cache, offline=True)

    def test_unexpected_payload_raises(self):
        routes = {"kev": json_route({"hello": "world"})}
        with MockServer({"/kev": routes["kev"]}) as server:
            with isolated_env(KEV_TRIAGE_KEV_URL=server.url("/kev")):
                with self.assertRaises(SourceError):
                    sources.fetch_kev(self.cache)

    def test_added_since_window(self):
        with self.serve():
            catalog, _ = sources.fetch_kev(self.cache)
        from datetime import date

        recent = catalog.added_since(7, today=date(2026, 11, 21))
        ids = {entry.cve_id for entry in recent}
        self.assertIn("CVE-2026-123890", ids)   # added 2026-11-20
        self.assertNotIn("CVE-2021-44228", ids)  # added 2021
        days = [entry.date_added for entry in recent]
        self.assertEqual(days, sorted(days, reverse=True))

    def test_added_since_window_includes_both_additions(self):
        with self.serve():
            catalog, _ = sources.fetch_kev(self.cache)
        from datetime import date

        window = catalog.added_since(4, today=date(2026, 11, 21))
        ids = {entry.cve_id for entry in window}
        self.assertIn("CVE-2026-123890", ids)
        self.assertIn("CVE-2026-40217", ids)
        self.assertTrue(all(entry.date_added >= "2026-11-18" for entry in window))

    def test_added_since_one_day_is_today_only(self):
        with self.serve():
            catalog, _ = sources.fetch_kev(self.cache)
        from datetime import date

        self.assertEqual(catalog.added_since(1, today=date(2026, 11, 21)), [])


# --------------------------------------------------------------------------
# EPSS
# --------------------------------------------------------------------------
class EpssTests(SourceTestCase):
    def test_lookup_parses_scores(self):
        with self.serve():
            scores, state = sources.fetch_epss(self.cache, ["CVE-2026-40217", "CVE-2026-123890"])
        self.assertEqual(state.status, "live")
        self.assertAlmostEqual(scores["CVE-2026-40217"].epss, 0.68902, places=5)
        self.assertAlmostEqual(scores["CVE-2026-40217"].percentile, 0.99365, places=5)
        self.assertEqual(scores["CVE-2026-40217"].date, "2026-11-20")
        self.assertIn("CVE-2026-123890", scores)

    def test_unknown_cve_yields_no_score(self):
        with self.serve():
            scores, state = sources.fetch_epss(self.cache, ["CVE-2099-99999"])
        self.assertEqual(scores, {})
        self.assertEqual(state.status, "live")

    def test_cache_is_keyed_by_the_batch(self):
        with self.serve() as server:
            sources.fetch_epss(self.cache, ["CVE-2026-40217"])
            sources.fetch_epss(self.cache, ["CVE-2026-40217"])
            self.assertEqual(len(server.requests), 1)
            scores, state = sources.fetch_epss(self.cache, ["CVE-2026-40217", "CVE-2026-123890"])
            self.assertEqual(state.status, "live")
            self.assertEqual(len(server.requests), 2)

    def test_batching_splits_requests(self):
        with mock.patch.object(config, "EPSS_BATCH_SIZE", 1):
            with self.serve() as server:
                scores, state = sources.fetch_epss(
                    self.cache, ["CVE-2026-40217", "CVE-2026-123890"]
                )
                self.assertEqual(len(server.requests), 2)
        self.assertEqual(state.status, "live")
        self.assertIn("2 batches", state.detail)
        self.assertEqual(len(scores), 2)

    def test_stale_on_failure(self):
        with self.serve() as server:
            sources.fetch_epss(self.cache, ["CVE-2026-40217"])
            url = server.url("/epss")
        with isolated_env(KEV_TRIAGE_EPSS_URL=url), self.fast_retries():
            scores, state = sources.fetch_epss(self.cache, ["CVE-2026-40217"], refresh=True)
        self.assertEqual(state.status, "stale")
        self.assertIn("CVE-2026-40217", scores)

    def test_offline_without_cache_raises(self):
        with isolated_env():
            with self.assertRaises(SourceError):
                sources.fetch_epss(self.cache, ["CVE-2026-40217"], offline=True)


# --------------------------------------------------------------------------
# NVD
# --------------------------------------------------------------------------
class NvdTests(SourceTestCase):
    def client(self, **kwargs):
        return sources.NvdClient(self.cache, min_interval=0, **kwargs)

    def test_v31_metric(self):
        with self.serve():
            record, state = self.client().lookup("CVE-2026-123890")
        self.assertEqual(state.status, "live")
        self.assertEqual(record.status, "found")
        self.assertIsNotNone(record.cvss)
        self.assertEqual(record.cvss.score, 9.8)
        self.assertEqual(record.cvss.severity, "CRITICAL")
        self.assertEqual(record.cvss.version, "3.1")
        self.assertTrue(record.cvss.vector.startswith("CVSS:3.1/"))
        self.assertIn("vCenter", record.description)
        self.assertTrue(record.published.startswith("2026-11-19"))

    def test_v40_metric_preferred(self):
        with self.serve():
            record, _ = self.client().lookup("CVE-2026-77777")
        self.assertEqual(record.cvss.version, "4.0")
        self.assertEqual(record.cvss.score, 9.2)
        self.assertEqual(record.description, "Synthetic CVSS 4.0 record for tests.")

    def test_404_is_reported_as_not_found(self):
        with self.serve():
            record, state = self.client().lookup("CVE-2099-99999")
        self.assertEqual(record.status, "not_found")
        self.assertIsNone(record.cvss)
        self.assertEqual(state.status, "live")

    def test_empty_result_is_not_found(self):
        with self.serve():
            record, _ = self.client().lookup("CVE-2026-88888")
        self.assertEqual(record.status, "not_found")

    def test_second_lookup_uses_cache(self):
        with self.serve() as server:
            client = self.client()
            client.lookup("CVE-2026-123890")
            record, state = client.lookup("CVE-2026-123890")
            self.assertEqual(state.status, "cache")
            self.assertEqual(len(server.requests), 1)
        self.assertEqual(record.cvss.score, 9.8)

    def test_failure_without_cache_is_unavailable(self):
        with self.serve() as server:
            url = server.url("/nvd")
        with isolated_env(KEV_TRIAGE_NVD_URL=url), self.fast_retries():
            record, state = self.client().lookup("CVE-2026-123890")
        self.assertEqual(record.status, "not_found")
        self.assertEqual(state.status, "unavailable")

    def test_rate_limit_spaces_requests(self):
        with self.serve():
            client = sources.NvdClient(self.cache, min_interval=0.25)
            client.lookup("CVE-2026-123890")
            started = time.monotonic()
            client.lookup("CVE-2026-40217")
            elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.2)

    def test_offline_lookup_is_not_found(self):
        with isolated_env():
            record, state = self.client(offline=True).lookup("CVE-2026-123890")
        self.assertEqual(record.status, "not_found")
        self.assertEqual(state.status, "unavailable")


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------
class HttpTests(SourceTestCase):
    def test_404_raises_source_not_found(self):
        with MockServer({}) as server:
            with self.assertRaises(SourceNotFound):
                sources.http_get_json(server.url("/nothing"))

    def test_retries_then_succeeds(self):
        calls = []

        def route(_path):
            calls.append(1)
            if len(calls) == 1:
                return 503, b'{"error":"busy"}', {}
            return 200, b'{"ok":true}', {}

        with MockServer({"/flaky": route}) as server:
            with mock.patch.object(sources.time, "sleep") as sleeper:
                payload = sources.http_get_json(server.url("/flaky"))
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(len(calls), 2)
        sleeper.assert_called_once()

    def test_retry_after_header_is_honoured(self):
        calls = []

        def route(_path):
            calls.append(1)
            if len(calls) == 1:
                return 429, b'{"error":"slow down"}', {"Retry-After": "0"}
            return 200, b'{"ok":true}', {}

        with MockServer({"/limited": route}) as server:
            payload = sources.http_get_json(server.url("/limited"))
        self.assertEqual(payload, {"ok": True})

    def test_gives_up_after_retries(self):
        with MockServer({"/down": json_route({"e": 1}, status=500)}) as server:
            with mock.patch.object(sources.time, "sleep"):
                with self.assertRaises(SourceError):
                    sources.http_get_json(server.url("/down"))

    def test_invalid_json_raises(self):
        with MockServer({"/html": json_route(b"<html>nope</html>")}) as server:
            with self.assertRaises(SourceError):
                sources.http_get_json(server.url("/html"))


if __name__ == "__main__":
    unittest.main()
