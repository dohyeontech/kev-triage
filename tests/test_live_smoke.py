"""Smoke test against the real CISA KEV and FIRST EPSS endpoints.

Skipped by default so the suite stays hermetic and fast. Run it before a
release, or whenever you need to know the upstream APIs still answer:

    KEV_TRIAGE_LIVE=1 python3 -m unittest tests.test_live_smoke -v
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from kev_triage import config, sources
from kev_triage.cache import Cache

from .support import isolated_env

LIVE = os.environ.get("KEV_TRIAGE_LIVE") == "1"


@unittest.skipUnless(LIVE, "set KEV_TRIAGE_LIVE=1 to hit the real APIs")
class LiveSmokeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        env = isolated_env(KEV_TRIAGE_CACHE_DIR=str(Path(self._tmp.name) / "cache"))
        env.__enter__()
        self.addCleanup(env.__exit__, None, None, None)
        self.cache = Cache(config.default_cache_dir())

    def test_kev_catalog_is_reachable_and_parseable(self):
        catalog, state = sources.fetch_kev(self.cache)
        self.assertIn(state.status, {"live", "cache"})
        self.assertGreater(len(catalog.entries), 500)
        self.assertTrue(catalog.catalog_version)
        # Log4Shell has been in KEV since December 2021 and will not leave it.
        self.assertIn("CVE-2021-44228", catalog.entries)

    def test_epss_returns_a_score_for_one_known_cve(self):
        scores, state = sources.fetch_epss(self.cache, ["CVE-2021-44228"])
        self.assertIn(state.status, {"live", "cache"})
        self.assertIn("CVE-2021-44228", scores)
        self.assertGreaterEqual(scores["CVE-2021-44228"].epss, 0.0)
        self.assertLessEqual(scores["CVE-2021-44228"].epss, 1.0)

    def test_nvd_returns_cvss_for_one_known_cve(self):
        client = sources.NvdClient(self.cache, min_interval=0)
        record, state = client.lookup("CVE-2021-44228")
        self.assertEqual(record.status, "found")
        self.assertIsNotNone(record.cvss)
        self.assertGreaterEqual(record.cvss.score, 0.0)


if __name__ == "__main__":
    unittest.main()
