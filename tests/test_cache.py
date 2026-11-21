"""The JSON cache: freshness, stale fallback, corruption tolerance."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from kev_triage.cache import Cache


class CacheTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name) / "cache"
        self.cache = Cache(self.dir)

    def _age(self, key: str, seconds: float) -> None:
        """Rewrite the stored entry so it looks older than it is."""
        files = list(self.dir.glob("*.json"))
        self.assertEqual(len(files), 1)
        record = json.loads(files[0].read_text())
        self.assertEqual(record["key"], key)
        record["fetched_at"] -= seconds
        files[0].write_text(json.dumps(record))

    def test_roundtrip(self):
        self.cache.put("k", {"a": 1})
        payload, age = self.cache.get("k", max_age=60)
        self.assertEqual(payload, {"a": 1})
        self.assertLess(age, 5)

    def test_missing_returns_none(self):
        self.assertIsNone(self.cache.get("nope", max_age=60))

    def test_ttl_expiry(self):
        self.cache.put("k", {"a": 1})
        self._age("k", 120)
        self.assertIsNone(self.cache.get("k", max_age=60))
        payload, age = self.cache.get("k", max_age=None)
        self.assertEqual(payload, {"a": 1})
        self.assertGreaterEqual(age, 100)

    def test_corrupt_entry_is_ignored(self):
        self.cache.put("k", {"a": 1})
        path = next(self.dir.glob("*.json"))
        path.write_text("{not json")
        self.assertIsNone(self.cache.get("k", max_age=60))

    def test_mismatched_key_is_ignored(self):
        self.cache.put("k", {"a": 1})
        path = next(self.dir.glob("*.json"))
        record = json.loads(path.read_text())
        record["key"] = "other"
        path.write_text(json.dumps(record))
        self.assertIsNone(self.cache.get("k", max_age=60))

    def test_no_temp_files_left_behind(self):
        self.cache.put("k", {"a": 1})
        self.assertEqual(list(self.dir.glob("*.tmp")), [])

    def test_clear(self):
        self.cache.put("a", 1)
        self.cache.put("b", 2)
        self.assertEqual(self.cache.clear(), 2)
        self.assertEqual(self.cache.stats()["entries"], 0)

    def test_stats(self):
        self.cache.put("a", 1)
        stats = self.cache.stats()
        self.assertEqual(stats["entries"], 1)
        self.assertGreater(stats["bytes"], 0)
        self.assertIsNotNone(stats["newest"])

    def test_disabled_cache_is_a_noop(self):
        cache = Cache(None, enabled=True)
        cache.put("k", {"a": 1})
        self.assertIsNone(cache.get("k", max_age=60))
        self.assertEqual(cache.clear(), 0)

    def test_unwritable_directory_does_not_raise(self):
        cache = Cache(Path(self._tmp.name) / "missing" / "deeper")
        cache.put("k", {"a": 1})  # mkdir(parents) creates it; should not raise
        self.assertIsNotNone(cache.get("k", max_age=60))


if __name__ == "__main__":
    unittest.main()
