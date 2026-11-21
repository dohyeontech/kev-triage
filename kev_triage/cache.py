"""A tiny JSON file cache with TTL and stale fallback.

The cache is deliberately boring: one file per key, atomic replace, and every
failure is non-fatal. A read-only or full disk must never stop a triage run.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, directory: Path | str | None, enabled: bool = True) -> None:
        self.directory = Path(directory).expanduser() if directory else None
        self.enabled = enabled and self.directory is not None

    # -- helpers ---------------------------------------------------------
    def _path(self, key: str) -> Path | None:
        if not self.enabled or self.directory is None:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"{digest}.json"

    def _read(self, key: str) -> tuple[Any, float] | None:
        path = self._path(key)
        if path is None or not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as fh:
                record = json.load(fh)
            if record.get("key") != key:
                return None
            fetched_at = float(record["fetched_at"])
            return record["payload"], max(0.0, time.time() - fetched_at)
        except (OSError, ValueError, KeyError, TypeError):
            return None

    # -- public API ------------------------------------------------------
    def get(self, key: str, max_age: float | None) -> tuple[Any, float] | None:
        """Return (payload, age_seconds) when the entry is fresh enough.

        ``max_age=None`` means "any age" (used for stale fallback).
        """
        found = self._read(key)
        if found is None:
            return None
        payload, age = found
        if max_age is not None and age > max_age:
            return None
        return payload, age

    def put(self, key: str, payload: Any) -> None:
        path = self._path(key)
        if path is None:
            return
        record = {"key": key, "fetched_at": time.time(), "payload": payload}
        try:
            self.directory.mkdir(parents=True, exist_ok=True)  # type: ignore[union-attr]
            fd, tmp = tempfile.mkstemp(dir=str(self.directory), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(record, fh)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        except OSError:
            return

    def clear(self) -> int:
        if not self.enabled or self.directory is None or not self.directory.exists():
            return 0
        removed = 0
        for item in self.directory.glob("*.json"):
            try:
                item.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def stats(self) -> dict[str, Any]:
        files = sorted(self.directory.glob("*.json")) if self.directory and self.directory.exists() else []
        size = 0
        newest = None
        for item in files:
            try:
                stat = item.stat()
            except OSError:
                continue
            size += stat.st_size
            newest = stat.st_mtime if newest is None else max(newest, stat.st_mtime)
        return {
            "directory": str(self.directory) if self.directory else None,
            "enabled": self.enabled,
            "entries": len(files),
            "bytes": size,
            "newest": newest,
        }
