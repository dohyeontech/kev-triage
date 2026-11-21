"""Exception types used across kev-triage."""

from __future__ import annotations


class KevTriageError(Exception):
    """Base class for errors this tool raises on purpose."""


class InputError(KevTriageError):
    """The caller supplied something unusable (bad CVE ID, empty file, ...)."""


class SourceError(KevTriageError):
    """A data source could not be reached or returned unusable data."""


class SourceNotFound(SourceError):
    """The source answered definitively that the item does not exist."""


class SourceUnavailable(SourceError):
    """No live data and nothing usable in the cache."""
