"""CVE identifier handling: normalisation and extraction from free text."""

from __future__ import annotations

import re

from .errors import InputError

# CVE-<year>-<sequence>: 4 to 7 digits is what MITRE assigns today.
_CVE_RE = re.compile(r"\b[Cc][Vv][Ee]-(\d{4})-(\d{4,7})\b")
_BARE_RE = re.compile(r"^\s*(\d{4})-(\d{4,7})\s*$")


def normalize(value: str) -> str:
    """Return the canonical ``CVE-YYYY-NNNN`` form or raise InputError."""
    text = (value or "").strip()
    match = _CVE_RE.search(text)
    if match is None:
        bare = _BARE_RE.match(text)
        if bare is None:
            raise InputError(f"not a CVE identifier: {value!r}")
        year, seq = bare.groups()
    else:
        year, seq = match.groups()
    return f"CVE-{year}-{seq}"


def looks_like_cve(value: str) -> bool:
    try:
        normalize(value)
    except InputError:
        return False
    return True


def extract(text: str) -> list[str]:
    """Pull every unique CVE ID out of free text, in first-appearance order."""
    seen: dict[str, None] = {}
    for match in _CVE_RE.finditer(text or ""):
        seen.setdefault(f"CVE-{match.group(1)}-{match.group(2)}", None)
    return list(seen)
