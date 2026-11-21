"""Environment-driven configuration.

Every endpoint can be overridden so the test suite (and air-gapped mirrors) can
point the tool at a local server without patching the code.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import __version__

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Cache lifetimes in seconds.
KEV_TTL = 6 * 60 * 60          # the KEV catalog changes a few times a day
EPSS_TTL = 6 * 60 * 60         # EPSS is rescored daily
NVD_TTL = 24 * 60 * 60         # CVSS rarely changes after a CVE is analysed

# NVD asks for at most 5 requests per 30s without an API key.
NVD_MIN_INTERVAL_ANONYMOUS = 6.0
NVD_MIN_INTERVAL_KEYED = 0.6
EPSS_BATCH_SIZE = 100


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def kev_url() -> str:
    return os.environ.get("KEV_TRIAGE_KEV_URL", DEFAULT_KEV_URL)


def epss_url() -> str:
    return os.environ.get("KEV_TRIAGE_EPSS_URL", DEFAULT_EPSS_URL)


def nvd_url() -> str:
    return os.environ.get("KEV_TRIAGE_NVD_URL", DEFAULT_NVD_URL)


def user_agent() -> str:
    return os.environ.get(
        "KEV_TRIAGE_USER_AGENT", f"kev-triage/{__version__} (+https://dohyeontech.github.io/tools/)"
    )


def timeout() -> float:
    return _env_float("KEV_TRIAGE_TIMEOUT", 30.0)


def nvd_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY") or os.environ.get("KEV_TRIAGE_NVD_API_KEY") or None


def nvd_min_interval() -> float:
    env = os.environ.get("KEV_TRIAGE_NVD_MIN_INTERVAL")
    if env:
        try:
            return float(env)
        except ValueError:
            pass
    return NVD_MIN_INTERVAL_KEYED if nvd_api_key() else NVD_MIN_INTERVAL_ANONYMOUS


def default_cache_dir() -> Path:
    override = os.environ.get("KEV_TRIAGE_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".cache"
    return root / "kev-triage"


def color_enabled() -> bool:
    return not os.environ.get("NO_COLOR")
