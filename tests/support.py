"""Test support: a throwaway HTTP server and environment isolation.

The tests never touch the real CISA/EPSS/NVD endpoints (except the opt-in live
smoke test). Instead they point kev-triage at a local server through the same
environment variables a real deployment would use.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

FIXTURES = Path(__file__).parent / "fixtures"

ENV_KEYS = (
    "KEV_TRIAGE_KEV_URL",
    "KEV_TRIAGE_EPSS_URL",
    "KEV_TRIAGE_NVD_URL",
    "KEV_TRIAGE_CACHE_DIR",
    "KEV_TRIAGE_NVD_MIN_INTERVAL",
    "KEV_TRIAGE_TIMEOUT",
    "KEV_TRIAGE_USER_AGENT",
    "NVD_API_KEY",
    "KEV_TRIAGE_NVD_API_KEY",
    "NO_COLOR",
)

Route = "tuple[int, bytes, dict[str, str]] | Callable[[str], tuple[int, bytes, dict[str, str]]]"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_json(name: str):
    return json.loads((FIXTURES / name).read_text())


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):  # noqa: N802 (http.server naming)
        server: "MockServer" = self.server  # type: ignore[assignment]
        server.requests.append(self.path)
        route = server.route_for(self.path)
        if callable(route):
            status, body, headers = route(self.path)
        else:
            status, body, headers = route
        if server.delay:
            time.sleep(server.delay)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        return


class MockServer:
    """Serves canned responses per path; also usable as a context manager."""

    def __init__(self, routes: dict[str, Route], delay: float = 0.0) -> None:
        self.routes = routes
        self.requests: list[str] = []
        self.delay = delay
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.route_for = self.route_for  # type: ignore[attr-defined]
        self.httpd.requests = self.requests  # type: ignore[attr-defined]
        self.httpd.delay = delay  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True)

    # -- lifecycle -------------------------------------------------------
    def __enter__(self) -> "MockServer":
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    # -- routing ---------------------------------------------------------
    def route_for(self, raw_path: str):
        path = urlsplit(raw_path).path
        if path in self.routes:
            return self.routes[path]
        return 404, b'{"error": "no route"}', {}

    @property
    def base(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}"

    def url(self, path: str) -> str:
        return f"{self.base}{path}"


def json_route(payload: bytes | str | dict, status: int = 200, headers: dict | None = None):
    if isinstance(payload, dict):
        body = json.dumps(payload).encode("utf-8")
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = payload
    return (status, body, headers or {})


def nvd_router(cves: dict[str, bytes]):
    """Answer NVD lookups by ?cveId=."""

    def route(raw_path: str):
        query = parse_qs(urlsplit(raw_path).query)
        cve_id = (query.get("cveId") or [""])[0]
        body = cves.get(cve_id)
        if body is None:
            return 404, b'{"message": "not found"}', {}
        return 200, body, {}

    return route


def epss_router():
    """Answer EPSS lookups for whatever CVEs are asked for, from the fixture."""

    def route(raw_path: str):
        query = parse_qs(urlsplit(raw_path).query)
        wanted = set((query.get("cve") or [""])[0].split(","))
        data = fixture_json("epss_scores.json")
        rows = [row for row in data["data"] if row["cve"] in wanted]
        return 200, json.dumps({"status": "OK", "data": rows}).encode(), {}

    return route


@contextlib.contextmanager
def isolated_env(**overrides):
    """Run with a private cache dir and the given KEV_TRIAGE_* overrides."""
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp) / "cache"
        os.environ["KEV_TRIAGE_CACHE_DIR"] = str(cache_dir)
        os.environ["KEV_TRIAGE_NVD_MIN_INTERVAL"] = "0"
        os.environ["KEV_TRIAGE_TIMEOUT"] = "10"
        os.environ.pop("NVD_API_KEY", None)
        os.environ.pop("KEV_TRIAGE_NVD_API_KEY", None)
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        try:
            yield cache_dir
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def unused_port():
    """A port that refuses connections, for network-failure tests."""
    yield f"http://127.0.0.1:{free_port()}"
