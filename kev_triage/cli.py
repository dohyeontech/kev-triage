"""Command line interface for kev-triage."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import __version__, config, cve as cve_module, report
from .errors import InputError, KevTriageError, SourceError, SourceUnavailable
from .model import PRIORITIES
from .service import TriageService

EXIT_OK = 0
EXIT_SOURCE_ERROR = 2
EXIT_GATE = 3
EXIT_INPUT = 4

GATE_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "none": 99}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-f", "--format", choices=report.FORMATS, default="table", help="output format (default: table)"
    )
    common.add_argument("--json", action="store_true", help="shorthand for --format json")
    common.add_argument(
        "--fail-on",
        choices=["P0", "P1", "P2", "none"],
        default="none",
        help="exit 3 when any finding is at or above this priority (for CI gates)",
    )
    common.add_argument("--offline", action="store_true", help="never touch the network; use the cache only")
    common.add_argument("--refresh", action="store_true", help="ignore fresh cache entries and refetch")
    common.add_argument("--no-cache", action="store_true", help="do not read or write the cache")
    common.add_argument("--cache-dir", metavar="PATH", help="cache location (default: ~/.cache/kev-triage)")
    common.add_argument("--no-nvd", action="store_true", help="skip NVD CVSS lookups (KEV + EPSS only)")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    common.add_argument("-q", "--quiet", action="store_true", help="suppress warnings on stderr")

    parser = argparse.ArgumentParser(
        prog="kev-triage",
        description=(
            "Risk-based CVE triage: CISA KEV exploitation status, FIRST EPSS likelihood "
            "and NVD CVSS, combined into a P0-P3 action priority."
        ),
        epilog="https://github.com/dohyeontech/kev-triage",
    )
    parser.add_argument("--version", action="version", version=f"kev-triage {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    check = subparsers.add_parser(
        "check", parents=[common], help="prioritise one or more CVE IDs"
    )
    check.add_argument("cves", nargs="+", metavar="CVE", help="CVE IDs, e.g. CVE-2026-40217")

    recent = subparsers.add_parser(
        "recent", parents=[common], help="CISA KEV entries added in the last N days"
    )
    recent.add_argument("--days", type=int, default=7, help="look-back window in days (default: 7)")
    recent.add_argument("--limit", type=int, default=0, help="show at most N entries (default: all)")

    file_cmd = subparsers.add_parser(
        "file",
        parents=[common],
        help="extract every CVE ID from a file, stdin or a string and triage them",
    )
    file_cmd.add_argument(
        "source",
        metavar="PATH|TEXT|-",
        help="file path, '-' for stdin, or a literal string containing CVE IDs",
    )

    cache_cmd = subparsers.add_parser("cache", parents=[common], help="inspect or clear the local cache")
    cache_cmd.add_argument("action", nargs="?", choices=["info", "clear", "path"], default="info")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_OK

    if getattr(args, "json", False):
        args.format = "json"
    color = (
        args.format == "table"
        and not args.no_color
        and config.color_enabled()
        and sys.stdout.isatty()
    )

    try:
        if args.command == "cache":
            return _cmd_cache(args)
        if args.command == "check":
            return _cmd_check(args, color)
        if args.command == "recent":
            return _cmd_recent(args, color)
        if args.command == "file":
            return _cmd_file(args, color)
    except InputError as exc:
        print(f"kev-triage: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except SourceUnavailable as exc:
        print(f"kev-triage: no usable data: {exc}", file=sys.stderr)
        return EXIT_SOURCE_ERROR
    except SourceError as exc:
        print(f"kev-triage: {exc}", file=sys.stderr)
        return EXIT_SOURCE_ERROR
    except KevTriageError as exc:
        print(f"kev-triage: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except KeyboardInterrupt:
        return 130
    return EXIT_OK


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def _service(args) -> TriageService:
    return TriageService(
        cache_dir=args.cache_dir,
        no_cache=args.no_cache,
        offline=args.offline,
        refresh=args.refresh,
        use_nvd=not args.no_nvd,
    )


def _cmd_check(args, color: bool) -> int:
    cve_ids: list[str] = []
    errors: list[str] = []
    for raw in args.cves:
        try:
            cve_ids.append(cve_module.normalize(raw))
        except InputError as exc:
            errors.append(str(exc))
    if errors:
        raise InputError("; ".join(errors))
    cve_ids = list(dict.fromkeys(cve_ids))

    service = _service(args)
    result = service.check(cve_ids)
    _warn_degraded(result.states, args.quiet)
    print(report.render_check(result.findings, result.states, args.format, color=color))
    return _gate(result.findings, args.fail_on)


def _cmd_recent(args, color: bool) -> int:
    if args.days < 1:
        raise InputError("--days must be 1 or more")
    service = _service(args)
    result = service.recent(args.days)
    _warn_degraded(result.states, args.quiet)
    entries = list(result.entries)
    if args.limit and args.limit > 0:
        entries = entries[: args.limit]
    print(
        report.render_recent(
            entries, result.states, result.days, args.format, color=color, now=datetime.now(timezone.utc)
        )
    )
    return EXIT_OK


def _cmd_file(args, color: bool) -> int:
    text = _read_source(args.source)
    cve_ids = cve_module.extract(text)
    if not cve_ids:
        raise InputError(f"no CVE IDs found in {_describe_source(args.source)}")

    service = _service(args)
    result = service.check(cve_ids)
    _warn_degraded(result.states, args.quiet)
    print(report.render_check(result.findings, result.states, args.format, color=color))
    return _gate(result.findings, args.fail_on)


def _cmd_cache(args) -> int:
    from .cache import Cache

    directory = Path(args.cache_dir).expanduser() if args.cache_dir else config.default_cache_dir()
    cache = Cache(directory, enabled=not args.no_cache)
    if args.action == "clear":
        removed = cache.clear()
        print(f"removed {removed} cache entr{'y' if removed == 1 else 'ies'} from {directory}")
        return EXIT_OK
    if args.action == "path":
        print(directory)
        return EXIT_OK
    stats = cache.stats()
    if not stats["entries"]:
        print(f"cache: {stats['directory']} (empty)")
        return EXIT_OK
    newest = (
        datetime.fromtimestamp(stats["newest"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if stats["newest"]
        else "—"
    )
    print(
        f"cache: {stats['directory']}\n"
        f"entries: {stats['entries']} · size: {stats['bytes'] / 1024:.1f} KiB · newest: {newest}"
    )
    return EXIT_OK


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _read_source(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    path = Path(source).expanduser()
    if path.exists():
        if not path.is_file():
            raise InputError(f"not a file: {source}")
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise InputError(f"cannot read {source}: {exc}") from exc
    return source


def _describe_source(source: str) -> str:
    if source == "-":
        return "stdin"
    path = Path(source).expanduser()
    return source if path.exists() else "the given text"


def _warn_degraded(states, quiet: bool) -> None:
    if quiet:
        return
    problems = [state for state in states if state.degraded]
    for state in problems:
        print(
            f"kev-triage: warning: {state.name} {state.status} ({state.detail})",
            file=sys.stderr,
        )


def _gate(findings, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold = GATE_ORDER.get(fail_on, 99)
    triggered = [
        finding
        for finding in findings
        if finding.priority and finding.priority.rank <= threshold
    ]
    if not triggered:
        return EXIT_OK
    names = ", ".join(f"{finding.cve_id} ({finding.priority.code})" for finding in triggered)
    print(f"kev-triage: gate failed (--fail-on {fail_on}): {names}", file=sys.stderr)
    return EXIT_GATE
