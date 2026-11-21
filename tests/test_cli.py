"""End-to-end tests through the CLI, against a mock HTTP server."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from kev_triage import cli

from .support import (
    MockServer,
    epss_router,
    fixture,
    isolated_env,
    json_route,
    nvd_router,
)

NVD_ROUTES = {
    "CVE-2026-123890": fixture("nvd_cve_vc.json"),
    "CVE-2026-40217": fixture("nvd_cve_litellm.json"),
}


def routes(kev: bytes | None = None):
    return {
        "/kev": json_route(kev if kev is not None else fixture("kev_catalog.json")),
        "/epss": epss_router(),
        "/nvd": nvd_router(NVD_ROUTES),
    }


class CliTestCase(unittest.TestCase):
    @contextlib.contextmanager
    def api(self, kev: bytes | None = None):
        with MockServer(routes(kev)) as server:
            with isolated_env(
                KEV_TRIAGE_KEV_URL=server.url("/kev"),
                KEV_TRIAGE_EPSS_URL=server.url("/epss"),
                KEV_TRIAGE_NVD_URL=server.url("/nvd"),
            ):
                yield server

    def run_cli(self, argv, stdin: str | None = None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if stdin is not None:
                with unittest.mock.patch("sys.stdin", io.StringIO(stdin)):
                    code = cli.main(argv)
            else:
                code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()


class CheckCommandTests(CliTestCase):
    def test_table_output(self):
        with self.api():
            code, out, err = self.run_cli(["check", "CVE-2026-123890", "CVE-2026-40217"])
        self.assertEqual(code, 0, err)
        self.assertIn("CVE-2026-123890", out)
        self.assertIn("CVE-2026-40217", out)
        self.assertIn("P0 1 · P1 1", out)
        self.assertIn("KEV listed 2/2", out)

    def test_json_output(self):
        with self.api():
            code, out, _ = self.run_cli(["check", "CVE-2026-40217", "--format", "json"])
        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertEqual(document["command"], "check")
        self.assertEqual(document["findings"][0]["cve"], "CVE-2026-40217")
        self.assertEqual(document["findings"][0]["priority"]["code"], "P1")

    def test_json_shorthand(self):
        with self.api():
            _, out, _ = self.run_cli(["check", "CVE-2026-40217", "--json"])
        self.assertEqual(json.loads(out)["command"], "check")

    def test_markdown_output(self):
        with self.api():
            _, out, _ = self.run_cli(["check", "CVE-2026-123890", "-f", "markdown"])
        self.assertIn("# CVE triage", out)
        self.assertIn("## Action items", out)

    def test_duplicate_ids_are_collapsed(self):
        with self.api():
            _, out, _ = self.run_cli(["check", "CVE-2026-40217", "cve-2026-40217", "--format", "json"])
        document = json.loads(out)
        self.assertEqual(document["summary"]["total"], 1)

    def test_invalid_identifier_exits_4(self):
        with self.api():
            code, _, err = self.run_cli(["check", "NOPE"])
        self.assertEqual(code, 4)
        self.assertIn("not a CVE identifier", err)

    def test_gate_triggers(self):
        with self.api():
            code, _, err = self.run_cli(["check", "CVE-2026-123890", "--fail-on", "P1"])
        self.assertEqual(code, 3)
        self.assertIn("gate failed", err)

    def test_gate_passes(self):
        with self.api():
            code, _, _ = self.run_cli(["check", "CVE-2099-99999", "--fail-on", "P1"])
        self.assertEqual(code, 0)

    def test_no_nvd_skips_cvss(self):
        with self.api():
            _, out, _ = self.run_cli(["check", "CVE-2026-40217", "--no-nvd"])
        self.assertIn("NVD: skipped", out)

    def test_colour_only_on_a_tty(self):
        with self.api():
            _, out, _ = self.run_cli(["check", "CVE-2026-40217"])
        self.assertNotIn("\x1b[", out)

    def test_offline_without_cache_exits_2(self):
        with isolated_env(
            KEV_TRIAGE_KEV_URL="http://127.0.0.1:1/kev",
            KEV_TRIAGE_EPSS_URL="http://127.0.0.1:1/epss",
            KEV_TRIAGE_NVD_URL="http://127.0.0.1:1/nvd",
        ):
            with unittest.mock.patch("kev_triage.sources.time.sleep"):
                code, _, err = self.run_cli(["check", "CVE-2026-40217", "--offline"])
        self.assertEqual(code, 2)
        self.assertIn("no usable data", err)

    def test_one_dead_source_degrades_but_succeeds(self):
        with MockServer(
            {
                "/kev": json_route({"error": "gone"}, status=500),
                "/epss": epss_router(),
                "/nvd": nvd_router(NVD_ROUTES),
            }
        ) as server:
            with isolated_env(
                KEV_TRIAGE_KEV_URL=server.url("/kev"),
                KEV_TRIAGE_EPSS_URL=server.url("/epss"),
                KEV_TRIAGE_NVD_URL=server.url("/nvd"),
            ), unittest.mock.patch("kev_triage.sources.time.sleep"):
                code, out, err = self.run_cli(["check", "CVE-2026-40217"])
        self.assertEqual(code, 0)
        self.assertIn("warning: kev unavailable", err)
        self.assertIn("KEV: UNAVAILABLE", out)
        self.assertIn("EPSS 68.9%", out)

    def test_quiet_suppresses_warnings(self):
        with MockServer(
            {
                "/kev": json_route({"error": "gone"}, status=500),
                "/epss": epss_router(),
                "/nvd": nvd_router(NVD_ROUTES),
            }
        ) as server:
            with isolated_env(
                KEV_TRIAGE_KEV_URL=server.url("/kev"),
                KEV_TRIAGE_EPSS_URL=server.url("/epss"),
                KEV_TRIAGE_NVD_URL=server.url("/nvd"),
            ), unittest.mock.patch("kev_triage.sources.time.sleep"):
                _, _, err = self.run_cli(["check", "CVE-2026-40217", "-q"])
        self.assertNotIn("kev-triage:", err)


class FileCommandTests(CliTestCase):
    def test_literal_text(self):
        with self.api():
            code, out, _ = self.run_cli(
                ["file", "advisory mentions CVE-2026-123890 and CVE-2021-44228"]
            )
        self.assertEqual(code, 0)
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("CVE-2026-123890", out)

    def test_file_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "advisory.txt"
            path.write_text("Affected: CVE-2026-40217\nAlso: CVE-2026-123890\n", encoding="utf-8")
            with self.api():
                code, out, _ = self.run_cli(["file", str(path), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["total"], 2)

    def test_stdin(self):
        with self.api():
            code, out, _ = self.run_cli(["file", "-"], stdin="CVE-2026-123890 only")
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-123890", out)

    def test_no_identifiers_exits_4(self):
        with self.api():
            code, _, err = self.run_cli(["file", "nothing to see"])
        self.assertEqual(code, 4)
        self.assertIn("no CVE IDs found", err)


class RecentCommandTests(CliTestCase):
    def test_recent_window(self):
        with self.api():
            code, out, _ = self.run_cli(["recent", "--days", "3"])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-123890", out)
        self.assertNotIn("CVE-2021-44228", out)

    def test_recent_json_and_limit(self):
        with self.api():
            _, out, _ = self.run_cli(["recent", "--days", "7", "--limit", "1", "--format", "json"])
        document = json.loads(out)
        self.assertEqual(document["count"], 1)
        self.assertEqual(document["entries"][0]["cve"], "CVE-2026-123890")

    def test_invalid_days(self):
        with self.api():
            code, _, err = self.run_cli(["recent", "--days", "0"])
        self.assertEqual(code, 4)
        self.assertIn("--days", err)


class CacheCommandTests(CliTestCase):
    def test_path_and_info(self):
        with self.api():
            code, out, _ = self.run_cli(["cache", "path"])
            self.assertEqual(code, 0)
            self.assertTrue(out.strip().endswith("cache"))
            self.run_cli(["check", "CVE-2026-40217"])
            code, out, _ = self.run_cli(["cache", "info"])
        self.assertEqual(code, 0)
        self.assertIn("entries:", out)

    def test_clear(self):
        with self.api():
            self.run_cli(["check", "CVE-2026-40217"])
            code, out, _ = self.run_cli(["cache", "clear"])
        self.assertEqual(code, 0)
        self.assertIn("removed", out)


class ParserTests(CliTestCase):
    def test_version(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_no_command_prints_help(self):
        code, out, _ = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("usage: kev-triage", out)


import unittest.mock  # noqa: E402  (used by the helpers above)


if __name__ == "__main__":
    unittest.main()
