"""CVE identifier handling."""

from __future__ import annotations

import unittest

from kev_triage import cve
from kev_triage.errors import InputError


class NormalizeTests(unittest.TestCase):
    def test_accepts_canonical_form(self):
        self.assertEqual(cve.normalize("CVE-2026-123890"), "CVE-2026-123890")

    def test_case_and_whitespace(self):
        self.assertEqual(cve.normalize("  cve-2021-44228\n"), "CVE-2021-44228")

    def test_bare_year_sequence(self):
        self.assertEqual(cve.normalize("2026-40217"), "CVE-2026-40217")

    def test_long_sequence(self):
        self.assertEqual(cve.normalize("CVE-2024-1234567"), "CVE-2024-1234567")

    def test_embedded_in_sentence(self):
        self.assertEqual(cve.normalize("see CVE-2026-40217 for details"), "CVE-2026-40217")

    def test_rejects_garbage(self):
        for value in ("", "  ", "NOTACVE", "CVE-2026-123", "CVE-26-1234", "2026-123"):
            with self.subTest(value=value):
                with self.assertRaises(InputError):
                    cve.normalize(value)

    def test_looks_like_cve(self):
        self.assertTrue(cve.looks_like_cve("CVE-2026-40217"))
        self.assertFalse(cve.looks_like_cve("CVE-2026"))


class ExtractTests(unittest.TestCase):
    def test_extracts_deduplicates_and_keeps_order(self):
        text = (
            "Ticket: CVE-2026-123890 hits VMware vCenter.\n"
            "Also cve-2021-44228 (Log4Shell) and CVE-2026-123890 again.\n"
            "Unrelated: CVE-2026-40217.\n"
        )
        self.assertEqual(
            cve.extract(text),
            ["CVE-2026-123890", "CVE-2021-44228", "CVE-2026-40217"],
        )

    def test_no_matches(self):
        self.assertEqual(cve.extract("no identifiers here"), [])
        self.assertEqual(cve.extract(""), [])

    def test_ignores_partial_tokens(self):
        self.assertEqual(cve.extract("XCVE-2026-123890 CVE-2026-123 2026-1234-1"), [])

    def test_finds_ids_inside_urls(self):
        text = "https://nvd.nist.gov/vuln/detail/CVE-2026-40217?x=1"
        self.assertEqual(cve.extract(text), ["CVE-2026-40217"])


if __name__ == "__main__":
    unittest.main()
