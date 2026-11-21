"""Rendering: tables, Markdown and JSON."""

from __future__ import annotations

import json
import unittest
from datetime import date, datetime, timezone

from kev_triage import report
from kev_triage.model import CvssScore, EpssScore, Finding, KevEntry, SourceState
from kev_triage.priority import classify

TODAY = date(2026, 11, 21)
NOW = datetime(2026, 11, 21, 13, 40, tzinfo=timezone.utc)


def make_finding(cve_id="CVE-2026-123890", kev=True, epss=0.0084, cvss=9.8, due="2026-11-23"):
    item = Finding(cve_id=cve_id)
    if kev:
        item.kev = KevEntry(
            cve_id=cve_id,
            vendor="Broadcom",
            product="VMware vCenter",
            name="VMware vCenter Authentication Bypass",
            date_added="2026-11-20",
            due_date=due,
            ransomware="Unknown",
            description="Authentication bypass in vCenter.",
            required_action="Apply the vendor update.",
            cwes=("CWE-288",),
        )
    if epss is not None:
        item.epss = EpssScore(cve_id, epss, 0.5884, "2026-11-20")
    if cvss is not None:
        item.cvss = CvssScore(cvss, "CRITICAL", "3.1")
    classify(item, TODAY)
    return item


STATES = [
    SourceState("kev", "live", "catalog 2026.11.20", 0.0),
    SourceState("epss", "cache", "2 CVE(s)", 7200),
    SourceState("nvd", "live", "2/2 lookups ok", 0.0),
]


class CheckTableTests(unittest.TestCase):
    def test_columns_and_order(self):
        low = make_finding("CVE-2026-99999", kev=False, epss=0.0001, cvss=4.0)
        high = make_finding()
        text = report.render_check([high, low], STATES, "table", now=NOW)
        header = next(line for line in text.splitlines() if line.startswith("PRI"))
        for column in ("PRI", "CVE", "KEV", "DUE", "EPSS", "CVSS", "ASSET", "SIGNAL"):
            self.assertIn(column, header)
        self.assertIn("P0", text)
        self.assertIn("CVE-2026-99999", text)
        self.assertIn("P0 1 · P1 0 · P2 0 · P3 1", text)
        self.assertIn("KEV listed 1/2", text)

    def test_no_ansi_by_default(self):
        text = report.render_check([make_finding()], STATES, "table", color=False, now=NOW)
        self.assertNotIn("\x1b[", text)

    def test_ansi_when_requested(self):
        text = report.render_check([make_finding()], STATES, "table", color=True, now=NOW)
        self.assertIn("\x1b[", text)

    def test_source_line_reports_states(self):
        text = report.render_check([make_finding()], STATES, "table", now=NOW)
        self.assertIn("KEV: live (catalog 2026.11.20)", text)
        self.assertIn("EPSS: cache, 2.0h old", text)

    def test_empty_finding_list(self):
        text = report.render_check([], STATES, "table", now=NOW)
        self.assertIn("P0 0 · P1 0 · P2 0 · P3 0", text)

    def test_degraded_sources_are_visible(self):
        states = [SourceState("kev", "stale", "HTTP 503; using catalog 2026.11.20", 90_000)]
        text = report.render_check([make_finding()], states, "table", now=NOW)
        self.assertIn("STALE", text)


class CheckJsonTests(unittest.TestCase):
    def test_document_shape(self):
        document = json.loads(
            report.render_check([make_finding()], STATES, "json", now=NOW)
        )
        self.assertEqual(document["tool"], "kev-triage")
        self.assertEqual(document["command"], "check")
        self.assertEqual(document["generated_at"], "2026-11-21T13:40:00+00:00")
        self.assertEqual(document["summary"]["P0"], 1)
        finding = document["findings"][0]
        self.assertEqual(finding["cve"], "CVE-2026-123890")
        self.assertTrue(finding["in_kev"])
        self.assertEqual(finding["kev"]["due_date"], "2026-11-23")
        self.assertEqual(finding["kev"]["days_to_due"], 2)
        self.assertAlmostEqual(finding["epss"]["score"], 0.0084)
        self.assertEqual(finding["cvss"]["base_score"], 9.8)
        self.assertEqual(finding["priority"]["code"], "P0")
        self.assertIn("rationale", finding)

    def test_sources_are_serialised(self):
        document = json.loads(report.render_check([make_finding()], STATES, "json", now=NOW))
        names = [source["name"] for source in document["sources"]]
        self.assertEqual(names, ["kev", "epss", "nvd"])
        self.assertEqual(document["sources"][1]["status"], "cache")


class CheckMarkdownTests(unittest.TestCase):
    def test_table_and_action_items(self):
        text = report.render_check([make_finding()], STATES, "markdown", now=NOW)
        self.assertIn("# CVE triage — 1 identifier", text)
        self.assertIn("| Priority | CVE | KEV | Due | EPSS | CVSS | Asset |", text)
        self.assertIn("| P0 | `CVE-2026-123890` |", text)
        self.assertIn("## Action items", text)
        self.assertIn("Required action (CISA): Apply the vendor update.", text)

    def test_no_action_items_for_p3_only(self):
        low = make_finding("CVE-2026-99999", kev=False, epss=0.0001, cvss=3.1)
        text = report.render_check([low], STATES, "markdown", now=NOW)
        self.assertNotIn("## Action items", text)

    def test_pipe_in_asset_is_escaped(self):
        item = make_finding()
        item.kev = KevEntry(cve_id="CVE-2026-123890", vendor="A|B", product="C", due_date="2026-11-23")
        classify(item, TODAY)
        text = report.render_check([item], STATES, "markdown", now=NOW)
        self.assertIn("A\\|B C", text)


class RecentTests(unittest.TestCase):
    def entries(self):
        return [
            KevEntry(
                cve_id="CVE-2026-123890",
                vendor="Broadcom",
                product="VMware vCenter",
                name="vCenter auth bypass",
                date_added="2026-11-20",
                due_date="2026-11-23",
                ransomware="Unknown",
            ),
            KevEntry(
                cve_id="CVE-2025-42884",
                vendor="SAP",
                product="NetWeaver",
                date_added="2026-11-19",
                due_date="2026-11-23",
                ransomware="Known",
            ),
        ]

    def test_table(self):
        text = report.render_recent(self.entries(), STATES[:1], 7, "table", now=NOW)
        self.assertIn("ADDED", text)
        self.assertIn("2 addition(s) in 7d", text)
        self.assertIn("SAP", text)

    def test_empty(self):
        text = report.render_recent([], STATES[:1], 7, "table", now=NOW)
        self.assertIn("no CISA KEV additions in the last 7 days", text)

    def test_json(self):
        document = json.loads(report.render_recent(self.entries(), STATES[:1], 7, "json", now=NOW))
        self.assertEqual(document["command"], "recent")
        self.assertEqual(document["count"], 2)
        self.assertEqual(document["entries"][0]["cve"], "CVE-2026-123890")
        self.assertEqual(document["entries"][1]["ransomware"], "Known")

    def test_markdown(self):
        text = report.render_recent(self.entries(), STATES[:1], 7, "markdown", now=NOW)
        self.assertIn("# CISA KEV additions — last 7 days", text)
        self.assertIn("| Added | CVE | Vendor | Product | Due | Ransomware |", text)


class SourceLineTests(unittest.TestCase):
    def test_statuses(self):
        states = [
            SourceState("kev", "live", "catalog 2026.11.20"),
            SourceState("epss", "skipped", "--no-nvd"),
            SourceState("nvd", "unavailable", "HTTP 500 from nvd.example"),
        ]
        line = report.sources_line(states)
        self.assertIn("KEV: live", line)
        self.assertIn("EPSS: skipped", line)
        self.assertIn("NVD: UNAVAILABLE", line)


if __name__ == "__main__":
    unittest.main()
