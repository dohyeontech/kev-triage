"""The P0-P3 decision table."""

from __future__ import annotations

import unittest
from datetime import date

from kev_triage.model import CvssScore, EpssScore, Finding, KevEntry
from kev_triage.priority import classify, summarize

TODAY = date(2026, 11, 21)


def kev_entry(due="2026-11-23", ransomware="Unknown", added="2026-11-20"):
    return KevEntry(
        cve_id="CVE-2026-0001",
        vendor="Vendor",
        product="Product",
        name="Test vulnerability",
        date_added=added,
        due_date=due,
        ransomware=ransomware,
        description="short description",
        required_action="apply updates",
    )


def finding(**kwargs) -> Finding:
    return Finding(cve_id="CVE-2026-0001", **kwargs)


class KevRules(unittest.TestCase):
    def test_kev_due_within_a_week_is_p0(self):
        item = finding(kev=kev_entry(due="2026-11-23"))
        self.assertEqual(classify(item, TODAY).code, "P0")

    def test_kev_due_today_is_p0(self):
        self.assertEqual(classify(finding(kev=kev_entry(due="2026-11-21")), TODAY).code, "P0")

    def test_kev_overdue_is_p0(self):
        self.assertEqual(classify(finding(kev=kev_entry(due="2026-11-01")), TODAY).code, "P0")

    def test_kev_with_distant_due_date_is_p1(self):
        self.assertEqual(classify(finding(kev=kev_entry(due="2026-12-11")), TODAY).code, "P1")

    def test_kev_ransomware_is_p0_even_with_time(self):
        item = finding(kev=kev_entry(due="2027-03-02", ransomware="Known"))
        self.assertEqual(classify(item, TODAY).code, "P0")
        self.assertIn("ransomware", item.rationale)

    def test_kev_without_due_date_is_p1(self):
        self.assertEqual(classify(finding(kev=kev_entry(due="")), TODAY).code, "P1")


class NonKevRules(unittest.TestCase):
    def test_high_epss_and_critical_cvss_is_p1(self):
        item = finding(epss=EpssScore("CVE-2026-0001", 0.42, 0.99), cvss=CvssScore(9.8, "CRITICAL", "3.1"))
        self.assertEqual(classify(item, TODAY).code, "P1")

    def test_high_epss_only_is_p2(self):
        item = finding(epss=EpssScore("CVE-2026-0001", 0.20, 0.97), cvss=CvssScore(6.5, "MEDIUM", "3.1"))
        self.assertEqual(classify(item, TODAY).code, "P2")

    def test_critical_cvss_only_is_p2(self):
        item = finding(epss=EpssScore("CVE-2026-0001", 0.001, 0.2), cvss=CvssScore(9.8, "CRITICAL", "3.1"))
        self.assertEqual(classify(item, TODAY).code, "P2")

    def test_not_exploited_and_low_severity_is_p3(self):
        item = finding(epss=EpssScore("CVE-2026-0001", 0.0004, 0.1), cvss=CvssScore(5.0, "MEDIUM", "3.1"))
        self.assertEqual(classify(item, TODAY).code, "P3")

    def test_cvss_high_threshold(self):
        item = finding(cvss=CvssScore(7.0, "HIGH", "3.1"))
        self.assertEqual(classify(item, TODAY).code, "P2")

    def test_threshold_boundaries(self):
        epss_at = finding(epss=EpssScore("CVE-2026-0001", 0.10, 0.9), cvss=CvssScore(9.0, "CRITICAL", "3.1"))
        self.assertEqual(classify(epss_at, TODAY).code, "P1")
        below = finding(epss=EpssScore("CVE-2026-0001", 0.0999, 0.9), cvss=CvssScore(9.0, "CRITICAL", "3.1"))
        self.assertEqual(classify(below, TODAY).code, "P2")


class DataGapRules(unittest.TestCase):
    def test_no_data_is_p3_with_gaps(self):
        item = finding()
        self.assertEqual(classify(item, TODAY).code, "P3")
        self.assertIn("no public data", item.rationale)
        self.assertTrue(any("EPSS" in gap for gap in item.gaps))
        self.assertTrue(any("CVSS" in gap for gap in item.gaps))

    def test_kev_entry_supplies_description(self):
        item = finding(kev=kev_entry())
        classify(item, TODAY)
        self.assertEqual(item.asset, "Vendor Product")

    def test_rationale_lists_sources(self):
        item = finding(
            kev=kev_entry(due="2026-11-30"),
            epss=EpssScore("CVE-2026-0001", 0.689, 0.9936),
            cvss=CvssScore(8.8, "HIGH", "3.1"),
        )
        classify(item, TODAY)
        self.assertIn("CISA KEV", item.rationale)
        self.assertIn("EPSS 68.9%", item.rationale)
        self.assertIn("CVSS 8.8 HIGH", item.rationale)
        self.assertIn("due in 9d", item.rationale)


class SummaryTests(unittest.TestCase):
    def test_counts(self):
        items = [
            finding(kev=kev_entry()),
            finding(epss=EpssScore("x", 0.001), cvss=CvssScore(4.0, "MEDIUM", "3.1")),
            Finding(cve_id="CVE-2026-0002"),
        ]
        for item in items:
            classify(item, TODAY)
        summary = summarize(items)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["P0"], 1)
        self.assertEqual(summary["P3"], 2)
        self.assertEqual(summary["kev_listed"], 1)

    def test_sorting_puts_p0_first(self):
        p3 = Finding(cve_id="CVE-2026-0003", epss=EpssScore("x", 0.0001))
        p0 = Finding(cve_id="CVE-2026-0001", kev=kev_entry())
        for item in (p3, p0):
            classify(item, TODAY)
        ordered = sorted([p3, p0], key=lambda item: item.sort_key())
        self.assertEqual([item.cve_id for item in ordered], ["CVE-2026-0001", "CVE-2026-0003"])


if __name__ == "__main__":
    unittest.main()
