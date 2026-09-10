"""Tests for Certificate Transparency acquisition and registrable-domain pivoting.

Nothing here touches the network. Acquisition is tested by feeding it the row
shape crt.sh returns; the network call itself is a thin wrapper and testing it
would test crt.sh rather than this code.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from tools.acquire_ct_snapshot import dedupe, to_records, write_snapshot
from tools.cti.graph import PivotGraph
from tools.cti.models import CollectionResult
from tools.cti.sources import (
    MULTI_LABEL_SUFFIXES,
    CertificateTransparencyCollector,
    registrable_domain,
)


def crtsh_row(names: str, ident: int, not_before: str) -> dict:
    return {
        "id": ident,
        "name_value": names,
        "not_before": f"{not_before}T00:00:00",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "serial_number": "abc123",
    }


class RegistrableDomainTests(unittest.TestCase):
    def test_simple_two_label_domain(self):
        self.assertEqual(registrable_domain("www.example.com"), "example.com")
        self.assertEqual(registrable_domain("example.com"), "example.com")

    def test_wildcard_prefix_is_stripped(self):
        self.assertEqual(registrable_domain("*.example.com"), "example.com")

    def test_multi_label_suffixes_take_one_more_label(self):
        """Without this, every site on a platform reads as one entity."""
        self.assertEqual(registrable_domain("a.b.myapp.workers.dev"), "myapp.workers.dev")
        self.assertEqual(registrable_domain("x.proj.hosted.app"), "proj.hosted.app")
        self.assertEqual(registrable_domain("site.co.uk"), "site.co.uk")

    def test_platform_suffix_alone_is_not_shortened_below_itself(self):
        self.assertEqual(registrable_domain("workers.dev"), "workers.dev")

    def test_every_listed_suffix_yields_more_than_the_suffix(self):
        for suffix in MULTI_LABEL_SUFFIXES:
            with self.subTest(suffix=suffix):
                self.assertEqual(registrable_domain(f"tenant.{suffix}"), f"tenant.{suffix}")

    def test_single_label_host_is_returned_unchanged(self):
        self.assertEqual(registrable_domain("localhost"), "localhost")


class RecordNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.today = date.today()

    def test_multiline_names_become_a_list(self):
        rows = [crtsh_row("a.example.com\nb.example.com", 1, self.today.isoformat())]
        records = to_records(rows, "example", None)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dns_names"], ["a.example.com", "b.example.com"])
        self.assertEqual(records[0]["matched_term"], "example")

    def test_rows_outside_the_window_are_dropped(self):
        old = (self.today - timedelta(days=400)).isoformat()
        recent = self.today.isoformat()
        rows = [crtsh_row("old.example.com", 1, old), crtsh_row("new.example.com", 2, recent)]
        records = to_records(rows, "example", self.today - timedelta(days=90))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dns_names"], ["new.example.com"])

    def test_rows_without_names_are_dropped(self):
        self.assertEqual(to_records([crtsh_row("", 1, self.today.isoformat())], "x", None), [])

    def test_dedupe_is_by_certificate_id(self):
        rows = [
            crtsh_row("a.example.com", 7, self.today.isoformat()),
            crtsh_row("a.example.com", 7, self.today.isoformat()),
            crtsh_row("b.example.com", 8, self.today.isoformat()),
        ]
        self.assertEqual(len(dedupe(to_records(rows, "example", None))), 2)


class SnapshotWritingTests(unittest.TestCase):
    def test_snapshot_and_lock_are_written_with_a_hash(self):
        records = to_records(
            [crtsh_row("a.example.com", 1, date.today().isoformat())], "example", None
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            lock = write_snapshot(records, out, ["example"], 90)
            self.assertTrue((out / lock["snapshot_file"]).is_file())
            self.assertTrue((out / "acquisition-lock.json").is_file())
            self.assertEqual(len(lock["snapshot_sha256"]), 64)

    def test_lock_states_that_the_snapshot_is_not_an_assessment(self):
        """Collection is not attribution, and the artifact has to say so."""
        records = to_records(
            [crtsh_row("a.example.com", 1, date.today().isoformat())], "example", None
        )
        with tempfile.TemporaryDirectory() as tmp:
            lock = write_snapshot(records, Path(tmp), ["example"], 90)
            note = lock["content_note"].lower()
            self.assertIn("nothing in this snapshot establishes that any domain is malicious", note)

    def test_snapshot_round_trips_through_the_pipeline_collector(self):
        records = to_records(
            [crtsh_row("a.example.com\nb.example.com", 1, date.today().isoformat())],
            "example",
            None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_snapshot(records, out, ["example"], 90)
            collector = CertificateTransparencyCollector(collected="2026-09-05")
            result = collector.collect(out / "certificate_transparency.jsonl")
            self.assertIsNone(result.error)
            self.assertEqual(len(result.indicators), 2)
            self.assertTrue(
                all(i.context.get("registrable_domain") == "example.com" for i in result.indicators)
            )


class RegistrableDomainPivotTests(unittest.TestCase):
    def _collect(self, names_per_cert):
        collector = CertificateTransparencyCollector(collected="2026-09-05")
        graph = PivotGraph()
        for index, names in enumerate(names_per_cert):
            result = CollectionResult(source="ct")
            graph.add_all(
                collector.parse(
                    {"dns_names": names, "not_before": "2026-09-01", "issuer": "CA"},
                    result,
                )
            )
        return graph.build()

    def test_names_on_one_apex_cluster_together(self):
        graph = self._collect(
            [["chat--openai--com.suspicious.invalid"], ["huggingface--co.suspicious.invalid"]]
        )
        clusters = [
            c for c in graph.clusters if c.shared_attribute == "registrable_domain"
        ]
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].shared_value, "suspicious.invalid")
        self.assertEqual(len(clusters[0].members), 2)

    def test_names_on_different_apexes_do_not_cluster(self):
        graph = self._collect([["a.one.invalid"], ["b.two.invalid"]])
        self.assertEqual(
            [c for c in graph.clusters if c.shared_attribute == "registrable_domain"], []
        )

    def test_shared_platform_is_refused_as_a_campaign(self):
        """A hosting provider must not be reported as a campaign."""
        graph = self._collect([[f"tenant{i}.example.invalid"] for i in range(40)])
        clusters = [
            c
            for c in graph.clusters
            if c.shared_attribute == "registrable_domain"
            and c.shared_value == "example.invalid"
        ]
        self.assertEqual(clusters, [])
        self.assertIn("registrable_domain=example.invalid", graph.rejected_pivots)


if __name__ == "__main__":
    unittest.main()
