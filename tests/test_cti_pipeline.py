"""Tests for the CTI collection, enrichment, and operationalization pipeline.

The scorer is measured against a labeled fixture set. That measurement is
internal: the fixtures were authored here, so it says the scorer behaves as
designed on cases the design anticipated. It is not evidence of performance on
real feed traffic, and the assertions below are written so that distinction
cannot be quietly lost.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.cti import emit
from tools.cti.graph import MAX_CLUSTER_FANOUT, PivotGraph
from tools.cti.models import (
    Confidence,
    Indicator,
    IndicatorType,
    Provenance,
)
from tools.cti.pipeline import CtiPipeline
from tools.cti.relevance import (
    PRIORITY_THRESHOLD,
    TRIAGE_THRESHOLD,
    damerau_levenshtein,
    normalize,
    score_indicator,
    typosquat_of,
)

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = ROOT / "tests" / "fixtures" / "cti" / "snapshots"
GROUND_TRUTH = ROOT / "tests" / "fixtures" / "cti" / "ground_truth.json"
PRODUCED = "2026-09-05"


def provenance(source: str = "test") -> Provenance:
    return Provenance(source=source, collected=PRODUCED)


class IndicatorModelTests(unittest.TestCase):
    def test_value_is_normalized_and_key_is_stable(self):
        a = Indicator("  Example.INVALID ", IndicatorType.DOMAIN, provenance())
        b = Indicator("example.invalid", IndicatorType.DOMAIN, provenance())
        self.assertEqual(a.key, b.key)
        self.assertEqual(a.stix_id, b.stix_id)

    def test_empty_value_is_rejected(self):
        with self.assertRaises(ValueError):
            Indicator("   ", IndicatorType.DOMAIN, provenance())

    def test_ttl_varies_by_type_and_confidence(self):
        low = Indicator("1.2.3.4", IndicatorType.IPV4, provenance(), Confidence.LOW)
        high = Indicator("1.2.3.5", IndicatorType.IPV4, provenance(), Confidence.HIGH)
        domain = Indicator("a.invalid", IndicatorType.DOMAIN, provenance())
        self.assertLess(low.ttl_days(), high.ttl_days())
        self.assertLess(high.ttl_days(), domain.ttl_days())

    def test_every_indicator_expires(self):
        for itype in IndicatorType:
            with self.subTest(type=itype):
                value = "1.2.3.4" if itype is IndicatorType.IPV4 else "sample-value"
                indicator = Indicator(value, itype, provenance())
                self.assertGreater(indicator.ttl_days(), 0)
                self.assertGreater(indicator.expires_on(), indicator.first_seen)

    def test_merge_keeps_strongest_signal_and_records_corroboration(self):
        first = Indicator(
            "lure.invalid",
            IndicatorType.DOMAIN,
            provenance("ct"),
            Confidence.LOW,
            relevance=0.2,
            relevance_reasons=["a"],
            first_seen="2026-09-04",
        )
        second = Indicator(
            "lure.invalid",
            IndicatorType.DOMAIN,
            provenance("url_feed"),
            Confidence.HIGH,
            relevance=0.8,
            relevance_reasons=["b"],
            first_seen="2026-09-01",
        )
        first.merge(second)
        self.assertEqual(first.confidence, Confidence.HIGH)
        self.assertEqual(first.relevance, 0.8)
        self.assertEqual(first.relevance_reasons, ["a", "b"])
        self.assertIn("url_feed", first.context["corroborating_sources"])
        self.assertEqual(first.first_seen, "2026-09-01", "earliest sighting must win")

    def test_merge_refuses_different_indicators(self):
        a = Indicator("a.invalid", IndicatorType.DOMAIN, provenance())
        b = Indicator("b.invalid", IndicatorType.DOMAIN, provenance())
        with self.assertRaises(ValueError):
            a.merge(b)


class RelevanceScorerTests(unittest.TestCase):
    def test_homoglyph_normalization(self):
        self.assertEqual(normalize("anthr0pic.invalid"), "anthropicinvalid")

    def test_transposition_costs_one_edit(self):
        self.assertEqual(damerau_levenshtein("huggingfaec", "huggingface"), 1)
        self.assertEqual(damerau_levenshtein("openai", "openai"), 0)

    def test_typosquat_detection_across_separators(self):
        self.assertIsNotNone(typosquat_of("huggingfaec.invalid"))
        self.assertIsNotNone(typosquat_of("pypi:huggingfaec-hub"))
        self.assertIsNone(typosquat_of("completely-unrelated.invalid"))

    def test_exact_brand_is_substring_not_typosquat(self):
        verdict = score_indicator("anthropic-careers.invalid")
        self.assertTrue(any("brand term" in r for r in verdict.reasons))

    def test_commodity_infrastructure_scores_below_triage(self):
        for value in (
            "banking-alert.invalid",
            "parcel-track.invalid",
            "blog.example.com",
            "cdn-assets-42.invalid",
        ):
            with self.subTest(value=value):
                self.assertLess(score_indicator(value).score, TRIAGE_THRESHOLD)

    def test_scores_are_bounded(self):
        verdict = score_indicator(
            "anthropic-careers-interview-safetensors-npm.top",
            context={"recently_registered": True},
        )
        self.assertLessEqual(verdict.score, 1.0)

    def test_recently_issued_cert_scores_relevance(self):
        verdict = score_indicator(
            "anthropic-login.com",
            context={"recently_issued_cert": True},
        )
        self.assertTrue(any("certificate recently issued" in r for r in verdict.reasons))

    def test_cctld_registrable_domain(self):
        from tools.cti.sources import registrable_domain
        self.assertEqual(registrable_domain("sub.attack.co.nz"), "attack.co.nz")
        self.assertEqual(registrable_domain("evil.phish.org.uk"), "phish.org.uk")
        self.assertEqual(registrable_domain("deep.login.gov.uk"), "login.gov.uk")

    def test_every_score_is_explained(self):
        verdict = score_indicator("anthropic-recruiting.invalid")
        self.assertGreater(verdict.score, 0)
        self.assertTrue(verdict.reasons, "a score with no stated reason is not reviewable")


class GraphTests(unittest.TestCase):
    def _domain(self, name: str, **context) -> Indicator:
        return Indicator(name, IndicatorType.DOMAIN, provenance(), context=context)

    def test_shared_attribute_creates_a_cluster(self):
        graph = PivotGraph()
        graph.add_all(
            [
                self._domain("a.invalid", cert_sha256="ff"),
                self._domain("b.invalid", cert_sha256="ff"),
                self._domain("c.invalid", cert_sha256="ee"),
            ]
        )
        graph.build()
        clusters = [c for c in graph.clusters if c.shared_value == "ff"]
        self.assertEqual(len(clusters), 1)
        self.assertEqual(len(clusters[0].members), 2)

    def test_high_fanout_attributes_are_refused(self):
        graph = PivotGraph()
        graph.add_all(
            [
                self._domain(f"host{i}.invalid", asn="AS64500")
                for i in range(MAX_CLUSTER_FANOUT + 5)
            ]
        )
        graph.build()
        self.assertEqual(graph.clusters, [], "shared hosting must not form a campaign")
        self.assertIn("asn=as64500", graph.rejected_pivots)

    def test_traversal_is_depth_bounded(self):
        graph = PivotGraph()
        graph.add_all(
            [
                self._domain("a.invalid", cert_sha256="11"),
                self._domain("b.invalid", cert_sha256="11"),
            ]
        )
        graph.build()
        self.assertEqual(graph.traverse("domain:a.invalid", max_depth=1),
                         ["domain:a.invalid", "domain:b.invalid"])
        self.assertEqual(graph.traverse("domain:missing.invalid"), [])

    def test_duplicate_indicators_merge_rather_than_duplicate(self):
        graph = PivotGraph()
        graph.add(self._domain("dup.invalid"))
        graph.add(self._domain("dup.invalid"))
        self.assertEqual(len(graph.nodes), 1)


class EmissionTests(unittest.TestCase):
    def setUp(self):
        self.indicators = [
            Indicator(
                "anthropic-careers.invalid",
                IndicatorType.DOMAIN,
                provenance("ct"),
                Confidence.MODERATE,
                relevance=0.85,
                relevance_reasons=["contains brand term: anthropic"],
                first_seen=PRODUCED,
            )
        ]

    def test_stix_indicators_all_carry_an_expiry(self):
        bundle = emit.to_stix_bundle(self.indicators, PRODUCED)
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["objects"])
        for obj in bundle["objects"]:
            self.assertIn("valid_until", obj)
            self.assertGreater(obj["valid_until"], obj["valid_from"])

    def test_siem_lookup_has_a_header_and_a_row(self):
        csv_text = emit.to_siem_lookup(self.indicators)
        lines = csv_text.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("indicator,type,confidence"))

    def test_candidate_rules_are_marked_unsupported_and_unmeasured(self):
        draft = emit.to_candidate_sigma(self.indicators, cluster_id="cert:aa")
        self.assertIn("status: unsupported", draft)
        self.assertIn("AUTOMATICALLY DRAFTED", draft)
        self.assertIn("Unmeasured", draft)
        self.assertIn("review_by", draft, "a generated indicator rule must carry a retirement date")

    def test_no_draft_without_network_indicators(self):
        hash_only = [
            Indicator("a" * 64, IndicatorType.FILE_SHA256, provenance())
        ]
        self.assertEqual(emit.to_candidate_sigma(hash_only), "")


class PipelineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pipeline = CtiPipeline(SNAPSHOTS, produced=PRODUCED)
        cls.report = cls.pipeline.run()
        cls.truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))

    def test_all_sources_collected_without_error(self):
        for result in self.report.collection:
            with self.subTest(source=result.source):
                self.assertIsNone(result.error)
                self.assertGreater(result.records_seen, 0)

    def test_malformed_records_are_counted_not_swallowed(self):
        feed = next(
            r for r in self.report.collection if r.source == "malicious_url_feed"
        )
        self.assertEqual(feed.records_skipped, 1)
        self.assertIn("not_a_url", feed.skip_reasons)

    def test_deduplication_across_sources(self):
        self.assertLess(
            self.report.unique_indicators,
            self.report.total_raw_indicators,
            "the same domain appears in more than one source and must merge",
        )

    def test_labeled_relevant_indicators_all_reach_the_queue(self):
        queued = {i.key for i in self.report.triage_queue}
        missed = [k for k in self.truth["relevant"] if k not in queued]
        self.assertEqual([], missed, f"relevant indicators dropped below triage: {missed}")

    def test_labeled_irrelevant_indicators_are_all_filtered(self):
        queued = {i.key for i in self.report.triage_queue}
        leaked = [k for k in self.truth["irrelevant_examples"] if k in queued]
        self.assertEqual([], leaked, f"commodity noise reached the queue: {leaked}")

    def test_queue_is_a_small_fraction_of_collection(self):
        self.assertGreater(self.report.unique_indicators, 0)
        ratio = len(self.report.triage_queue) / self.report.unique_indicators
        self.assertLess(ratio, 0.35, "the queue is not being reduced enough to be useful")

    def test_measurement_is_labeled_internal(self):
        """The ground truth file must state that it was authored here."""
        note = self.truth.get("note", "").lower()
        self.assertIn("authored in this repository", note)
        self.assertIn("not a measurement against real feed traffic", note)

    def test_campaign_clusters_are_discovered(self):
        cluster_members = {
            member for cluster in self.report.graph.clusters for member in cluster.members
        }
        self.assertIn("domain:anthropic-careers.invalid", cluster_members)
        self.assertIn("domain:anthropic-recruiting.invalid", cluster_members)

    def test_priority_queue_is_a_subset_of_triage(self):
        triage = {i.key for i in self.report.triage_queue}
        for indicator in self.report.priority_queue:
            self.assertIn(indicator.key, triage)
            self.assertGreaterEqual(indicator.relevance, PRIORITY_THRESHOLD)

    def test_run_is_deterministic(self):
        second = CtiPipeline(SNAPSHOTS, produced=PRODUCED).run()
        self.assertEqual(
            [i.key for i in self.report.triage_queue],
            [i.key for i in second.triage_queue],
        )
        self.assertEqual(
            emit.to_json(self.report.summary()), emit.to_json(second.summary())
        )

    def test_outputs_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = self.pipeline.write_outputs(self.report, Path(tmp))
            for label in ("summary", "triage_queue", "stix", "siem_lookup"):
                self.assertTrue(written[label].is_file(), f"{label} not written")
            drafts = list((Path(tmp) / "candidate_rules").glob("*.yml"))
            self.assertTrue(drafts, "no candidate rule drafted from a discovered cluster")
            for draft in drafts:
                self.assertIn("status: unsupported", draft.read_text(encoding="utf-8"))

    def test_missing_snapshot_directory_reports_errors_rather_than_crashing(self):
        report = CtiPipeline(SNAPSHOTS / "does-not-exist", produced=PRODUCED).run()
        self.assertEqual(report.unique_indicators, 0)
        self.assertTrue(all(r.error for r in report.collection))


if __name__ == "__main__":
    unittest.main()
