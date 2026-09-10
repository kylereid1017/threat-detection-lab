"""Tests for the detection rule durability benchmark.

The analyzer is a measuring instrument applied to corpora this repository did not
write, so the property that matters most is that its scores mean what the
documentation says they mean. These tests pin each dimension to a rule that
isolates it, rather than asserting an aggregate that could drift for any reason.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.brittleness.metrics import (
    ENUMERATION_SATURATION,
    WEIGHTS,
    analyze_text,
    summarize,
)

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
REPORTS = ROOT / "docs" / "brittleness"


def rule(**overrides) -> str:
    """A minimal well-formed Sigma rule, with fields overridable per test."""
    body = {
        "title": "Test Rule",
        "id": "00000000-0000-0000-0000-000000000000",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"sel": {"Image|endswith": "\\test.exe"}, "condition": "sel"},
        "level": "medium",
    }
    body.update(overrides)
    import yaml

    return yaml.safe_dump(body, default_flow_style=False)


class DimensionIsolationTests(unittest.TestCase):
    def test_command_line_dependence_is_detected(self):
        result = analyze_text(
            rule(
                detection={
                    "sel": {"CommandLine|contains": "whoami"},
                    "condition": "sel",
                }
            ),
            "cmdline.yml",
        )
        self.assertEqual(result.dimensions["commandline_dependence"], 1.0)
        self.assertTrue(
            any("command-line capture" in o for o in result.observations)
        )

    def test_command_line_as_one_alternative_scores_lower(self):
        """An optional dependency is not the same as a required one."""
        required = analyze_text(
            rule(
                detection={
                    "a": {"CommandLine|contains": "x"},
                    "b": {"Image|endswith": "y.exe"},
                    "condition": "a and b",
                }
            ),
            "req.yml",
        )
        optional = analyze_text(
            rule(
                detection={
                    "a": {"CommandLine|contains": "x"},
                    "b": {"Image|endswith": "y.exe"},
                    "condition": "a or b",
                }
            ),
            "opt.yml",
        )
        self.assertGreater(
            required.dimensions["commandline_dependence"],
            optional.dimensions["commandline_dependence"],
        )

    def test_no_command_line_field_scores_zero(self):
        result = analyze_text(rule(), "plain.yml")
        self.assertEqual(result.dimensions["commandline_dependence"], 0.0)

    def test_enumeration_saturates(self):
        many = analyze_text(
            rule(
                detection={
                    "sel": {"CommandLine|contains": [f"token{i}" for i in range(ENUMERATION_SATURATION * 2)]},
                    "condition": "sel",
                }
            ),
            "many.yml",
        )
        few = analyze_text(
            rule(
                detection={
                    "sel": {"CommandLine|contains": ["a", "b"]},
                    "condition": "sel",
                }
            ),
            "few.yml",
        )
        self.assertEqual(many.dimensions["literal_enumeration"], 1.0)
        self.assertLess(few.dimensions["literal_enumeration"], 0.2)
        self.assertGreater(many.literal_count, few.literal_count)

    def test_lineage_dependence_is_detected(self):
        result = analyze_text(
            rule(
                detection={
                    "parent": {"ParentImage|endswith": "\\explorer.exe"},
                    "child": {"Image|endswith": "\\cmd.exe"},
                    "condition": "parent and child",
                }
            ),
            "lineage.yml",
        )
        self.assertEqual(result.dimensions["lineage_dependence"], 1.0)

    def test_substring_reliance_distinguishes_equality(self):
        substring = analyze_text(
            rule(detection={"sel": {"Image|contains": "x"}, "condition": "sel"}),
            "sub.yml",
        )
        equality = analyze_text(
            rule(detection={"sel": {"EventID": 4688}, "condition": "sel"}),
            "eq.yml",
        )
        self.assertEqual(substring.dimensions["substring_reliance"], 1.0)
        self.assertEqual(equality.dimensions["substring_reliance"], 0.0)

    def test_environment_coupling_flags_deployment_literals(self):
        coupled = analyze_text(
            rule(
                detection={
                    "sel": {"sourceIPAddress|cidr": "10.0.0.0/8"},
                    "filter": {"userIdentity.arn|contains": "arn:aws:iam::1:role/x"},
                    "condition": "sel and not filter",
                }
            ),
            "coupled.yml",
        )
        plain = analyze_text(rule(), "plain.yml")
        self.assertGreater(
            coupled.dimensions["environment_coupling"],
            plain.dimensions["environment_coupling"],
        )

    def test_documentation_gap_rewards_both_declarations(self):
        undocumented = analyze_text(rule(), "undoc.yml")
        partial = analyze_text(rule(falsepositives=["admin activity"]), "partial.yml")
        full = analyze_text(
            rule(
                falsepositives=["admin activity"],
                telemetry_prerequisites={"channel": "Sysmon", "event_id": 1},
            ),
            "full.yml",
        )
        self.assertEqual(undocumented.dimensions["documentation_gap"], 1.0)
        self.assertLess(partial.dimensions["documentation_gap"], 1.0)
        self.assertEqual(full.dimensions["documentation_gap"], 0.0)


class CompositeAndBandTests(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(WEIGHTS.values()), 1.0, places=6)

    def test_composite_is_bounded(self):
        worst = analyze_text(
            rule(
                detection={
                    "parent": {"ParentCommandLine|contains": [f"t{i}" for i in range(200)]},
                    "child": {"CommandLine|contains": [f"u{i}" for i in range(200)]},
                    "condition": "parent and child",
                }
            ),
            "worst.yml",
        )
        self.assertLessEqual(worst.composite, 1.0)
        self.assertEqual(worst.band, "fragile")

    def test_bands_are_ordered(self):
        clean = analyze_text(
            rule(
                detection={"sel": {"EventID": 4688}, "condition": "sel"},
                falsepositives=["none"],
                telemetry_prerequisites={"channel": "Security"},
            ),
            "clean.yml",
        )
        self.assertEqual(clean.band, "durable")
        self.assertLess(clean.composite, 0.35)


class MalformedInputTests(unittest.TestCase):
    def test_invalid_yaml_is_reported_not_raised(self):
        result = analyze_text("this: [is: not: valid", "bad.yml")
        self.assertIsNotNone(result.parse_error)
        self.assertEqual(result.composite, 0.0)

    def test_rule_without_detection_block_is_skipped(self):
        result = analyze_text(
            "title: Correlation\ncorrelation:\n  type: temporal\n", "corr.yml"
        )
        self.assertIsNotNone(result.parse_error)

    def test_empty_document_is_skipped(self):
        self.assertIsNotNone(analyze_text("", "empty.yml").parse_error)

    def test_summary_counts_skipped_rules_separately(self):
        results = [
            analyze_text(rule(), "ok.yml"),
            analyze_text("", "empty.yml"),
        ]
        report = summarize(results, "mixed")
        self.assertEqual(report["rules_scored"], 1)
        self.assertEqual(report["rules_skipped"], 1)
        self.assertIn("empty.yml", report["skipped_reasons"])


class OwnCorpusTests(unittest.TestCase):
    """The benchmark must run against this repository's own rules."""

    def test_every_local_rule_scores_or_explains_itself(self):
        from tools.brittleness.metrics import analyze_corpus

        results = analyze_corpus(SIGMA_DIR)
        self.assertGreater(len(results), 0)
        for result in results:
            with self.subTest(rule=result.path):
                self.assertTrue(
                    result.parse_error or result.dimensions,
                    "a rule must either score or say why it could not",
                )

    def test_local_rules_declare_prerequisites(self):
        """This repository's one measured advantage over the public corpus."""
        from tools.brittleness.metrics import analyze_corpus

        scored = [r for r in analyze_corpus(SIGMA_DIR) if not r.parse_error]
        mean_gap = sum(r.dimensions["documentation_gap"] for r in scored) / len(scored)
        self.assertLess(
            mean_gap,
            0.25,
            "rules here are expected to declare telemetry prerequisites; if this "
            "fails, a rule was added without them",
        )


class PublishedReportTests(unittest.TestCase):
    SIGMAHQ = REPORTS / "brittleness_SigmaHQ.json"

    def setUp(self):
        if not self.SIGMAHQ.is_file():
            self.skipTest("public corpus benchmark has not been run in this checkout")
        self.report = json.loads(self.SIGMAHQ.read_text(encoding="utf-8"))

    def test_corpus_revision_is_pinned(self):
        acquisition = self.report["acquisition"]
        self.assertTrue(acquisition["revision"], "a corpus measurement needs a revision")
        self.assertEqual(
            acquisition["files_listed"],
            acquisition["files_read"],
            "a short read means the measurement covered fewer rules than it claims",
        )

    def test_weights_are_published_with_the_result(self):
        self.assertIn("weights", self.report)
        self.assertIn("policy, not measurement", self.report["weights_note"])

    def test_detail_cap_is_disclosed(self):
        self.assertIn("rules_detail_note", self.report)
        self.assertLessEqual(len(self.report["rules"]), self.report["rules_scored"])


if __name__ == "__main__":
    unittest.main()
