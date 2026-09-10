"""Tests for the inventory-derived protected-name registry.

This module exists because the vocabulary branches of the relevance scorer
measured 0% held-out recall against 877 real malicious packages. The registry is
the branch that generalizes, and these tests pin the two properties that make it
usable: it must not flag the inventory against itself, and it must catch both
imitation forms that real lures actually use.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.cti import protected_names
from tools.cti.protected_names import (
    GENERIC_NAMES,
    MIN_PROTECTED_LENGTH,
    ProtectedRegistry,
)
from tools.cti.relevance import TRIAGE_THRESHOLD, score_indicator

INVENTORY = [
    "langchain",
    "transformers",
    "safetensors",
    "openai",
    "tiktoken",
    "express",
    "lodash",
    "@babel/core",
]


class RegistryConstructionTests(unittest.TestCase):
    def setUp(self):
        self.registry = protected_names.from_names(INVENTORY, source="test")

    def test_short_names_are_not_indexed(self):
        registry = protected_names.from_names(["ab", "abc", "abcd", "abcde"])
        for name in ("ab", "abc", "abcd"):
            self.assertIsNone(registry.nearest(name))
        self.assertLessEqual(registry.indexed_count, 1)

    def test_generic_names_are_excluded(self):
        registry = protected_names.from_names(sorted(GENERIC_NAMES) + ["langchain"])
        self.assertIsNone(registry.nearest("cores"))
        self.assertIsNotNone(registry.nearest("langchian"))

    def test_indexed_count_reflects_filtering(self):
        self.assertGreater(self.registry.indexed_count, 0)
        self.assertLessEqual(self.registry.indexed_count, len(INVENTORY))

    def test_round_trip_through_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            protected_names.save(self.registry, path)
            restored = protected_names.from_json(path)
            self.assertEqual(restored.names, self.registry.names)
            self.assertEqual(restored.indexed_count, self.registry.indexed_count)


class ImitationDetectionTests(unittest.TestCase):
    def setUp(self):
        self.registry = protected_names.from_names(INVENTORY, source="test")

    def test_exact_inventory_names_are_never_flagged(self):
        """The inventory must not fire on itself.

        This is the property that makes the branch deployable. Without it, every
        legitimate dependency in the organization becomes an alert.
        """
        for name in INVENTORY:
            with self.subTest(package=name):
                self.assertIsNone(self.registry.nearest(name))

    def test_misspelling_form_is_caught(self):
        for typo, expected in (
            ("langchian", "langchain"),
            ("transfomers", "transformers"),
            ("safetesnors", "safetensors"),
        ):
            with self.subTest(package=typo):
                result = self.registry.nearest(typo)
                self.assertIsNotNone(result, f"{typo} not caught")
                self.assertEqual(result[0], expected)

    def test_compound_form_is_caught(self):
        """Edit distance cannot see this form; the length gap is too large."""
        for compound, expected in (
            ("langchain-toolkit", "langchain"),
            ("openai-sdk-helper", "openai"),
            ("safetensors-fast", "safetensors"),
        ):
            with self.subTest(package=compound):
                result = self.registry.nearest(compound)
                self.assertIsNotNone(result, f"{compound} not caught")
                self.assertEqual(result[0], expected)

    def test_unrelated_names_are_not_flagged(self):
        for name in ("postgresql-driver", "weather-widget", "zzzzzzzzzz"):
            with self.subTest(package=name):
                self.assertIsNone(self.registry.nearest(name))

    def test_homoglyph_substitution_is_caught(self):
        """`l0dash` normalizes to `lodash`, which is why this nearly slipped.

        Excluding exact matches on the normalized form suppressed pure character
        substitution entirely: the attack collapses into the real name and is then
        discarded as genuine. The exclusion is done on the literal name instead.
        """
        result = self.registry.nearest("l0dash")
        self.assertIsNotNone(result, "homoglyph substitution of a dependency missed")
        self.assertEqual(result[0], "lodash")
        self.assertEqual(result[1], 0)

    def test_empty_registry_flags_nothing(self):
        empty = protected_names.from_names([])
        self.assertIsNone(empty.nearest("langchian"))


class ScorerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.registry = protected_names.from_names(INVENTORY, source="test")

    def test_inventory_branch_scores_without_any_vocabulary(self):
        """With brands disabled, only the generalizing branch can score."""
        verdict = score_indicator(
            "pypi:langchian",
            indicator_type="package",
            protected=self.registry,
            brands=(),
        )
        self.assertGreaterEqual(verdict.score, TRIAGE_THRESHOLD)
        self.assertTrue(any("protected dependency inventory" in r for r in verdict.reasons))

    def test_no_registry_means_no_inventory_signal(self):
        verdict = score_indicator("pypi:langchian", indicator_type="package", brands=())
        self.assertLess(verdict.score, TRIAGE_THRESHOLD)
        self.assertFalse(
            any("protected dependency inventory" in r for r in verdict.reasons)
        )

    def test_reason_names_the_real_package(self):
        verdict = score_indicator(
            "pypi:transfomers",
            indicator_type="package",
            protected=self.registry,
            brands=(),
        )
        self.assertTrue(
            any("transformers" in r for r in verdict.reasons),
            "a finding must name the package it believes is being imitated",
        )


class ManifestSourcingTests(unittest.TestCase):
    def test_registry_builds_from_manifests_including_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "package.json").write_text(
                json.dumps(
                    {
                        "name": "internal-service",
                        "dependencies": {"langchain": "^0.1.0"},
                        "devDependencies": {"transformers": "^4.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            registry = protected_names.from_manifests(root)
            self.assertIn("langchain", registry.names)
            self.assertIn("transformers", registry.names)
            self.assertIn("internal-service", registry.names)
            self.assertIsNotNone(registry.nearest("langchian"))

    def test_malformed_manifests_are_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{not json", encoding="utf-8")
            registry = protected_names.from_manifests(root)
            self.assertEqual(registry.names, set())


class PublishedMeasurementTests(unittest.TestCase):
    """The published recall figures must stay attached to the current code."""

    RESULTS = Path(__file__).resolve().parents[1] / "docs" / "detections" / "evaluation-relevance-recall.json"

    def setUp(self):
        if not self.RESULTS.is_file():
            self.skipTest("recall measurement has not been run in this checkout")
        self.results = json.loads(self.RESULTS.read_text(encoding="utf-8"))

    def test_both_ecosystems_measured(self):
        for eco in ("npm", "pypi"):
            self.assertIn(eco, self.results)

    def test_measurement_is_declared_external(self):
        for eco, data in self.results.items():
            with self.subTest(ecosystem=eco):
                self.assertEqual(data["measurement_class"], "external")
                self.assertIn("not authored by this repository", data["measurement_note"])

    def test_vocabulary_held_out_recall_is_recorded_as_zero(self):
        """The failure that motivated the fix must stay visible."""
        for eco, data in self.results.items():
            with self.subTest(ecosystem=eco):
                self.assertEqual(
                    data["recall_held_out"]["count"],
                    0,
                    "if this is no longer zero the vocabulary was widened to fit the "
                    "test, which is the thing this measurement exists to prevent",
                )

    def test_inventory_mechanism_beats_vocabulary(self):
        for eco, data in self.results.items():
            with self.subTest(ecosystem=eco):
                self.assertGreater(
                    data["recall_inventory_mechanism"]["rate"],
                    data["recall_held_out"]["rate"],
                )

    def test_recall_is_zero_wherever_inventory_coverage_is_absent(self):
        """The operating characteristic, asserted rather than described."""
        for eco, data in self.results.items():
            for row in data["inventory_coverage_sweep"]:
                with self.subTest(ecosystem=eco, coverage=row["inventory_coverage"]):
                    self.assertEqual(
                        row["imitations_of_uncovered_names"]["count"],
                        0,
                        "an imitation of a name outside the inventory must never be "
                        "caught; if it is, the branch is matching on something else",
                    )

    def test_false_positive_cost_is_published(self):
        for eco, data in self.results.items():
            with self.subTest(ecosystem=eco):
                holdout = data["benign_control"]["inventory_branch_holdout"]
                self.assertGreater(holdout["total"], 0)
                self.assertIn("wilson_ci_95", holdout)


if __name__ == "__main__":
    unittest.main()
