"""Correlation rules must resolve their component rules and express real ordering.

The existing correlation tests parse each correlation file in isolation with
`resolve_references=False`. That is why two correlation rules shipped declaring
`temporal_ordered` while referencing a single component stage: nothing ever
resolved the references, so a correlation that could not express its own
description still parsed cleanly and passed.

These tests load every production rule into one collection, resolve references,
and assert that an ordered correlation actually has stages to order.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
CORRELATION_DIR = SIGMA_DIR / "correlation"
CLOUD_DIR = SIGMA_DIR / "cloud"

# Correlation types whose semantics require more than one component stage.
MULTI_STAGE_TYPES = {"temporal", "temporal_ordered"}


def load_all_rules() -> SigmaCollection:
    """Every production rule and correlation, resolved as one collection."""
    paths = (
        sorted(SIGMA_DIR.glob("*.yml"))
        + sorted(CLOUD_DIR.glob("*.yml"))
        + sorted(CORRELATION_DIR.glob("*.yml"))
    )
    return SigmaCollection.merge(
        SigmaCollection.from_yaml(p.read_text(encoding="utf-8"), resolve_references=False)
        for p in paths
    )


class CorrelationResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.collection = load_all_rules()
        cls.collection.resolve_rule_references()
        cls.correlations = [
            r for r in cls.collection.rules if isinstance(r, SigmaCorrelationRule)
        ]

    def test_correlation_rules_are_present(self):
        self.assertGreaterEqual(len(self.correlations), 2)

    def test_every_reference_resolves_to_a_real_rule(self):
        for correlation in self.correlations:
            for ref in correlation.rules:
                with self.subTest(correlation=correlation.title, reference=ref.reference):
                    self.assertIsNotNone(
                        ref.rule,
                        f"{correlation.title} references {ref.reference}, which does not exist",
                    )

    def test_ordered_correlations_have_more_than_one_stage(self):
        for correlation in self.correlations:
            corr_type = str(getattr(correlation.type, "name", correlation.type)).lower()
            if corr_type not in MULTI_STAGE_TYPES:
                continue
            with self.subTest(correlation=correlation.title):
                self.assertGreaterEqual(
                    len(correlation.rules),
                    2,
                    f"{correlation.title} declares {corr_type} over "
                    f"{len(correlation.rules)} stage(s); an ordering needs at least two",
                )

    def test_group_by_fields_are_declared(self):
        for correlation in self.correlations:
            with self.subTest(correlation=correlation.title):
                self.assertTrue(
                    correlation.group_by,
                    f"{correlation.title} has no group-by field, so it correlates across "
                    "unrelated entities",
                )

    def test_every_reference_matches_a_component_name_or_id(self):
        """References resolve by rule name or by rule id; both are valid Sigma."""
        referenced = {ref.reference for c in self.correlations for ref in c.rules}
        identifiers: set[str] = set()
        for rule in self.collection.rules:
            if getattr(rule, "name", None):
                identifiers.add(rule.name)
            if getattr(rule, "id", None):
                identifiers.add(str(rule.id))
        missing = referenced - identifiers
        self.assertEqual(
            set(), missing, f"correlation references with no matching component rule: {missing}"
        )


class CorrelationStageBindingTests(unittest.TestCase):
    """Every correlation stage must bind to a rule file the engine can evaluate.

    An unresolved stage does not raise. It produces a correlation whose stage has
    no rule, which fails at evaluation time as a logged warning and a correlation
    that can never match. Silent non-firing is indistinguishable from a quiet
    environment, so it is asserted here instead.
    """

    def test_every_stage_binds_to_a_rule_file(self):
        from tools.swarm.models import CorrelationRule
        from tools.swarm.telemetry_replay import TelemetryReplayEngine

        engine = TelemetryReplayEngine()
        for path in sorted(CORRELATION_DIR.glob("correlation_*.yml")):
            with self.subTest(correlation=path.name):
                rule = CorrelationRule.from_yaml(path, rule_resolver=engine._resolve_rule)
                self.assertGreater(len(rule.stages), 0, f"{path.name} has no stages")
                for stage in rule.stages:
                    self.assertTrue(
                        stage.rule_path or stage.rule_yaml,
                        f"{path.name} stage '{stage.name}' resolved to no rule; "
                        "this correlation can never fire",
                    )


class CorrelationTelemetryHonestyTests(unittest.TestCase):
    """Cross-source correlations must state the field mapping they depend on."""

    def test_cross_source_correlation_declares_its_join_requirement(self):
        path = CORRELATION_DIR / "correlation_imds_checkpoint_exfiltration.yml"
        rule = SigmaCollection.from_yaml(
            path.read_text(encoding="utf-8"), resolve_references=False
        ).rules[0]
        prereqs = getattr(rule, "custom_attributes", {}).get("telemetry_prerequisites", {})
        self.assertIn("audit_policy", prereqs)
        policy = prereqs["audit_policy"].lower()
        self.assertIn(
            "normalized",
            policy,
            "a correlation joining host telemetry to CloudTrail must state that the join "
            "field does not exist in either raw source",
        )


if __name__ == "__main__":
    unittest.main()
