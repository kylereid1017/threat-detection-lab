"""Tests for telemetry-layer coverage mapping.

The mapping's whole value is the layer classification, so most of these tests pin
individual log sources to the layer they must land in. Everything downstream is
counting.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.telemetry_coverage import (
    CONTROL_PLANE_TECHNIQUES,
    build_map,
    classify_layer,
    parse_rule,
)

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "docs" / "brittleness"


class LayerClassificationTests(unittest.TestCase):
    def test_process_creation_is_endpoint_process(self):
        for product in ("windows", "linux", "macos"):
            with self.subTest(product=product):
                self.assertEqual(
                    classify_layer({"product": product, "category": "process_creation"}),
                    "endpoint_process",
                )

    def test_cloud_products_are_control_plane(self):
        for source in (
            {"product": "aws", "service": "cloudtrail"},
            {"product": "kubernetes", "service": "audit"},
            {"product": "gcp", "service": "gcp.audit"},
            {"product": "azure", "service": "activitylogs"},
        ):
            with self.subTest(source=source):
                self.assertEqual(classify_layer(source), "cloud_control_plane")

    def test_identity_providers_are_their_own_layer(self):
        self.assertEqual(classify_layer({"product": "okta", "service": "okta"}), "identity")

    def test_network_categories(self):
        for category in ("network_connection", "dns_query", "proxy", "firewall"):
            with self.subTest(category=category):
                self.assertEqual(
                    classify_layer({"product": "windows", "category": category}), "network"
                )

    def test_endpoint_non_process_categories(self):
        for category in ("file_event", "registry_set", "image_load"):
            with self.subTest(category=category):
                self.assertEqual(
                    classify_layer({"product": "windows", "category": category}),
                    "endpoint_other",
                )

    def test_unknown_source_falls_back_to_application(self):
        self.assertEqual(classify_layer({}), "application")

    def test_process_creation_wins_over_cloud_product(self):
        """A CloudTrail-tagged process rule is still a process rule.

        This ordering is deliberate. A rule reading command lines on a cloud host
        is defeated by SDK use regardless of the product field, so classifying it
        as control-plane coverage would overstate exactly the thing this mapping
        exists to measure.
        """
        self.assertEqual(
            classify_layer({"product": "aws", "category": "process_creation"}),
            "endpoint_process",
        )


class RuleParsingTests(unittest.TestCase):
    def test_technique_tags_are_extracted(self):
        rule = parse_rule(
            "title: T\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1552.005\n"
            "  - attack.T1530\n"
            "logsource:\n  product: aws\n  service: cloudtrail\n"
            "detection:\n  sel:\n    eventName: GetObject\n  condition: sel\n",
            "r.yml",
        )
        self.assertIsNotNone(rule)
        self.assertEqual(sorted(rule["techniques"]), ["t1530", "t1552.005"])
        self.assertEqual(rule["layer"], "cloud_control_plane")

    def test_tactic_tags_are_not_techniques(self):
        rule = parse_rule(
            "title: T\ntags:\n  - attack.execution\n"
            "logsource:\n  category: process_creation\n"
            "detection:\n  sel:\n    Image: x\n  condition: sel\n",
            "r.yml",
        )
        self.assertEqual(rule["techniques"], [])

    def test_rules_without_detection_are_skipped(self):
        self.assertIsNone(parse_rule("title: C\ncorrelation:\n  type: temporal\n", "c.yml"))

    def test_malformed_yaml_is_skipped(self):
        self.assertIsNone(parse_rule("a: [b: c: d", "bad.yml"))


class CoverageMapTests(unittest.TestCase):
    def _rule(self, layer: str, techniques: list[str]) -> dict:
        return {"name": "r", "title": "r", "layer": layer, "techniques": techniques}

    def test_single_layer_techniques_are_identified(self):
        report = build_map(
            [
                self._rule("endpoint_process", ["t1059"]),
                self._rule("endpoint_process", ["t1059"]),
                self._rule("cloud_control_plane", ["t1078.004"]),
                self._rule("endpoint_process", ["t1078.004"]),
            ]
        )
        singles = {e["technique"] for e in report["single_layer_techniques"]}
        self.assertIn("t1059", singles)
        self.assertNotIn("t1078.004", singles)

    def test_absent_control_plane_technique_is_reported_as_missing(self):
        report = build_map([self._rule("endpoint_process", ["t1059"])])
        statuses = {e["technique"]: e["status"] for e in report["control_plane_assessment"]}
        self.assertEqual(statuses["t1530"], "no rules in corpus")

    def test_endpoint_only_coverage_is_distinguished_from_partial(self):
        endpoint_only = build_map([self._rule("endpoint_process", ["t1530"])])
        mixed = build_map(
            [
                self._rule("endpoint_process", ["t1530"]),
                self._rule("network", ["t1530"]),
            ]
        )
        self.assertEqual(
            next(
                e["status"]
                for e in endpoint_only["control_plane_assessment"]
                if e["technique"] == "t1530"
            ),
            "covered only at the endpoint process layer",
        )
        self.assertEqual(
            next(
                e["status"]
                for e in mixed["control_plane_assessment"]
                if e["technique"] == "t1530"
            ),
            "no control-plane coverage",
        )

    def test_layer_shares_sum_to_one(self):
        report = build_map(
            [
                self._rule("endpoint_process", ["t1059"]),
                self._rule("cloud_control_plane", ["t1530"]),
                self._rule("network", []),
            ]
        )
        # Shares are rounded to four decimals for the report, so three equal
        # thirds sum to 0.9999 rather than 1.0. Allow the rounding, not a real gap.
        self.assertAlmostEqual(sum(report["layer_share"].values()), 1.0, delta=0.001)

    def test_every_control_plane_technique_is_assessed(self):
        report = build_map([self._rule("endpoint_process", ["t1059"])])
        assessed = {e["technique"] for e in report["control_plane_assessment"]}
        self.assertEqual(assessed, set(CONTROL_PLANE_TECHNIQUES))


class LocalCorpusCoverageTests(unittest.TestCase):
    """This repository's stated coverage claim, asserted rather than described."""

    REPORT = REPORTS / "telemetry_coverage_threat-detection-lab.json"

    def setUp(self):
        if not self.REPORT.is_file():
            self.skipTest("coverage mapping has not been run in this checkout")
        self.report = json.loads(self.REPORT.read_text(encoding="utf-8"))

    def test_cloud_techniques_are_covered_at_the_control_plane(self):
        statuses = {
            e["technique"]: e["status"] for e in self.report["control_plane_assessment"]
        }
        for technique in ("t1552.005", "t1530", "t1567.002", "t1611"):
            with self.subTest(technique=technique):
                self.assertEqual(
                    statuses[technique],
                    "control-plane covered",
                    "the cloud rules exist specifically so these techniques are not "
                    "detected only by matching command lines",
                )

    def test_control_plane_share_is_material(self):
        share = self.report["layer_share"].get("cloud_control_plane", 0.0)
        self.assertGreater(share, 0.2)


class CoverageCliTests(unittest.TestCase):
    def test_cli_runs_local_and_no_write(self):
        from tools.telemetry_coverage import main
        ret = main(["--rules", "rules/sigma", "--no-write"])
        self.assertEqual(ret, 0)

    def test_cli_writes_report(self):
        import tempfile
        from tools.telemetry_coverage import main
        with tempfile.TemporaryDirectory() as tmp_dir:
            ret = main(["--rules", "rules/sigma", "--out", tmp_dir, "--label", "test-cov"])
            self.assertEqual(ret, 0)
            self.assertTrue((Path(tmp_dir) / "telemetry_coverage_test-cov.json").exists())

    def test_cli_invalid_rules_dir(self):
        from tools.telemetry_coverage import main
        ret = main(["--rules", "nonexistent_dir_for_test"])
        self.assertEqual(ret, 2)


if __name__ == "__main__":
    unittest.main()
