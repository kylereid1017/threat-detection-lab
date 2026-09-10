"""Regression tests for the cloud control-plane detections.

These rules read AWS CloudTrail and Kubernetes audit events rather than process
creation, so they need their own evaluator. The process-creation harness in
`test_sigma_rules.py` coerces every fixture value to TEXT, which silently breaks
boolean comparisons: a pod spec field of `true` becomes the string "True" and
never equals the SQL literal `true`. Typed columns are used here instead.

Coverage rationale: the execution-layer rule for this campaign matches command
lines. An adversary using a cloud SDK produces no command line, and SDK use is
the normal way a training job talks to object storage. These rules exist so the
campaign is observable at the layer where the activity is actually recorded.
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]
CLOUD_RULES_DIR = ROOT / "rules" / "sigma" / "cloud"
POSITIVE_DIR = ROOT / "tests" / "fixtures" / "cloud" / "positive"
NEGATIVE_DIR = ROOT / "tests" / "fixtures" / "cloud" / "negative"

# Each positive fixture is paired with the one rule that must detect it.
FIXTURE_RULE_MAP = {
    "aws_node_role_replayed_offhost.json": "aws_cloudtrail_node_role_credentials_used_offhost.yml",
    "aws_weight_object_read_by_foreign_role.json": "aws_cloudtrail_model_weight_bulk_retrieval.yml",
    "aws_role_chain_from_node_role.json": "aws_cloudtrail_role_chain_from_workload_role.yml",
    "k8s_privileged_pod_with_runtime_socket.json": "k8s_audit_training_pod_escape_primitives.yml",
    "k8s_privileged_container_no_host_namespace.json": "k8s_audit_training_pod_escape_primitives.yml",
    "k8s_exec_into_training_pod.json": "k8s_audit_exec_into_training_workload.yml",
}

REQUIRED_PREREQ_KEYS = (
    "channel",
    "event_id",
    "audit_policy",
    "required_fields",
    "degradation_mode",
)


def sql_type(value) -> str:
    if isinstance(value, bool):
        return "INTEGER"
    if isinstance(value, int):
        return "INTEGER"
    return "TEXT"


def build_schema(*fixture_dirs: Path) -> dict[str, str]:
    """Union of every field across the corpus, with a type per column.

    A real event store has a schema wider than any single event, and a field a
    document does not carry reads as null rather than as a query error. Building
    the union here reproduces that. Evaluating each event against a table of only
    its own keys would instead make any rule referencing an absent field raise,
    which is a property of SQLite, not of the detection.
    """
    schema: dict[str, str] = {}
    for directory in fixture_dirs:
        for path in sorted(directory.glob("*.json")):
            event = json.loads(path.read_text(encoding="utf-8"))
            for key, value in event.items():
                if value is None or value == "":
                    schema.setdefault(key, "TEXT")
                else:
                    schema[key] = sql_type(value)
    return schema


def evaluate(event: dict, queries: list[str], schema: dict[str, str]) -> bool:
    """Run compiled queries against a single-row store with typed columns."""
    conn = sqlite3.connect(":memory:")
    try:
        cursor = conn.cursor()
        cols = list(schema)
        col_defs = ", ".join(f'"{c}" {schema[c]}' for c in cols)
        cursor.execute(f"CREATE TABLE events ({col_defs})")
        row = []
        for col in cols:
            value = event.get(col)
            row.append(int(value) if isinstance(value, bool) else value)
        cursor.execute(
            f"INSERT INTO events VALUES ({', '.join('?' * len(cols))})", row
        )
        for query in queries:
            if cursor.execute(query.replace("<TABLE_NAME>", "events")).fetchall():
                return True
        return False
    finally:
        conn.close()


class CloudRuleCompilationTests(unittest.TestCase):
    def test_every_cloud_rule_compiles(self):
        backend = sqliteBackend()
        rules = sorted(CLOUD_RULES_DIR.glob("*.yml"))
        self.assertGreaterEqual(len(rules), 5, "cloud rule set is incomplete")
        for path in rules:
            with self.subTest(rule=path.name):
                queries = backend.convert(
                    SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
                )
                self.assertEqual(len(queries), 1)

    def test_every_cloud_rule_declares_telemetry_prerequisites(self):
        for path in sorted(CLOUD_RULES_DIR.glob("*.yml")):
            with self.subTest(rule=path.name):
                collection = SigmaCollection.from_yaml(
                    path.read_text(encoding="utf-8"), resolve_references=False
                )
                custom = getattr(collection.rules[0], "custom_attributes", {})
                self.assertIn("telemetry_prerequisites", custom)
                prereqs = custom["telemetry_prerequisites"]
                for key in REQUIRED_PREREQ_KEYS:
                    self.assertIn(key, prereqs, f"{path.name} missing {key}")
                self.assertGreater(len(prereqs["required_fields"]), 0)

    def test_log_sources_are_control_plane_not_process_creation(self):
        """The point of this rule set is the telemetry layer it reads."""
        allowed = {("aws", "cloudtrail"), ("kubernetes", "audit")}
        for path in sorted(CLOUD_RULES_DIR.glob("*.yml")):
            with self.subTest(rule=path.name):
                rule = SigmaCollection.from_yaml(
                    path.read_text(encoding="utf-8"), resolve_references=False
                ).rules[0]
                self.assertIn(
                    (rule.logsource.product, rule.logsource.service),
                    allowed,
                    f"{path.name} is not a control-plane rule",
                )


class CloudFixtureRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        backend = sqliteBackend()
        cls.queries = {
            path.name: backend.convert(
                SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
            )
            for path in sorted(CLOUD_RULES_DIR.glob("*.yml"))
        }
        cls.schema = build_schema(POSITIVE_DIR, NEGATIVE_DIR)

    def test_each_positive_fixture_matches_its_rule(self):
        for fixture_name, rule_name in FIXTURE_RULE_MAP.items():
            with self.subTest(fixture=fixture_name):
                path = POSITIVE_DIR / fixture_name
                self.assertTrue(path.exists(), f"missing fixture {fixture_name}")
                event = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(
                    evaluate(event, self.queries[rule_name], self.schema),
                    f"{rule_name} did not detect {fixture_name}",
                )

    def test_no_negative_fixture_matches_any_rule(self):
        fixtures = sorted(NEGATIVE_DIR.glob("*.json"))
        self.assertGreater(len(fixtures), 0)
        fired = []
        for path in fixtures:
            event = json.loads(path.read_text(encoding="utf-8"))
            for rule_name, queries in self.queries.items():
                if evaluate(event, queries, self.schema):
                    fired.append(f"{path.name} triggered {rule_name}")
        self.assertEqual([], fired, f"false positives: {fired}")

    def test_identity_not_object_pattern_is_the_discriminator(self):
        """The same checkpoint object read by the pipeline role must not alert.

        If this ever inverts, the rule has degraded into a filename match and
        will alert on the training job it is meant to protect.
        """
        rule = "aws_cloudtrail_model_weight_bulk_retrieval.yml"
        adversary = json.loads(
            (POSITIVE_DIR / "aws_weight_object_read_by_foreign_role.json").read_text(
                encoding="utf-8"
            )
        )
        pipeline = json.loads(
            (NEGATIVE_DIR / "aws_weight_read_by_pipeline_role.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            adversary["requestParameters.key"], pipeline["requestParameters.key"]
        )
        self.assertTrue(evaluate(adversary, self.queries[rule], self.schema))
        self.assertFalse(evaluate(pipeline, self.queries[rule], self.schema))


if __name__ == "__main__":
    unittest.main()
