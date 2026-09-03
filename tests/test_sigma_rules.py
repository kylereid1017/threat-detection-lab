import json
import sqlite3
import unittest
import uuid
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.sqlite import sqliteBackend


ROOT = Path(__file__).resolve().parents[1]
SIGMA_RULES_DIR = ROOT / "rules" / "sigma"
RULE_PATH = SIGMA_RULES_DIR / "proc_creation_win_explorer_clickfix_execution.yml"
POSITIVE_DIR = ROOT / "tests" / "fixtures" / "sigma" / "positive"
NEGATIVE_DIR = ROOT / "tests" / "fixtures" / "sigma" / "negative"


class SigmaRuleSchemaTests(unittest.TestCase):
    """Validates Sigma rule syntax, schema, and metadata compliance."""

    def test_all_sigma_rules_parse_cleanly(self):
        rule_files = list(SIGMA_RULES_DIR.glob("*.yml"))
        self.assertGreater(len(rule_files), 0, "no Sigma rule files found")
        for rule_file in rule_files:
            collection = SigmaCollection.from_yaml(rule_file.read_text(encoding="utf-8"))
            self.assertGreater(len(collection.rules), 0, f"no rules loaded from {rule_file.name}")
            rule = collection.rules[0]

            # Title & ID
            self.assertTrue(rule.title, f"{rule_file.name} missing title")
            self.assertIsInstance(rule.id, uuid.UUID, f"{rule_file.name} ID must be a valid UUID")

            # Logsource
            self.assertEqual(rule.logsource.category, "process_creation")
            self.assertEqual(rule.logsource.product, "windows")

            # Severity and Status
            self.assertIn(str(rule.level.name).lower(), ["low", "medium", "high", "critical"])
            self.assertIn(str(rule.status.name).lower(), ["experimental", "test", "stable"])

            # ATT&CK tags
            attack_tags = [str(t) for t in rule.tags if str(t).startswith("attack.")]
            self.assertGreater(len(attack_tags), 0, f"{rule_file.name} must have MITRE ATT&CK tags")


class SigmaRuleFixtureRegressionTests(unittest.TestCase):
    """Executes rule detection logic against positive and negative synthetic telemetry fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.collection = SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8"))
        cls.backend = sqliteBackend()
        cls.queries = cls.backend.convert(cls.collection)

    def _evaluate_event(self, event_dict: dict) -> bool:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cols = list(event_dict.keys())
        placeholders = ", ".join("?" * len(cols))
        col_defs = ", ".join(f'"{c}" TEXT' for c in cols)
        cursor.execute(f"CREATE TABLE events ({col_defs})")
        cursor.execute(
            f"INSERT INTO events VALUES ({placeholders})",
            [str(v) if v is not None else "" for v in event_dict.values()]
        )
        for query in self.queries:
            sql = query.replace("<TABLE_NAME>", "events")
            rows = cursor.execute(sql).fetchall()
            if rows:
                return True
        return False

    def test_every_positive_fixture_matches(self):
        fixtures = sorted(POSITIVE_DIR.glob("*.json"))
        self.assertGreater(len(fixtures), 0, "no positive fixtures found")
        missed = []
        for fixture in fixtures:
            event = json.loads(fixture.read_text(encoding="utf-8"))
            if not self._evaluate_event(event):
                missed.append(fixture.name)
        self.assertEqual([], missed, f"Positive fixtures failed to match: {missed}")

    def test_every_negative_fixture_does_not_match(self):
        fixtures = sorted(NEGATIVE_DIR.glob("*.json"))
        self.assertGreater(len(fixtures), 0, "no negative fixtures found")
        false_positives = []
        for fixture in fixtures:
            event = json.loads(fixture.read_text(encoding="utf-8"))
            if self._evaluate_event(event):
                false_positives.append(fixture.name)
        self.assertEqual([], false_positives, f"Negative fixtures falsely triggered: {false_positives}")


class SigmaBackendConversionTests(unittest.TestCase):
    """Tests cross-platform rule conversion to SIEM/EDR query languages."""

    @classmethod
    def setUpClass(cls):
        cls.collection = SigmaCollection.from_yaml(RULE_PATH.read_text(encoding="utf-8"))

    def test_splunk_backend_conversion(self):
        backend = SplunkBackend()
        queries = backend.convert(self.collection)
        self.assertEqual(len(queries), 1)
        query = queries[0]
        self.assertIn("ParentImage=", query)
        self.assertIn("explorer.exe", query)
        self.assertIn("CommandLine IN (", query)
        self.assertIn("powershell.exe", query)

    def test_elasticsearch_lucene_backend_conversion(self):
        backend = LuceneBackend()
        queries = backend.convert(self.collection)
        self.assertEqual(len(queries), 1)
        query = queries[0]
        self.assertIn("ParentImage:", query)
        self.assertIn("explorer.exe", query)
        self.assertIn("CommandLine:", query)
        self.assertIn("powershell.exe", query)

    def test_crowdstrike_logscale_backend_conversion(self):
        backend = LogScaleBackend()
        queries = backend.convert(self.collection)
        self.assertEqual(len(queries), 1)
        query = queries[0]
        self.assertIn("ParentImage=", query)
        self.assertIn("explorer", query)
        self.assertIn("CommandLine=", query)
        self.assertIn("powershell", query)


if __name__ == "__main__":
    unittest.main()
