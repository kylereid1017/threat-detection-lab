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

    def test_every_rule_has_telemetry_prerequisites(self):
        rule_files = list(SIGMA_RULES_DIR.glob("*.yml"))
        corr_files = list((SIGMA_RULES_DIR / "correlation").glob("*.yml"))
        all_rules = rule_files + corr_files
        self.assertGreater(len(all_rules), 0)

        for rule_file in all_rules:
            collection = SigmaCollection.from_yaml(
                rule_file.read_text(encoding="utf-8"), resolve_references=False
            )
            rule = collection.rules[0]
            custom = getattr(rule, "custom_attributes", {})
            self.assertIn(
                "telemetry_prerequisites",
                custom,
                f"{rule_file.name} must specify telemetry_prerequisites",
            )
            prereqs = custom["telemetry_prerequisites"]
            self.assertIn("channel", prereqs, f"{rule_file.name} missing telemetry channel")
            self.assertIn("event_id", prereqs, f"{rule_file.name} missing event_id")
            self.assertIn("audit_policy", prereqs, f"{rule_file.name} missing audit_policy")
            self.assertIn("required_fields", prereqs, f"{rule_file.name} missing required_fields")
            self.assertIn("degradation_mode", prereqs, f"{rule_file.name} missing degradation_mode")
            self.assertGreater(len(prereqs["required_fields"]), 0)


class SigmaRuleFixtureRegressionTests(unittest.TestCase):
    """Executes rule detection logic against positive and negative synthetic telemetry fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.backend = sqliteBackend()
        cls.rule_queries = {}
        for rpath in SIGMA_RULES_DIR.glob("*.yml"):
            col = SigmaCollection.from_yaml(rpath.read_text(encoding="utf-8"))
            cls.rule_queries[rpath.name] = cls.backend.convert(col)

    def _evaluate_event(self, event_dict: dict, rule_name: str | None = None) -> bool:
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
        queries_to_test = []
        if rule_name:
            queries_to_test = self.rule_queries.get(rule_name, [])
        else:
            for q_list in self.rule_queries.values():
                queries_to_test.extend(q_list)

        for query in queries_to_test:
            sql = query.replace("<TABLE_NAME>", "events")
            rows = cursor.execute(sql).fetchall()
            if rows:
                return True
        return False

    def test_every_positive_fixture_matches_its_rule(self):
        rule_fixture_map = {
            "proc_creation_win_defense_evasion_tampering.yml": [
                "clickfix_wevtutil_log_clear.json",
                "clickfix_defender_disable.json",
            ],
            "proc_creation_win_rundll32_lsass_dump.yml": [
                "clickfix_rundll32_comsvcs_dump.json",
                "clickfix_rundll32_comsvcs_ordinal.json",
            ],
            "proc_creation_win_schtasks_persistence.yml": [
                "clickfix_schtasks_logon_powershell.json",
                "clickfix_schtasks_minute_cmd.json",
            ],
            "proc_creation_win_explorer_clickfix_execution.yml": [
                "clickfix_cmd_powershell_staging.json",
                "clickfix_curl_temp_exec.json",
                "clickfix_mshta_remote.json",
                "clickfix_powershell_encoded.json",
                "clickfix_powershell_irm_iex.json",
                "clickfix_powershell_webclient_hidden.json",
            ],
        }

        for rule_name, fixture_names in rule_fixture_map.items():
            for fname in fixture_names:
                fpath = POSITIVE_DIR / fname
                self.assertTrue(fpath.exists(), f"Fixture {fname} does not exist")
                event = json.loads(fpath.read_text(encoding="utf-8"))
                self.assertTrue(
                    self._evaluate_event(event, rule_name=rule_name),
                    f"Rule {rule_name} failed to detect positive fixture {fname}"
                )

    def test_every_negative_fixture_does_not_match_any_rule(self):
        fixtures = sorted(NEGATIVE_DIR.glob("*.json"))
        self.assertGreater(len(fixtures), 0, "no negative fixtures found")
        false_positives = []
        for fixture in fixtures:
            event = json.loads(fixture.read_text(encoding="utf-8"))
            for rule_name in self.rule_queries:
                if self._evaluate_event(event, rule_name=rule_name):
                    false_positives.append(f"{fixture.name} triggered {rule_name}")
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
