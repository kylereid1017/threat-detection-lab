"""Unit tests for newly added YARA, Sigma, and Correlation detection rules."""

import unittest
from pathlib import Path

import yara
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"


class NewDetectionRulesTests(unittest.TestCase):
    def test_developer_malicious_package_hooks_yara_compilation_and_match(self):
        yara_path = RULES_DIR / "yara" / "developer_malicious_package_hooks.yar"
        self.assertTrue(yara_path.exists())
        compiled = yara.compile(filepath=str(yara_path))

        # Positive case: package.json postinstall hook with base64 eval
        pos_payload = '{"name":"ai-bench","scripts":{"postinstall":"node -e \\"eval(Buffer.from(\'dmFyIGE9MQ==\',\'base64\').toString())\\""}}'
        matches = compiled.match(data=pos_payload.encode("utf-8"))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "Suspicious_Developer_Package_Lifecycle_Hooks")

        # Positive case: setup.py with install cmdclass override fetching url
        pos_setup_py = "from setuptools import setup\nimport urllib.request\nclass Custom(install):\n  def run(self):\n    urllib.request.urlopen('https://stage.invalid')\n    install.run(self)\nsetup(cmdclass={'install': Custom})"
        matches_py = compiled.match(data=pos_setup_py.encode("utf-8"))
        self.assertEqual(len(matches_py), 1)

        # Negative case: benign package.json
        neg_payload = '{"name":"lodash","version":"4.17.21","scripts":{"test":"mocha"}}'
        matches_neg = compiled.match(data=neg_payload.encode("utf-8"))
        self.assertEqual(len(matches_neg), 0)

    def test_macos_dev_credential_theft_sigma_rule(self):
        rule_path = RULES_DIR / "sigma" / "proc_creation_macos_dev_credential_theft.yml"
        self.assertTrue(rule_path.exists())
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
        backend = sqliteBackend()
        queries = backend.convert(collection)
        self.assertGreater(len(queries), 0)

    def test_cloud_imds_checkpoint_exfiltration_sigma_rule(self):
        rule_path = RULES_DIR / "sigma" / "proc_creation_cloud_imds_checkpoint_exfiltration.yml"
        self.assertTrue(rule_path.exists())
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
        backend = sqliteBackend()
        queries = backend.convert(collection)
        self.assertGreater(len(queries), 0)

    def test_correlation_rules_parse_cleanly(self):
        corr_dir = RULES_DIR / "sigma" / "correlation"
        for corr_file in [
            corr_dir / "correlation_supply_chain_credential_theft.yml",
            corr_dir / "correlation_imds_checkpoint_exfiltration.yml",
        ]:
            self.assertTrue(corr_file.exists(), f"Correlation rule {corr_file.name} missing")
            collection = SigmaCollection.from_yaml(
                corr_file.read_text(encoding="utf-8"), resolve_references=False
            )
            self.assertGreater(len(collection.rules), 0)
            rule = collection.rules[0]
            self.assertTrue(rule.title)
            self.assertEqual(str(rule.level.name).lower(), "critical")


if __name__ == "__main__":
    unittest.main()
