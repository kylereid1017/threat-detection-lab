"""Unit tests for tools.evaluate_relevance_recall."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.evaluate_relevance_recall import (
    _edit_budget,
    coverage_sweep,
    evaluate,
    label_ai_imitation,
    load_benign_names,
    load_corpus,
    main,
    rate,
)
import tools.evaluate_relevance_recall as err


class EvaluateRelevanceRecallTests(unittest.TestCase):
    def test_edit_budget(self):
        self.assertEqual(_edit_budget("short"), 1)
        self.assertEqual(_edit_budget("openai"), 1)
        self.assertEqual(_edit_budget("transformers"), 2)

    def test_label_ai_imitation(self):
        refs = ["openai", "anthropic", "langchain"]
        # Substring
        self.assertEqual(label_ai_imitation("openai-helper", refs), ("openai", "contains"))
        self.assertEqual(label_ai_imitation("anthropic-client", refs), ("anthropic", "contains"))
        # Typosquat (within edit budget)
        self.assertEqual(label_ai_imitation("opneai", refs), ("openai", "typosquat"))
        # Unrelated
        self.assertIsNone(label_ai_imitation("express", refs))
        self.assertIsNone(label_ai_imitation("", refs))

    def test_load_corpus_and_load_benign_names(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            jsonl = p / "corpus.jsonl"
            jsonl.write_text(
                '{"name": "pkg-a"}\n{"name": "pkg-b"}\n', encoding="utf-8"
            )
            names = load_corpus(jsonl)
            self.assertEqual(names, ["pkg-a", "pkg-b"])

            sub = p / "node_modules" / "demo"
            sub.mkdir(parents=True)
            (sub / "package.json").write_text(
                json.dumps({"name": "demo-pkg"}), encoding="utf-8"
            )
            benign = load_benign_names(p)
            self.assertIn("demo-pkg", benign)

    def test_rate_calculation(self):
        zero = rate(0, 0)
        self.assertEqual(zero["rate"], 0.0)
        self.assertEqual(zero["count"], 0)

        calc = rate(10, 100)
        self.assertEqual(calc["rate"], 0.1)
        self.assertEqual(len(calc["wilson_ci_95"]), 2)

    def test_coverage_sweep(self):
        labeled = [
            ("openai-helper", "openai", "contains"),
            ("langchain-extra", "langchain", "contains"),
        ]
        sweep = coverage_sweep(
            "npm", labeled, ["openai", "langchain"], fractions=(0.0, 1.0)
        )
        self.assertEqual(len(sweep), 2)
        self.assertEqual(sweep[0]["inventory_coverage"], 0.0)
        self.assertEqual(sweep[1]["inventory_coverage"], 1.0)

    def test_evaluate_and_main_with_fixture(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            corp_dir = p / "corpus"
            corp_dir.mkdir()
            (corp_dir / "testeco_acquisition-lock.json").write_text(
                json.dumps({"dataset": "test", "snapshot_sha256": "abc"}),
                encoding="utf-8",
            )
            (corp_dir / "testeco_malicious_packages.jsonl").write_text(
                '{"name": "openai-fake", "advisory": "MAL-1"}\n'
                '{"name": "harmless-pkg", "advisory": "MAL-2"}\n',
                encoding="utf-8",
            )

            benign_dir = p / "benign"
            benign_dir.mkdir()
            (benign_dir / "package.json").write_text(
                json.dumps({"name": "regular-tool"}), encoding="utf-8"
            )

            out_json = p / "results.json"

            with patch.object(err, "CORPUS_DIR", corp_dir), \
                 patch.object(err, "RESULTS_PATH", out_json):
                res = evaluate("testeco", benign_dir=benign_dir)
                self.assertEqual(res["ecosystem"], "testeco")
                self.assertEqual(res["corpus"]["malicious_packages"], 2)

                # Test main CLI
                ret = main(["--ecosystem", "testeco", "--benign-corpus", str(benign_dir)])
                self.assertEqual(ret, 0)
                self.assertTrue(out_json.exists())

                # Test main with --no-write
                ret_nw = main(["--ecosystem", "testeco", "--no-write"])
                self.assertEqual(ret_nw, 0)

                # Test main missing ecosystem raises FileNotFoundError -> handled gracefully
                ret_missing = main(["--ecosystem", "nonexistent"])
                self.assertEqual(ret_missing, 2)


if __name__ == "__main__":
    unittest.main()
