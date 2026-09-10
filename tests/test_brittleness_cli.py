"""Unit tests for tools.brittleness.cli."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.brittleness.cli import main


class BrittlenessCliTests(unittest.TestCase):
    def test_cli_local_rules_no_write(self):
        ret = main(["--rules", "rules/sigma", "--no-write", "--top", "3"])
        self.assertEqual(ret, 0)

    def test_cli_local_rules_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ret = main(["--rules", "rules/sigma", "--out", tmp_dir, "--label", "test-corpus"])
            self.assertEqual(ret, 0)
            out_file = Path(tmp_dir) / "brittleness_test-corpus.json"
            self.assertTrue(out_file.exists())

    def test_cli_nonexistent_directory(self):
        ret = main(["--rules", "nonexistent_directory_for_test"])
        self.assertEqual(ret, 2)

    def test_cli_empty_directory_no_rules(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ret = main(["--rules", tmp_dir])
            self.assertEqual(ret, 2)

    def test_cli_git_corpus_error_handled(self):
        ret = main(["--git-corpus", "https://invalid.example.com/not-a-repo.git"])
        self.assertEqual(ret, 2)


if __name__ == "__main__":
    unittest.main()
