"""Unit tests for tools.cti.cli."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.cti.cli import cmd_score, main


class CtiCliTests(unittest.TestCase):
    def test_cmd_score(self):
        ret = cmd_score("anthropic-careers.invalid")
        self.assertEqual(ret, 0)

        ret_benign = cmd_score("harmless-regular-domain.invalid")
        self.assertEqual(ret_benign, 0)

    def test_main_with_score_flag(self):
        ret = main(["--score", "openai-login-portal.invalid"])
        self.assertEqual(ret, 0)

    def test_main_summary_only(self):
        ret = main(["--summary-only"])
        self.assertEqual(ret, 0)

    def test_main_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ret = main(["--out", tmp_dir, "--top", "5"])
            self.assertEqual(ret, 0)
            p = Path(tmp_dir)
            files = list(p.iterdir())
            self.assertGreater(len(files), 0)


if __name__ == "__main__":
    unittest.main()
