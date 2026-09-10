"""Unit tests for tools.acquire_malicious_corpus."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tools.acquire_malicious_corpus as amc


class AcquireMaliciousCorpusTests(unittest.TestCase):
    def test_dedupe(self):
        pkgs = [
            {"name": "pkg-a", "ecosystem": "npm", "advisory": "MAL-2025-002"},
            {"name": "pkg-a", "ecosystem": "npm", "advisory": "MAL-2025-001"},
            {"name": "pkg-b", "ecosystem": "npm", "advisory": "MAL-2025-003"},
        ]
        deduped = amc.dedupe(pkgs)
        self.assertEqual(len(deduped), 2)
        # Keeps earliest advisory
        self.assertEqual(deduped[0]["advisory"], "MAL-2025-001")
        self.assertEqual(deduped[1]["name"], "pkg-b")

    def test_sha256_text(self):
        h = amc.sha256_text("hello world")
        self.assertEqual(h, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_write_and_load_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            pkgs = [
                {"name": "test-mal", "ecosystem": "npm", "advisory": "MAL-TEST-1"},
            ]
            lock = amc.write_snapshot(pkgs, "npm", p, "2026-09-06")
            self.assertEqual(lock["package_count"], 1)
            self.assertTrue((p / "npm_malicious_packages.jsonl").exists())
            self.assertTrue((p / "npm_acquisition-lock.json").exists())

            loaded = list(amc.load_snapshot(p / "npm_malicious_packages.jsonl"))
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["name"], "test-mal")

    def test_list_packages(self):
        mock_listing = (
            "osv/malicious/npm/mal-one/MAL-2025-1.json\n"
            "osv/malicious/npm/@scope/mal-two/MAL-2025-2.json\n"
            "osv/malicious/pypi/py-mal/MAL-2025-3.json\n"
            "other/unrelated.txt\n"
        )
        with patch.object(amc, "_clone_index", return_value=mock_listing):
            with patch.object(amc, "_force_rmtree"):
                npm_pkgs = amc.list_packages("npm")
                self.assertEqual(len(npm_pkgs), 2)
                names = [p["name"] for p in npm_pkgs]
                self.assertIn("mal-one", names)
                self.assertIn("@scope/mal-two", names)

                pypi_pkgs = amc.list_packages("pypi")
                self.assertEqual(len(pypi_pkgs), 1)
                self.assertEqual(pypi_pkgs[0]["name"], "py-mal")

                with self.assertRaises(amc.AcquisitionError):
                    amc.list_packages("rubygems")

    def test_main_cli(self):
        mock_pkgs = [{"name": "fake-mal", "ecosystem": "npm", "advisory": "MAL-1"}]
        with patch.object(amc, "list_packages", return_value=mock_pkgs):
            # With --no-write
            ret_nw = amc.main(["--ecosystem", "npm", "--no-write"])
            self.assertEqual(ret_nw, 0)

            # With --out
            with tempfile.TemporaryDirectory() as tmp_dir:
                ret = amc.main(["--ecosystem", "npm", "--out", tmp_dir, "--limit", "1"])
                self.assertEqual(ret, 0)
                self.assertTrue((Path(tmp_dir) / "npm_malicious_packages.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
