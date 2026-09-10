"""Unit tests for the Agent Execution Layer Population Study.

Verifies acquisition record normalization, population metrics calculations,
manifest privilege scanning, protected imitation detection, malicious lead triage,
and maintainer hygiene analysis using deterministic offline fixtures.
"""

from __future__ import annotations

import json
import unittest
from datetime import date
from pathlib import Path

from tools.acquire_agent_registry import (
    normalize_npm_package,
    _hash_bytes,
)
from tools.evaluate_agent_population import (
    evaluate_ecosystem_scope,
    evaluate_manifest_privileges,
    evaluate_protected_imitations,
    evaluate_malicious_cross_reference,
    evaluate_maintainer_hygiene,
    run_evaluation,
    _extract_yara_string_ids,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "agent"
NPM_SAMPLE_PATH = FIXTURES_DIR / "npm_agent_sample.jsonl"
PYPI_SAMPLE_PATH = FIXTURES_DIR / "pypi_agent_sample.jsonl"
PROTECTED_NAMES_PATH = FIXTURES_DIR / "protected_names.json"
YARA_RULE_PATH = Path(__file__).resolve().parents[1] / "rules" / "yara" / "developer_malicious_package_hooks.yar"
MALICIOUS_NPM_PATH = Path(__file__).resolve().parents[1] / "corpus" / "malicious" / "npm_malicious_packages.jsonl"
MALICIOUS_PYPI_PATH = Path(__file__).resolve().parents[1] / "corpus" / "malicious" / "pypi_malicious_packages.jsonl"


class TestAgentPopulationAcquisition(unittest.TestCase):
    def test_normalize_npm_package_valid(self):
        raw = {
            "package": {
                "name": "@modelcontextprotocol/sdk",
                "version": "1.30.0",
                "description": "TypeScript SDK",
                "date": "2026-07-27T17:56:01.640Z",
                "publisher": {"username": "admin"},
                "maintainers": [{"username": "alice"}],
                "keywords": ["mcp"],
            },
            "downloads": {"weekly": 1000},
            "score": {"final": 99.0},
        }
        norm = normalize_npm_package(raw)
        self.assertIsNotNone(norm)
        self.assertEqual(norm["name"], "@modelcontextprotocol/sdk")
        self.assertEqual(norm["ecosystem"], "npm")
        self.assertEqual(norm["version"], "1.30.0")
        self.assertEqual(norm["downloads"]["weekly"], 1000)

    def test_normalize_npm_package_malformed(self):
        self.assertIsNone(normalize_npm_package({}))
        self.assertIsNone(normalize_npm_package({"package": "not-a-dict"}))
        self.assertIsNone(normalize_npm_package({"package": {"name": ""}}))

    def test_hash_bytes(self):
        data = b"test payload"
        digest = _hash_bytes(data)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, _hash_bytes(data))

    def test_fetch_npm_search_and_manifest(self):
        from unittest.mock import MagicMock, patch
        from tools import acquire_agent_registry as aar

        mock_search_data = {
            "objects": [
                {
                    "package": {
                        "name": "test-agent-tool",
                        "version": "1.0.0",
                        "description": "A test tool",
                        "date": "2026-01-01T00:00:00.000Z",
                    }
                }
            ],
            "total": 1,
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_search_data).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            records, discards, total = aar.fetch_npm_search("query", limit=1, delay=0.0)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["name"], "test-agent-tool")

        # Manifest
        mock_manifest_data = {
            "name": "test-agent-tool",
            "version": "1.0.0",
            "scripts": {"postinstall": "node setup.js"},
        }
        mock_resp_m = MagicMock()
        mock_resp_m.read.return_value = json.dumps(mock_manifest_data).encode("utf-8")
        mock_resp_m.__enter__.return_value = mock_resp_m

        with patch("urllib.request.urlopen", return_value=mock_resp_m):
            man = aar.fetch_npm_manifest("test-agent-tool")
            self.assertIsNotNone(man)
            self.assertEqual(man["name"], "test-agent-tool")

    def test_fetch_pypi_list_and_metadata(self):
        from unittest.mock import MagicMock, patch
        from tools import acquire_agent_registry as aar

        mock_simple = {
            "projects": [
                {"name": "mcp-test-server"},
                {"name": "flask"},
            ]
        }
        mock_resp_s = MagicMock()
        mock_resp_s.read.return_value = json.dumps(mock_simple).encode("utf-8")
        mock_resp_s.__enter__.return_value = mock_resp_s

        with patch("urllib.request.urlopen", return_value=mock_resp_s):
            names, total = aar.fetch_pypi_project_list()
            self.assertEqual(names, ["mcp-test-server"])
            self.assertEqual(total, 2)

        mock_meta = {
            "info": {
                "name": "mcp-test-server",
                "version": "0.1.0",
                "summary": "test MCP server",
                "author": "Alice",
                "requires_dist": ["mcp>=0.1"],
                "project_urls": {},
            },
            "releases": {
                "0.1.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]
            },
        }
        mock_resp_meta = MagicMock()
        mock_resp_meta.read.return_value = json.dumps(mock_meta).encode("utf-8")
        mock_resp_meta.__enter__.return_value = mock_resp_meta

        with patch("urllib.request.urlopen", return_value=mock_resp_meta):
            meta = aar.fetch_pypi_package_metadata("mcp-test-server")
            self.assertIsNotNone(meta)
            self.assertEqual(meta["name"], "mcp-test-server")
            self.assertEqual(meta["version"], "0.1.0")

    def test_write_snapshot_and_run_acquisition_dry_run(self):
        import tempfile
        from unittest.mock import patch
        from tools import acquire_agent_registry as aar

        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            records = [{"name": "pkg-a", "version": "1.0"}]
            lock_meta = {"dataset": "test"}
            j_path, l_path = aar.write_snapshot_and_lock(p, "npm", records, lock_meta)
            self.assertTrue(j_path.exists())
            self.assertTrue(l_path.exists())

        # Test dry-run CLI
        parser = aar.build_parser()
        args = parser.parse_args(["--ecosystem", "all", "--no-write", "--npm-limit", "1", "--pypi-limit", "1"])
        with patch.object(aar, "fetch_npm_search", return_value=([{"name": "p1", "version": "1.0"}], 0, 1)), \
             patch.object(aar, "fetch_pypi_project_list", return_value=(["mcp-pkg"], 1)), \
             patch.object(aar, "fetch_pypi_package_metadata", return_value={"name": "mcp-pkg", "version": "1.0"}):
            ret = aar.run_acquisition(args)
            self.assertEqual(ret, 0)


class TestAgentPopulationEvaluation(unittest.TestCase):
    def setUp(self):
        self.npm_records = [
            json.loads(line)
            for line in NPM_SAMPLE_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.pypi_records = [
            json.loads(line)
            for line in PYPI_SAMPLE_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.protected_names = json.loads(PROTECTED_NAMES_PATH.read_text(encoding="utf-8"))

    def test_ecosystem_scope_and_growth(self):
        res = evaluate_ecosystem_scope(self.npm_records, self.pypi_records)
        self.assertEqual(res["npm_packages_analyzed"], len(self.npm_records))
        self.assertEqual(res["pypi_packages_analyzed"], len(self.pypi_records))
        self.assertEqual(res["total_packages_analyzed"], len(self.npm_records) + len(self.pypi_records))

        # Check era distribution
        era_npm = res["era_distribution"]["npm"]
        self.assertIn("pre_mcp_launch", era_npm)
        self.assertIn("post_mcp_launch", era_npm)
        self.assertGreaterEqual(era_npm["post_mcp_launch"]["rate_pct"], 80.0)

        era_pypi = res["era_distribution"]["pypi"]
        self.assertGreater(era_pypi["pre_mcp_launch"]["count"], 0)

        # Check monthly growth curve
        growth = res["monthly_growth_curve"]
        self.assertIsInstance(growth, list)
        self.assertGreater(len(growth), 0)

    def test_manifest_privileges_and_yara(self):
        res = evaluate_manifest_privileges(self.npm_records, YARA_RULE_PATH)
        self.assertEqual(res["manifests_evaluated"], len(self.npm_records))

        # Binaries
        self.assertGreater(res["cli_binary_privilege"]["count"], 0)

        # Lifecycle hooks
        self.assertGreater(res["lifecycle_hooks_declared"]["count"], 0)
        self.assertIn("preinstall", res["hook_breakdown"])

        # YARA suspicious hooks: the sample fixture contains 2 malicious hook packages
        yara_res = res["yara_suspicious_hook_detections"]
        self.assertGreaterEqual(yara_res["count"], 2)
        matched_packages = [s["package"] for s in res["yara_match_samples"]]
        self.assertIn("fake-mcp-dropper", matched_packages)
        self.assertIn("cradle-mcp-agent", matched_packages)

    def test_protected_registry_imitations(self):
        all_pkgs = self.npm_records + self.pypi_records
        res = evaluate_protected_imitations(all_pkgs, self.protected_names)
        self.assertGreater(res["total_imitations_flagged"]["count"], 0)
        self.assertIn("compound", res["imitation_taxonomy"])
        self.assertIn("misspelling", res["imitation_taxonomy"])

        imitated_names = [i["candidate"] for i in res["sample_imitations"]]
        # e.g. langchain-mcp-impersonator, openai-mcp, openai-mcp-proxy
        self.assertTrue(any("langchain" in name or "openai" in name for name in imitated_names))

    def test_malicious_cross_reference_triage(self):
        res = evaluate_malicious_cross_reference(
            MALICIOUS_NPM_PATH,
            MALICIOUS_PYPI_PATH,
            self.npm_records,
            self.pypi_records,
        )
        self.assertEqual(res["mcp_substring_leads"]["npm_mcp_leads_count"], 138)
        self.assertEqual(res["mcp_substring_leads"]["pypi_mcp_leads_count"], 72)
        self.assertEqual(res["mcp_substring_leads"]["total_mcp_leads"], 210)

        triage = res["forensic_triage_breakdown"]
        self.assertIn("historical_pre_mcp_collision", triage)
        self.assertIn("compromised_legitimate_tooling", triage)
        self.assertIn("targeted_agent_imitation", triage)
        self.assertIn("research_canary_test", triage)

        self.assertGreater(triage["historical_pre_mcp_collision"], 0)
        self.assertGreater(triage["targeted_agent_imitation"], 0)
        self.assertGreater(triage["compromised_legitimate_tooling"], 0)

    def test_maintainer_hygiene_and_power_law(self):
        res = evaluate_maintainer_hygiene(self.npm_records, self.pypi_records)
        self.assertGreaterEqual(res["single_maintainer_concentration"]["rate_pct"], 50.0)
        self.assertIn("download_skew_power_law", res)
        power_law = res["download_skew_power_law"]
        self.assertGreater(power_law["top_1_percent_download_share_pct"], 80.0)

    def test_end_to_end_offline_evaluation(self):
        report = run_evaluation(
            npm_snapshot_path=NPM_SAMPLE_PATH,
            pypi_snapshot_path=PYPI_SAMPLE_PATH,
            npm_malicious_path=MALICIOUS_NPM_PATH,
            pypi_malicious_path=MALICIOUS_PYPI_PATH,
            yara_rule_path=YARA_RULE_PATH,
            protected_names=self.protected_names,
            out_path=None,
        )
        self.assertEqual(report["measurement_type"], "internal")
        self.assertIn("research_questions", report)
        rq = report["research_questions"]
        self.assertIn("1_ecosystem_scope_and_growth", rq)
        self.assertIn("2_manifest_privileges_and_hooks", rq)
        self.assertIn("3_protected_registry_imitations", rq)
        self.assertIn("4_malicious_corpus_cross_reference", rq)
        self.assertIn("5_maintainer_demographics_and_hygiene", rq)


if __name__ == "__main__":
    unittest.main()
