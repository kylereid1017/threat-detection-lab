"""Unit tests for the Flagship Agent Exposure Review workflow."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.agent_graph.exposure_review import (
    SAFE_BENIGN_EXAMPLE,
    evaluate_tool_addition,
    format_exposure_report,
    load_configuration,
    main,
)


class AgentExposureReviewTests(unittest.TestCase):
    def test_benign_tool_addition_remains_open(self):
        # Baseline: SQLite + Git (Distance 1 or 2, open)
        delta = evaluate_tool_addition(
            SAFE_BENIGN_EXAMPLE,
            candidate_tool="mcp-server-postgres",
            candidate_args=["--connection-string", "postgresql://localhost/test"],
        )
        self.assertFalse(delta.closure_flipped)
        self.assertFalse(delta.after_closed)
        self.assertGreater(delta.after_distance, 0)
        report = format_exposure_report(delta, "<test>")
        self.assertIn("SAFE TO ADD", report)
        self.assertNotIn("CRITICAL COMPOSITION CHANGE", report)

    def test_trifecta_closure_flip_detected_with_mitigations(self):
        # Baseline agent has untrusted content ingest + outbound egress, but NO private data
        baseline_config = {
            "mcpServers": {
                "fetcher": {
                    "command": "npx",
                    "args": ["-y", "web-crawler-mcp"],  # web_fetch (untrusted_ingress)
                },
                "notifier": {
                    "command": "npx",
                    "args": ["-y", "notifier-service"],
                    "env": {"SENDGRID_API_KEY": "sg_123"},  # message_send, net_egress (exfiltration)
                },
            }
        }
        # Candidate tool introduces private data (fs_read)
        delta = evaluate_tool_addition(
            baseline_config,
            candidate_tool="@modelcontextprotocol/server-filesystem",
            candidate_args=["/"],
        )
        self.assertTrue(delta.closure_flipped)
        self.assertTrue(delta.after_closed)
        self.assertEqual(delta.after_distance, 0)
        self.assertGreater(len(delta.modeled_paths), 0)
        self.assertIn("@modelcontextprotocol/server-filesystem", delta.new_critical_packages)

        # Confirm concrete mitigations proposed
        strategies = [m["strategy"] for m in delta.mitigations]
        self.assertTrue(any("Directory Path Scoping" in s for s in strategies))
        self.assertTrue(any("Agent Profile Separation" in s for s in strategies))

        # Report text format
        report = format_exposure_report(delta, "two-tier-test.json")
        self.assertIn("CRITICAL COMPOSITION CHANGE DETECTED", report)
        self.assertIn("MODELED EXPOSURE PATHS:", report)
        self.assertIn("MITIGATION RECHECK & RESIDUAL EXPOSURE:", report)
        self.assertEqual(delta.recheck_validation["modeled_paths_remaining"], 0)
        self.assertEqual(delta.recheck_validation["post_mitigation_status"], "OPEN (Post-Mitigation)")

    def test_load_configuration_with_unparsed_notice(self):
        conf = {
            "mcpServers": {
                "valid": {"command": "npx", "args": ["mcp-server-sqlite"]},
                "unsupported_runner": {"command": "custom_binary", "args": ["foo"]},
            }
        }
        parsed, unparsed = load_configuration(conf)
        self.assertEqual(len(parsed), 1)
        self.assertIn("unsupported_runner", unparsed)

    def test_cli_execution_with_out(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            out_json = p / "exposure_report.json"
            cfg_file = p / "agent.json"
            cfg_file.write_text(json.dumps(SAFE_BENIGN_EXAMPLE), encoding="utf-8")

            ret = main(["--config", str(cfg_file), "--tool", "mcp-server-sqlite", "--out", str(out_json)])
            self.assertEqual(ret, 0)
            self.assertTrue(out_json.exists())

            report_data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(report_data["title"], "Agent Exposure Review")
            self.assertIn("evaluation", report_data)

    def test_cli_missing_config_returns_error(self):
        ret = main(["--config", "nonexistent_config_file.json"])
        self.assertEqual(ret, 2)


if __name__ == "__main__":
    unittest.main()


class ExposureReviewCorrectnessTests(unittest.TestCase):
    """Regressions for three defects found by running the tool, not by reading it.

    All three shipped while the suite was green, which is why each of these
    asserts on the content of a claim rather than on its presence.
    """

    #: A baseline that does not close on its own, so any closure below is
    #: attributable to the candidate rather than to the starting set.
    def _open_baseline(self):
        return {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                }
            }
        }

    def test_modeled_path_names_only_capabilities_the_closure_holds(self):
        """The path description listed the entire taxonomy for every closure.

        That credited each tool with seventeen capabilities regardless of what it
        had, so every closure read identically and none of them were true.
        """
        delta = evaluate_tool_addition(
            self._open_baseline(),
            "@modelcontextprotocol/server-github",
            candidate_env_keys=["GITHUB_PERSONAL_ACCESS_TOKEN"],
        )
        self.assertTrue(delta.modeled_paths)
        path = delta.modeled_paths[0]
        # A capability no package in this closure holds must not appear.
        for absent in ("browser_automation", "database_read", "message_send"):
            with self.subTest(capability=absent):
                self.assertNotIn(absent, path)

    def test_recheck_is_computed_and_can_report_failure(self):
        """The recheck hardcoded success: zero paths remaining, posture OPEN.

        A tool that carries all three legs by itself defeats the profile split,
        because it takes the whole trifecta into whichever profile it lands in.
        The recheck has to be able to say so.
        """
        delta = evaluate_tool_addition(
            self._open_baseline(),
            "@modelcontextprotocol/server-github",
            candidate_env_keys=["GITHUB_PERSONAL_ACCESS_TOKEN"],
        )
        recheck = delta.recheck_validation
        self.assertGreater(
            recheck["modeled_paths_remaining"],
            0,
            "a single tool holding all three legs cannot be split apart",
        )
        self.assertIn("STILL CLOSED", recheck["post_mitigation_status"])
        self.assertTrue(
            any("does not resolve" in d for d in recheck["details"]),
            "a failed mitigation must say it failed",
        )

    def test_directory_scoping_is_not_offered_to_tools_without_filesystem_access(self):
        """The gate was the private_data leg, which also covers repo and mailbox
        reads. That told operators to constrain directory arguments on tools that
        take none."""
        delta = evaluate_tool_addition(
            self._open_baseline(),
            "@modelcontextprotocol/server-github",
            candidate_env_keys=["GITHUB_PERSONAL_ACCESS_TOKEN"],
        )
        strategies = {m["strategy"] for m in delta.mitigations}
        self.assertNotIn("Directory Path Scoping", strategies)

    def test_directory_scoping_is_offered_to_filesystem_tools(self):
        delta = evaluate_tool_addition(
            {"mcpServers": {}}, "@modelcontextprotocol/server-filesystem", candidate_args=["/"]
        )
        strategies = {m["strategy"] for m in delta.mitigations}
        self.assertIn("Directory Path Scoping", strategies)
