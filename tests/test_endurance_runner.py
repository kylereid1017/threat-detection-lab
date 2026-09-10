"""Unit tests for tools.swarm.endurance_runner."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.swarm.endurance_runner import EnduranceRunner


class EnduranceRunnerTests(unittest.TestCase):
    """Verifies that the EnduranceRunner executes cycles and tracks state correctly."""

    def test_runner_initialization(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with EnduranceRunner(pace_seconds=0.01, serve_workbench=False, results_dir=Path(tmp_dir)) as runner:
                self.assertEqual(runner.pace, 0.01)
                self.assertFalse(runner.serve_workbench)
                self.assertEqual(runner.total_cycles, 0)
                self.assertEqual(runner.total_probes, 0)
                self.assertEqual(runner.results_dir, Path(tmp_dir))
                self.assertIsNotNone(runner.critic)
                self.assertIsNotNone(runner.campaign_orchestrator)
                self.assertIsNotNone(runner.graph_engine)

    def test_runner_metrics_properties(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with EnduranceRunner(pace_seconds=0.01, serve_workbench=False, results_dir=Path(tmp_dir)) as runner:
                # Initial state without data should return None, not fabricated defaults
                self.assertIsNone(runner.current_resilience)
                self.assertIsNone(runner.containment_rate)
                self.assertIsNone(runner.average_dod)
                self.assertIsNone(runner.average_mttd)

                # Simulate some data
                runner.total_probes = 10
                runner.critic_approved = 10
                runner.true_positives = 7
                runner.evasion_gaps = 3
                self.assertAlmostEqual(runner.current_resilience, 0.7, places=2)

                runner.campaigns_count = 2
                runner.campaigns_contained = 2
                runner.campaign_dod_sum = 1.8
                self.assertAlmostEqual(runner.containment_rate, 1.0, places=2)
                self.assertAlmostEqual(runner.average_dod, 0.9, places=2)

    def test_runner_executes_max_cycles(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            res_dir = Path(tmp_dir)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res_dir) as runner:
                with patch.object(runner.synthesizer, "synthesize", return_value=(res_dir / "dummy.md", {"cable_id": "DUMMY", "total_evaluations": 6, "resilience_rate": 0.8})):
                    result = runner.run(max_cycles=6)
                    self.assertEqual(result["total_cycles"], 6)
                    self.assertGreater(result["total_probes"], 0)
                    self.assertIn("resilience", result)
                    self.assertIn("dod", result)
                    self.assertIn("containment", result)

                    # Ensure results written to isolated tmp_dir, not repo docs/swarm/results
                    self.assertTrue((res_dir / "endurance_state.json").exists())

    def test_runner_honors_stop_signal(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            res_dir = Path(tmp_dir)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res_dir) as runner:
                runner.stop_file.write_text("STOP", encoding="utf-8")
                with patch.object(runner.synthesizer, "synthesize", return_value=(res_dir / "dummy.md", {"cable_id": "DUMMY", "total_evaluations": 0, "resilience_rate": 0.714})):
                    result = runner.run(max_cycles=100)
                    self.assertEqual(result["total_cycles"], 0)

    def test_boundary_histories_reconcile_with_real_counters(self):
        """Histories must be real per-target observations, not ratio allocations."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res_dir = Path(tmp_dir)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res_dir) as runner:
                with patch.object(
                    runner.synthesizer,
                    "synthesize",
                    return_value=(res_dir / "dummy.md", {"cable_id": "DUMMY", "total_evaluations": 0, "resilience_rate": 0.0}),
                ):
                    runner.run(max_cycles=12)

                total_sparring = sum(c["probes"] for c in runner.target_probes.values())
                self.assertGreater(total_sparring, 0, "no sparring probes recorded")
                for target in ("sigma", "yara"):
                    hist = json.loads(
                        (res_dir / f"boundary_history_{target}.json").read_text(encoding="utf-8")
                    )
                    counts = runner.target_probes[target]
                    self.assertEqual(hist["total_generated"], counts["probes"])
                    self.assertEqual(hist["critic_approved"], counts["approved"])
                    self.assertEqual(hist["detected_count"], counts["detected"])
                    self.assertEqual(hist["evaded_count"], counts["gaps"])
                    self.assertEqual(
                        hist["detected_count"] + hist["evaded_count"], hist["critic_approved"]
                    )


if __name__ == "__main__":
    unittest.main()
