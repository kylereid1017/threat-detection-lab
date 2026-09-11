"""Unit tests for tools.swarm.endurance_runner."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.swarm.endurance_runner import EnduranceRunner
from tools.swarm.records import (
    KIND_TELEMETRY_SWEEP,
    OUTCOME_ERROR,
    aggregate,
    load_records,
    to_runner_counters,
)


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


class EnduranceRunnerLifecycleTests(unittest.TestCase):
    """Resume, stop, finish and error paths, exercised against a real scratch run.

    These are the paths a long endurance run only reaches when something goes
    wrong (a corrupt state file, a replay engine failure) or when an operator
    intervenes (the stop-file signal, a resumed run).  Each test asserts an
    observable consequence rather than that the code merely ran.
    """

    @staticmethod
    def _patched_synthesis(runner, res_dir):
        """Stub cable synthesis so lifecycle tests stay off the published cable path."""
        return patch.object(
            runner.synthesizer,
            "synthesize",
            return_value=(
                res_dir / "dummy.md",
                {"cable_id": "DUMMY", "total_evaluations": 0, "resilience_rate": 0.8},
            ),
        )

    def test_stale_stop_file_is_cleared_at_construction(self):
        """A leftover STOP_ENDURANCE must not kill the next run on its first cycle."""
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            (res / "STOP_ENDURANCE").write_text("stale signal", encoding="utf-8")
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                self.assertFalse(runner.stop_file.exists(), "stale stop signal survived startup")
                with self._patched_synthesis(runner, res):
                    result = runner.run(max_cycles=6)
            self.assertEqual(result["total_cycles"], 6)

    def test_resume_without_state_file_is_a_clean_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(
                pace_seconds=0.0, serve_workbench=False, results_dir=res, resume=True
            ) as runner:
                self.assertFalse(runner.load_prior_state())
                self.assertEqual(runner.total_cycles, 0)
                self.assertEqual(runner.total_probes, 0)

    def test_resume_with_corrupt_state_does_not_crash(self):
        """A truncated state file must degrade to a fresh run, not raise."""
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            (res / "endurance_state.json").write_text("{ this is not json", encoding="utf-8")
            with EnduranceRunner(
                pace_seconds=0.0, serve_workbench=False, results_dir=res, resume=True
            ) as runner:
                self.assertFalse(runner.load_prior_state())
                self.assertEqual(runner.total_probes, 0)

    def test_resume_rebuilds_counters_from_records(self):
        """Every resumed counter must equal the value derived from the raw ledger."""
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as first:
                with self._patched_synthesis(first, res):
                    first.run(max_cycles=6)
                run_id = first.run_id
                snapshot = {
                    "cycles": first.total_cycles,
                    "probes": first.total_probes,
                    "approved": first.critic_approved,
                    "detected": first.true_positives,
                    "gaps": first.evasion_gaps,
                }
            first_count = len(load_records(res, run_id))
            self.assertGreater(first_count, 0, "no observation records to resume from")

            with EnduranceRunner(
                pace_seconds=0.0, serve_workbench=False, results_dir=res, resume=True
            ) as resumed:
                self.assertEqual(resumed.run_id, run_id, "resume started a new run id instead of continuing")
                self.assertEqual(resumed.total_cycles, snapshot["cycles"])
                self.assertEqual(resumed.total_probes, snapshot["probes"])
                self.assertEqual(resumed.critic_approved, snapshot["approved"])
                self.assertEqual(resumed.true_positives, snapshot["detected"])
                self.assertEqual(resumed.evasion_gaps, snapshot["gaps"])

                derived = to_runner_counters(aggregate(load_records(res, run_id)))
                self.assertEqual(
                    resumed.total_probes, derived["total_probes"], "resumed counter is not record-derived"
                )
                self.assertEqual(resumed._record_start_seq, first_count)

                with self._patched_synthesis(resumed, res):
                    resumed.run(max_cycles=9)
                self.assertEqual(resumed.total_cycles, 9)

            rows = load_records(res, run_id)
            self.assertEqual(
                [r["seq"] for r in rows],
                list(range(1, len(rows) + 1)),
                "ledger sequence numbers are not contiguous across a resume",
            )
            self.assertGreater(len(rows), first_count, "resumed run appended no records")

    def test_checkpoint_snapshot_matches_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                runner.total_cycles = 3
                runner._save_state(force=True)
                runner._save_checkpoint()
                checkpoint = res / "checkpoints" / "checkpoint_cycle_000003.json"
                self.assertTrue(checkpoint.exists(), "no checkpoint written")
                self.assertEqual(
                    checkpoint.read_text(encoding="utf-8"),
                    (res / "endurance_state.json").read_text(encoding="utf-8"),
                )

                # An unreadable state file must warn and skip, not raise or fake a checkpoint.
                runner.state_file = res / "absent_state.json"
                runner.total_cycles = 4
                runner._save_checkpoint()
                self.assertFalse((res / "checkpoints" / "checkpoint_cycle_000004.json").exists())

    def test_finish_run_returns_summary_and_closes_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(
                pace_seconds=0.0, serve_workbench=True, http_port=8073, results_dir=res
            ) as runner:
                runner.start_http_server()
                self.assertIsNotNone(runner.httpd, "workbench server never bound a port")
                self.assertEqual(
                    runner.httpd.server_address[0],
                    "127.0.0.1",
                    "workbench listener is not loopback-only",
                )

                runner.total_probes = 10
                runner.critic_approved = 10
                runner.true_positives = 7
                runner.evasion_gaps = 3
                with self._patched_synthesis(runner, res):
                    summary = runner._finish_run()

                self.assertFalse(runner.running, "run still marked running after wrap-up")
                self.assertIsNone(runner.httpd, "listener left open after wrap-up")
                self.assertEqual(summary["total_probes"], 10)
                self.assertEqual(summary["total_cycles"], runner.total_cycles)
                self.assertTrue((res / "endurance_state.json").exists())

    def test_finish_run_contains_synthesis_failure(self):
        """A cable failure must still conclude the run with a summary, not propagate."""
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                with patch.object(
                    runner.synthesizer, "synthesize", side_effect=RuntimeError("cable write failed")
                ):
                    summary = runner._finish_run()
                self.assertIsInstance(summary, dict)
                self.assertIn("total_cycles", summary)
                self.assertIn("total_probes", summary)

    def test_replay_sweep_without_fixtures_is_a_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                runner.telemetry_fixtures = [res / "missing_fixture.jsonl"]
                before = (runner.total_probes, runner.replay_evals_count)
                runner._run_telemetry_replay_sweep()
                self.assertEqual((runner.total_probes, runner.replay_evals_count), before)

    def test_replay_engine_error_is_recorded_and_reraised(self):
        """An engine failure must increment the error count and leave an error record."""
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            fixture = res / "captured_attack.jsonl"
            fixture.write_text('{"EventID": 1}\n', encoding="utf-8")
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                runner.telemetry_fixtures = [fixture]
                with patch.object(
                    runner.replay_engine, "replay_file", side_effect=RuntimeError("corrupt evtx")
                ):
                    with self.assertRaises(RuntimeError):
                        runner._run_telemetry_replay_sweep()

                self.assertEqual(runner.error_records, 1)
                rows = load_records(res, runner.run_id)
                errors = [r for r in rows if r.get("outcome") == OUTCOME_ERROR]
                self.assertEqual(len(errors), 1, "engine failure left no error record")
                self.assertEqual(errors[0]["kind"], KIND_TELEMETRY_SWEEP)


if __name__ == "__main__":
    unittest.main()
