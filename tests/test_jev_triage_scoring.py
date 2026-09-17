"""Behavioral tests for the Jev triage scoring math (tools/jev_triage/score.py).

Pure functions only; no network, no API keys. Run with either:
  ./.venv/Scripts/python.exe -m pytest tests/test_jev_triage_scoring.py
  ./.venv/Scripts/python.exe -m unittest tests.test_jev_triage_scoring
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))

import score  # noqa: E402


def obs(email_id, true, pred, confidence=None, ts="2026-09-17T14:00:00+00:00",
        input_tokens=700, output_tokens=30, error=None, raw=None):
    return {
        "kind": "observation", "run_id": "test", "email_id": email_id,
        "label_true": true, "label_pred": pred, "confidence": confidence,
        "ts_utc": ts, "input_tokens": input_tokens, "output_tokens": output_tokens,
        "error": error, "raw_answer": raw,
    }


class TestConfusionMath(unittest.TestCase):
    def test_confusion_and_accuracy(self):
        rows = [obs("a", "safe", "safe"), obs("b", "attack", "safe"),
                obs("c", "spam", "spam"), obs("d", "gray", "gray")]
        matrix = score.confusion(rows)
        self.assertEqual(matrix["safe"]["safe"], 1)
        self.assertEqual(matrix["attack"]["safe"], 1)
        self.assertEqual(score.accuracy(matrix), 0.75)

    def test_error_rows_excluded_from_matrix(self):
        rows = [obs("a", "safe", "safe"), obs("b", "attack", None, error="HTTP 500")]
        matrix = score.confusion(rows)
        self.assertEqual(sum(sum(r.values()) for r in matrix.values()), 1)

    def test_per_class_precision_recall(self):
        rows = [obs("a", "safe", "safe"), obs("b", "safe", "spam"),
                obs("c", "attack", "safe"), obs("d", "attack", "attack")]
        stats = score.per_class(score.confusion(rows))
        self.assertEqual(stats["safe"]["recall"], 0.5)
        self.assertEqual(stats["safe"]["precision"], 0.5)
        self.assertEqual(stats["attack"]["recall"], 0.5)
        # spam was predicted once (row b) and was wrong: precision 0.0, recall 0.0 (no true spam)
        self.assertEqual(stats["spam"]["precision"], 0.0)
        self.assertEqual(stats["spam"]["recall"], None)

    def test_empty_basis_is_none_not_zero(self):
        stats = score.per_class(score.confusion([]))
        self.assertIsNone(stats["safe"]["recall"])
        self.assertIsNone(stats["safe"]["precision"])
        self.assertIsNone(score.accuracy(score.confusion([])))


class TestCostMath(unittest.TestCase):
    def test_offpeak_deepseek_cost(self):
        row = obs("a", "safe", "safe", ts="2026-09-17T14:00:00+00:00",
                  input_tokens=1_000_000, output_tokens=1_000_000)
        pricing = {"input": 0.15, "output": 0.60, "input_peak": 0.30, "output_peak": 1.20}
        self.assertAlmostEqual(score.email_cost(row, pricing), 0.75)

    def test_peak_deepseek_cost(self):
        row = obs("a", "safe", "safe", ts="2026-09-15T07:00:00+00:00",
                  input_tokens=1_000_000, output_tokens=1_000_000)
        pricing = {"input": 0.15, "output": 0.60, "input_peak": 0.30, "output_peak": 1.20}
        self.assertAlmostEqual(score.email_cost(row, pricing), 1.50)

    def test_weekend_is_offpeak_and_free_output_pricing(self):
        weekend = "2026-09-19T07:00:00+00:00"  # Saturday
        self.assertFalse(score.is_peak(weekend))
        jev_pricing = {"input": 0.042, "output": 0.0}
        row = obs("a", "safe", "safe", ts="2026-09-17T14:00:00+00:00",
                  input_tokens=1_000_000, output_tokens=999_999)
        self.assertAlmostEqual(score.email_cost(row, jev_pricing), 0.042)


class TestSweepPolicy(unittest.TestCase):
    def make_jev_run(self, rows):
        return {"meta": {"run_id": "jev-test", "model_requested": "jev-latest",
                         "provider": "typesafe"}, "observations": rows}

    def make_llm_run(self, rows, model="deepseek-flash"):
        return {"meta": {"run_id": "llm-test", "model_requested": model,
                         "provider": "deepseek"}, "observations": rows}

    def test_high_confidence_auto_paths_and_escalation(self):
        jev_rows = [
            obs("a", "attack", "attack", confidence=0.97),
            obs("b", "safe", "safe", confidence=0.95),
            obs("c", "gray", "gray", confidence=0.95),   # gray never auto-decides
            obs("d", "spam", "safe", confidence=0.40),   # low conf -> escalate
        ]
        llm_rows = [
            obs("c", "gray", "gray"), obs("d", "spam", "spam"),
            obs("a", "attack", "attack"), obs("b", "safe", "safe"),
        ]
        sweep = score.sweep_thresholds(self.make_jev_run(jev_rows), self.make_llm_run(llm_rows))
        row = next(r for r in sweep if abs(r["threshold"] - 0.9) < 0.01)
        self.assertEqual(row["auto_decided"], 2)       # a and b
        self.assertEqual(row["escalated"], 2)          # c and d
        self.assertEqual(row["auto_error_rate"], 0.0)
        self.assertEqual(row["final_accuracy"], 1.0)

    def test_missed_attack_counted_not_hidden(self):
        jev_rows = [obs("a", "attack", "safe", confidence=0.99)]
        llm_rows = [obs("a", "attack", "attack")]
        sweep = score.sweep_thresholds(self.make_jev_run(jev_rows), self.make_llm_run(llm_rows))
        row = next(r for r in sweep if abs(r["threshold"] - 0.9) < 0.01)
        self.assertEqual(row["auto_decided"], 1)
        self.assertEqual(row["auto_missed_attack"], 1)
        self.assertEqual(row["auto_error_rate"], 1.0)

    def test_cascade_cost_uses_only_escalated_llm_rows(self):
        jev_rows = [obs("a", "safe", "safe", confidence=0.99, input_tokens=1000),
                    obs("b", "spam", "spam", confidence=0.10, input_tokens=1000)]
        llm_rows = [obs("b", "spam", "spam", input_tokens=800, output_tokens=40),
                    obs("a", "safe", "safe", input_tokens=800, output_tokens=40)]
        sweep = score.sweep_thresholds(self.make_jev_run(jev_rows), self.make_llm_run(llm_rows))
        row = next(r for r in sweep if abs(r["threshold"] - 0.9) < 0.01)
        expected_jev = 2000 / 1e6 * 0.042
        expected_llm = 800 / 1e6 * 0.15 + 40 / 1e6 * 0.60
        self.assertAlmostEqual(row["cascade_cost_usd"], expected_jev + expected_llm)

    def test_no_llm_run_still_reports_sweep(self):
        jev_rows = [obs("a", "safe", "safe", confidence=0.99)]
        sweep = score.sweep_thresholds(self.make_jev_run(jev_rows), None)
        row = next(r for r in sweep if abs(r["threshold"] - 0.9) < 0.01)
        self.assertEqual(row["auto_decided"], 1)
        self.assertIsNone(row["pure_llm_per_1000"])


class TestAuxSignal(unittest.TestCase):
    def test_means_by_true_label(self):
        rows = [
            obs("a", "attack", "attack", raw={"deception_present": {"noul": 0.9},
                                              "requests_credentials_or_payment": {"noul": 0.8}}),
            obs("b", "attack", "attack", raw={"deception_present": {"noul": 0.7},
                                              "requests_credentials_or_payment": {"noul": 0.6}}),
            obs("c", "safe", "safe", raw={"deception_present": {"noul": 0.05},
                                          "requests_credentials_or_payment": {"noul": 0.02}}),
        ]
        aux = score.aux_signal(rows)
        self.assertAlmostEqual(aux["attack"]["deception_mean"], 0.8)
        self.assertAlmostEqual(aux["safe"]["deception_mean"], 0.05)


class TestPercentile(unittest.TestCase):
    def test_percentiles(self):
        values = [10, 20, 30, 40, 50]
        self.assertEqual(score.percentile(values, 0.50), 30)
        self.assertEqual(score.percentile(values, 0.95), 50)
        self.assertIsNone(score.percentile([], 0.5))


if __name__ == "__main__":
    unittest.main()
