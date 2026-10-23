"""Tests for tools/eg2_triage/stats_util.py (shared statistics for EG2 Batteries A, D).

Run:
  python -m unittest tests/test_eg2_stats_util.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HAVE_SCI = all(importlib.util.find_spec(m) for m in ("numpy", "scipy", "sklearn"))
if HAVE_SCI:
    import numpy as np

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "eg2_triage"))
    import stats_util as su  # noqa: E402
else:  # CI's requirements-dev.txt carries no scientific stack; EG2 tooling runs locally
    raise unittest.SkipTest("numpy/scipy/sklearn not installed")


class TestWilson(unittest.TestCase):
    def test_known_interval(self):
        # 320/336 recall from the URL benchmark: Wilson 95% [0.924, 0.9705]
        p, lo, hi = su.wilson(320, 336)
        self.assertAlmostEqual(p, 0.95238, places=4)
        self.assertAlmostEqual(lo, 0.924, places=3)
        self.assertAlmostEqual(hi, 0.9705, places=3)

    def test_edges(self):
        self.assertEqual(su.wilson(0, 0), (None, None, None))
        p, lo, hi = su.wilson(0, 672)
        self.assertEqual((p, lo), (0.0, 0.0))
        self.assertGreater(hi, 0.0)


class TestCounts(unittest.TestCase):
    def test_binary_counts(self):
        y = np.array([1, 1, 1, 0, 0, 0, 0])
        f = np.array([1, 1, 0, 1, 0, 0, 0])
        b = su.binary_counts(y, f)
        self.assertEqual((b["tp"], b["fn"], b["fp"], b["tn"]), (2, 1, 1, 3))
        self.assertAlmostEqual(b["recall"][0], 2 / 3)
        self.assertAlmostEqual(b["fpr"][0], 1 / 4)
        self.assertAlmostEqual(b["precision"][0], 2 / 3)

    def test_projected_precision(self):
        # recall 0.95, FPR 0.064 at 1:10,000 -> ~0.15%
        self.assertAlmostEqual(su.projected_precision(0.9524, 0.064, 1e-4), 0.00149, places=4)
        self.assertIsNone(su.projected_precision(0.0, 0.0, 1e-4))


class TestPairedTests(unittest.TestCase):
    def test_mcnemar_exact(self):
        a = np.array([1] * 7 + [1] * 10, dtype=bool)
        b = np.array([0] * 7 + [1] * 10, dtype=bool)
        m = su.mcnemar_exact(a, b)
        self.assertEqual((m["a_only_right"], m["b_only_right"]), (7, 0))
        self.assertAlmostEqual(m["p_exact"], 2 * 0.5 ** 7)
        self.assertEqual(su.mcnemar_exact(a, a)["p_exact"], 1.0)

    def test_bootstrap_identical_scores_zero_diff(self):
        rng = np.random.default_rng(0)
        y = np.array([1] * 30 + [0] * 70)
        s = rng.random(100) + y
        r = su.paired_bootstrap_auc(y, s, s, n_boot=50)
        self.assertEqual(r["d_roc_auc"], 0.0)
        self.assertEqual(r["d_pr_auc_ci"], (0.0, 0.0))

    def test_auc_with_ci_brackets_point(self):
        rng = np.random.default_rng(1)
        y = np.array([1] * 40 + [0] * 60)
        s = rng.random(100) + 0.8 * y
        r = su.auc_with_ci(y, s, n_boot=200)
        self.assertLessEqual(r["roc_auc_ci"][0], r["roc_auc"])
        self.assertGreaterEqual(r["roc_auc_ci"][1], r["roc_auc"])


class TestOperatingPoints(unittest.TestCase):
    def test_tpr_at_fpr(self):
        y = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        s = np.array([.9, .8, .7, .2, .85, .1, .1, .1, .1, .1, .1, .1, .1, .1])
        zero = su.tpr_at_fpr(y, s, 0.0)
        self.assertEqual((zero["tp"], zero["fp"]), (1, 0))
        ten = su.tpr_at_fpr(y, s, 0.10)
        self.assertEqual((ten["tp"], ten["fp"]), (4, 1))

    def test_calibration(self):
        y = np.array([0, 1, 0, 1])
        self.assertEqual(su.brier(y, y.astype(float)), 0.0)
        self.assertAlmostEqual(su.brier(y, np.full(4, 0.5)), 0.25)
        self.assertAlmostEqual(su.ece_equal_mass(y, np.full(4, 0.5), bins=2), 0.0)


if __name__ == "__main__":
    unittest.main()
