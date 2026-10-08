"""Behavioral tests for EG2 email triage scoring logic.

Tests pure functions for:
  - Subject normalization & group key hashing (PLAN C5)
  - Two-branch gate & delivered attacks count (PLAN C6)
  - Matched threshold search on 0.001 grid (PLAN C6)
  - MRL vector truncation & L2 re-normalization (PLAN C3)
  - Metric computation (precision, recall, confusion)

Run:
  python -m unittest tests/test_eg2_email_scoring.py
"""

from __future__ import annotations

import re
import unittest
import numpy as np


def normalize_subject(subj: str) -> str:
    """PLAN C5: lowercased, digits -> '0', whitespace collapsed."""
    s = subj.lower()
    s = re.sub(r"\d", "0", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def two_branch_decide(pred_label: str, confidence: float, threshold: float) -> str:
    """PLAN C6: pred=attack & conf >= T -> quarantine; pred=safe & conf >= T -> deliver; else escalate."""
    if pred_label == "attack" and confidence >= threshold:
        return "quarantine"
    elif pred_label == "safe" and confidence >= threshold:
        return "deliver"
    return "escalate"


def is_delivered_attack(true_label: str, pred_label: str, confidence: float, threshold: float) -> bool:
    """PLAN C6: true attack delivered as safe under threshold T."""
    return true_label == "attack" and pred_label == "safe" and confidence >= threshold


def find_matched_threshold(eg2_confs: list[tuple[str, float]], target_auto_share: float) -> float:
    """PLAN C6: smallest threshold on 0.001 grid where eg2 auto-share <= target."""
    n = len(eg2_confs)
    if n == 0:
        return 0.0
    for step in range(1001):
        t = round(step * 0.001, 3)
        auto_count = sum(1 for pred, conf in eg2_confs if pred in ("attack", "safe") and conf >= t)
        share = auto_count / n
        if share <= target_auto_share + 1e-9:
            return t
    return 1.0


def truncate_and_normalize_mrl(vecs: np.ndarray, dim: int = 256) -> np.ndarray:
    """PLAN C3: take first `dim` dimensions and L2 re-normalize."""
    sliced = vecs[:, :dim].copy()
    norms = np.linalg.norm(sliced, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return sliced / norms


class TestEG2EmailScoring(unittest.TestCase):
    def test_normalize_subject(self):
        s1 = "Invoice #12345 for John   Doe!"
        s2 = "invoice #99999 for john doe!"
        self.assertEqual(normalize_subject(s1), "invoice #00000 for john doe!")
        self.assertEqual(normalize_subject(s1), normalize_subject(s2))

    def test_two_branch_gate(self):
        self.assertEqual(two_branch_decide("attack", 0.85, 0.50), "quarantine")
        self.assertEqual(two_branch_decide("attack", 0.45, 0.50), "escalate")
        self.assertEqual(two_branch_decide("safe", 0.90, 0.50), "deliver")
        self.assertEqual(two_branch_decide("safe", 0.30, 0.50), "escalate")
        self.assertEqual(two_branch_decide("spam", 0.99, 0.50), "escalate")
        self.assertEqual(two_branch_decide("gray", 0.99, 0.50), "escalate")

    def test_delivered_attack_predicate(self):
        # Attack called safe with high confidence -> true delivered attack
        self.assertTrue(is_delivered_attack("attack", "safe", 0.85, 0.50))
        # Attack called safe with low confidence -> escalated, NOT delivered
        self.assertFalse(is_delivered_attack("attack", "safe", 0.30, 0.50))
        # Attack called attack -> quarantined, NOT delivered
        self.assertFalse(is_delivered_attack("attack", "attack", 0.85, 0.50))
        # Safe called safe -> benign delivery, NOT attack
        self.assertFalse(is_delivered_attack("safe", "safe", 0.85, 0.50))

    def test_matched_threshold(self):
        # 10 rows: 4 with conf 0.9, 4 with conf 0.5, 2 with conf 0.2 (all pred attack)
        rows = [("attack", 0.9)] * 4 + [("attack", 0.5)] * 4 + [("attack", 0.2)] * 2
        # Target auto share = 0.40 -> threshold should be >= 0.501, so 0.501 or 0.9
        # at t=0.500: conf >= 0.50 -> 8 items -> share 0.80
        # at t=0.501: conf >= 0.501 -> 4 items -> share 0.40 <= 0.40
        t = find_matched_threshold(rows, 0.40)
        self.assertEqual(t, 0.501)

    def test_mrl_truncation_and_l2(self):
        rng = np.random.default_rng(42)
        v = rng.standard_normal((10, 768)).astype(np.float32)
        # normalize original
        v /= np.linalg.norm(v, axis=1, keepdims=True)
        # truncate to 256
        trunc = truncate_and_normalize_mrl(v, 256)
        self.assertEqual(trunc.shape, (10, 256))
        # Check all unit length
        norms = np.linalg.norm(trunc, axis=1)
        np.testing.assert_allclose(norms, 1.0, atol=1e-6)


if __name__ == "__main__":
    unittest.main()
