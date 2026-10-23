"""Shared statistics for EG2 Batteries A, D (pre-registered in the PLAN addenda).

Pure functions on numpy arrays; no model or data access here.
"""

from __future__ import annotations

import math

import numpy as np
from scipy.stats import binomtest
from sklearn.metrics import average_precision_score, roc_auc_score

SEED = 20261008


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float | None, float | None, float | None]:
    """Point estimate and Wilson score 95% interval for k successes out of n."""
    if n == 0:
        return None, None, None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def binary_counts(y: np.ndarray, flag: np.ndarray) -> dict:
    """Confusion counts plus precision / recall / FPR (each with Wilson CI)."""
    y = np.asarray(y).astype(bool)
    flag = np.asarray(flag).astype(bool)
    tp = int((y & flag).sum())
    fp = int((~y & flag).sum())
    fn = int((y & ~flag).sum())
    tn = int((~y & ~flag).sum())
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": wilson(tp, tp + fn),
        "fpr": wilson(fp, fp + tn),
        "precision": wilson(tp, tp + fp),
    }


def projected_precision(recall: float, fpr: float, prevalence: float) -> float | None:
    """PROJECTION: precision at a deployment prevalence from measured recall and FPR."""
    num = recall * prevalence
    den = num + fpr * (1 - prevalence)
    return (num / den) if den > 0 else None


def mcnemar_exact(correct_a: np.ndarray, correct_b: np.ndarray) -> dict:
    """Exact (binomial) McNemar on paired correctness indicators.

    b = A right & B wrong, c = A wrong & B right. Two-sided p.
    """
    a = np.asarray(correct_a).astype(bool)
    b_ = np.asarray(correct_b).astype(bool)
    b = int((a & ~b_).sum())
    c = int((~a & b_).sum())
    p = binomtest(b, b + c, 0.5).pvalue if (b + c) > 0 else 1.0
    return {"a_only_right": b, "b_only_right": c, "p_exact": float(p)}


def _auc_pair(y, s1, s2):
    return (roc_auc_score(y, s1) - roc_auc_score(y, s2),
            average_precision_score(y, s1) - average_precision_score(y, s2))


def paired_bootstrap_auc(y: np.ndarray, s1: np.ndarray, s2: np.ndarray,
                         n_boot: int = 2000, seed: int = SEED) -> dict:
    """Stratified paired bootstrap of ROC-AUC and PR-AUC (average precision) differences s1 - s2."""
    y = np.asarray(y).astype(int)
    s1 = np.asarray(s1, dtype=float)
    s2 = np.asarray(s2, dtype=float)
    rng = np.random.default_rng(seed)
    pos = np.flatnonzero(y == 1)
    neg = np.flatnonzero(y == 0)
    d_roc, d_pr = [], []
    for _ in range(n_boot):
        idx = np.concatenate([rng.choice(pos, len(pos), replace=True),
                              rng.choice(neg, len(neg), replace=True)])
        r, p = _auc_pair(y[idx], s1[idx], s2[idx])
        d_roc.append(r)
        d_pr.append(p)
    r0, p0 = _auc_pair(y, s1, s2)

    def ci(v):
        return float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))

    return {"d_roc_auc": float(r0), "d_roc_auc_ci": ci(d_roc),
            "d_pr_auc": float(p0), "d_pr_auc_ci": ci(d_pr)}


def auc_with_ci(y: np.ndarray, s: np.ndarray, n_boot: int = 2000, seed: int = SEED) -> dict:
    """ROC-AUC and PR-AUC with stratified bootstrap percentile CIs."""
    y = np.asarray(y).astype(int)
    s = np.asarray(s, dtype=float)
    rng = np.random.default_rng(seed)
    pos = np.flatnonzero(y == 1)
    neg = np.flatnonzero(y == 0)
    rocs, prs = [], []
    for _ in range(n_boot):
        idx = np.concatenate([rng.choice(pos, len(pos), replace=True),
                              rng.choice(neg, len(neg), replace=True)])
        rocs.append(roc_auc_score(y[idx], s[idx]))
        prs.append(average_precision_score(y[idx], s[idx]))
    return {
        "roc_auc": float(roc_auc_score(y, s)),
        "roc_auc_ci": (float(np.percentile(rocs, 2.5)), float(np.percentile(rocs, 97.5))),
        "pr_auc": float(average_precision_score(y, s)),
        "pr_auc_ci": (float(np.percentile(prs, 2.5)), float(np.percentile(prs, 97.5))),
    }


def tpr_at_fpr(y: np.ndarray, s: np.ndarray, max_fpr: float) -> dict:
    """Highest TPR among thresholds whose FPR <= max_fpr (threshold = flag if s >= t)."""
    y = np.asarray(y).astype(bool)
    s = np.asarray(s, dtype=float)
    n_neg = int((~y).sum())
    n_pos = int(y.sum())
    best = {"tpr": 0.0, "fpr": 0.0, "threshold": float("inf"), "tp": 0, "fp": 0}
    for t in np.unique(s)[::-1]:
        flag = s >= t
        fp = int((flag & ~y).sum())
        if fp / n_neg > max_fpr + 1e-12:
            break
        tp = int((flag & y).sum())
        if tp / n_pos >= best["tpr"]:
            best = {"tpr": tp / n_pos, "fpr": fp / n_neg, "threshold": float(t), "tp": tp, "fp": fp}
    return best


def threshold_for_fpr(y: np.ndarray, s: np.ndarray, max_fpr: float) -> float:
    """Lowest threshold whose FPR <= max_fpr."""
    return tpr_at_fpr(y, s, max_fpr)["threshold"]


def brier(y: np.ndarray, p: np.ndarray) -> float:
    y = np.asarray(y, dtype=float)
    p = np.asarray(p, dtype=float)
    return float(np.mean((p - y) ** 2))


def ece_equal_mass(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    """Expected calibration error with equal-mass bins (binary, positive-class probability)."""
    y = np.asarray(y, dtype=float)
    p = np.asarray(p, dtype=float)
    order = np.argsort(p)
    chunks = np.array_split(order, bins)
    n = len(p)
    return float(sum(len(c) / n * abs(y[c].mean() - p[c].mean()) for c in chunks if len(c)))
