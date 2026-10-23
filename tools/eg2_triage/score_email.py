"""Score the EG2 email triage battery (Battery C) against Jev scale records.

Frozen by tools/eg2_triage/PLAN.md.
Implements:
  - Protocol E1 (5-fold StratifiedGroupKFold out-of-fold)
  - Protocol E2 (cross-source holdouts: nazario, nigerian_5)
  - Bases: registered and CEAS_08->spam remap
  - MRL 256-d sensitivity
  - Matched threshold search & criteria checking (C8a..C8e)
  - Outputs committed records, results-email.json, RESULTS-EMAIL.md

Run:
  python tools/eg2_triage/score_email.py
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "corpus" / "email" / "scale" / "scale-corpus.jsonl"
EG2_DIR = REPO / "corpus" / "email" / "scale" / "eg2"
VECS_PATH = EG2_DIR / "embeddings-768.npy"
IDS_PATH = EG2_DIR / "ids.json"
LATENCY_PATH = EG2_DIR / "latency-ms.npy"
SMOKE_PATH = EG2_DIR / "smoke.json"

JEV_RECORDS_DIR = REPO / "docs" / "research" / "jev-email-triage" / "records" / "scale"
OUT_DIR = REPO / "docs" / "research" / "eg2-email-triage"
RECORDS_OUT_DIR = OUT_DIR / "records"

LABELS = ["safe", "gray", "spam", "attack"]
CLEAN_SOURCES = {"nazario", "nigerian_5"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_subject(subj: str) -> str:
    s = subj.lower()
    s = re.sub(r"\d", "0", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def truncate_and_normalize_mrl(vecs: np.ndarray, dim: int = 256) -> np.ndarray:
    sliced = vecs[:, :dim].copy()
    norms = np.linalg.norm(sliced, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return sliced / norms


def load_corpus() -> dict[str, dict]:
    data = {}
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            eid = rec["email_id"]
            data[eid] = {
                "email_id": eid,
                "label_registered": rec["label"],
                "label_remap": "spam" if rec["source"] == "ceas_08" else rec["label"],
                "source": rec["source"],
                "subject_group": hashlib.sha256(normalize_subject(rec.get("subject", "")).encode("utf-8")).hexdigest(),
            }
    return data


def load_jev_scale_observations() -> dict[str, dict]:
    obs = {}
    jev_files = sorted(JEV_RECORDS_DIR.glob("jev-scale-*.jsonl")) + sorted(JEV_RECORDS_DIR.glob("jev-scale-*.jsonl.gz"))
    if not jev_files:
        raise SystemExit(f"ABORT: no Jev scale records found in {JEV_RECORDS_DIR}")
    target = jev_files[-1]
    opener = gzip.open(target, "rt", encoding="utf-8") if target.name.endswith(".gz") else target.open(encoding="utf-8")
    with opener as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "observation" and not row.get("error"):
                obs[row["email_id"]] = row
    return obs


def confusion_matrix(true_labels: list[str], pred_labels: list[str]) -> dict[str, dict[str, int]]:
    matrix = {t: {p: 0 for p in LABELS} for t in LABELS}
    for t, p in zip(true_labels, pred_labels):
        if t in matrix and p in matrix[t]:
            matrix[t][p] += 1
    return matrix


def per_class_metrics(matrix: dict[str, dict[str, int]]) -> dict[str, dict]:
    out = {}
    for l in LABELS:
        tp = matrix[l][l]
        fn = sum(matrix[l][p] for p in LABELS if p != l)
        fp = sum(matrix[t][l] for t in LABELS if t != l)
        support = tp + fn
        recall = (tp / support) if support > 0 else None
        pred_total = tp + fp
        precision = (tp / pred_total) if pred_total > 0 else None
        out[l] = {"precision": precision, "recall": recall, "support": support, "pred_count": pred_total}
    return out


def fit_and_predict(X_train: np.ndarray, y_train: list[str], X_test: np.ndarray) -> tuple[list[str], list[float], list[dict]]:
    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, solver="lbfgs", random_state=20261008)
    clf.fit(X_train, y_train)
    classes = list(clf.classes_)
    probs = clf.predict_proba(X_test)
    preds, confs, prob_dicts = [], [], []
    for p_row in probs:
        best_idx = int(np.argmax(p_row))
        pred_label = classes[best_idx]
        conf = float(p_row[best_idx])
        p_dict = {classes[i]: float(p_row[i]) for i in range(len(classes))}
        preds.append(pred_label)
        confs.append(conf)
        prob_dicts.append(p_dict)
    return preds, confs, prob_dicts


def run_e1_oof(vecs: np.ndarray, ids: list[str], labels: list[str], groups: list[str]) -> tuple[list[str], list[float], list[dict], list[int]]:
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=20261008)
    oof_preds = [None] * len(ids)
    oof_confs = [None] * len(ids)
    oof_probs = [None] * len(ids)
    oof_folds = [None] * len(ids)

    for fold_idx, (train_idx, test_idx) in enumerate(sgkf.split(vecs, labels, groups)):
        X_tr, y_tr = vecs[train_idx], [labels[i] for i in train_idx]
        X_te = vecs[test_idx]
        p_sub, c_sub, probs_sub = fit_and_predict(X_tr, y_tr, X_te)
        for local_i, global_i in enumerate(test_idx):
            oof_preds[global_i] = p_sub[local_i]
            oof_confs[global_i] = c_sub[local_i]
            oof_probs[global_i] = probs_sub[local_i]
            oof_folds[global_i] = fold_idx

    return oof_preds, oof_confs, oof_probs, oof_folds


def find_matched_threshold(preds_confs: list[tuple[str, float]], target_auto_share: float) -> float:
    n = len(preds_confs)
    if n == 0:
        return 0.0
    for step in range(1001):
        t = round(step * 0.001, 3)
        auto_count = sum(1 for p, c in preds_confs if p in ("attack", "safe") and c >= t)
        share = auto_count / n
        if share <= target_auto_share + 1e-9:
            return t
    return 1.0


def sweep(preds: list[str], confs: list[float], trues: list[str]) -> list[dict]:
    out = []
    n = len(preds)
    for step in range(21):
        t = round(step * 0.05, 2)
        auto_total = auto_correct = 0
        missed_attacks = 0  # true attack -> safe
        safe_to_attack = 0
        for p, c, tr in zip(preds, confs, trues):
            if p in ("attack", "safe") and c >= t:
                auto_total += 1
                if p == tr:
                    auto_correct += 1
                if tr == "attack" and p == "safe":
                    missed_attacks += 1
                if tr == "safe" and p == "attack":
                    safe_to_attack += 1
        share = (auto_total / n) if n else 0.0
        err = ((auto_total - auto_correct) / auto_total) if auto_total else 0.0
        out.append({
            "threshold": t,
            "auto_decided": auto_total,
            "auto_share": share,
            "auto_error_rate": err,
            "delivered_attacks": missed_attacks,
            "safe_to_attack": safe_to_attack,
        })
    return out


def main() -> int:
    if not VECS_PATH.exists() or not IDS_PATH.exists():
        print(f"Embeddings not consolidated yet ({VECS_PATH}).", file=sys.stderr)
        return 1

    vecs_768 = np.load(VECS_PATH)
    ids = json.loads(IDS_PATH.read_text(encoding="utf-8"))
    corpus = load_corpus()
    jev_obs = load_jev_scale_observations()

    if len(ids) != 18314:
        raise SystemExit(f"ABORT: expected 18314 ids, got {len(ids)}")
    if len(jev_obs) != 18314:
        raise SystemExit(f"ABORT: expected 18314 clean Jev obs, got {len(jev_obs)}")

    # Align data
    sources = [corpus[eid]["source"] for eid in ids]
    groups = [corpus[eid]["subject_group"] for eid in ids]
    labels_reg = [corpus[eid]["label_registered"] for eid in ids]
    labels_remap = [corpus[eid]["label_remap"] for eid in ids]

    ts = now()
    run_id = f"eg2-email-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    RECORDS_OUT_DIR.mkdir(parents=True, exist_ok=True)
    records_file = RECORDS_OUT_DIR / f"{run_id}.jsonl"

    print("Running E1 OOF (Registered basis, 768d)...")
    e1_reg_preds, e1_reg_confs, e1_reg_probs, e1_reg_folds = run_e1_oof(vecs_768, ids, labels_reg, groups)

    print("Running E1 OOF (CEAS-remap basis, 768d)...")
    e1_remap_preds, e1_remap_confs, e1_remap_probs, e1_remap_folds = run_e1_oof(vecs_768, ids, labels_remap, groups)

    print("Running E1 OOF (Registered basis, MRL 256d sensitivity)...")
    vecs_256 = truncate_and_normalize_mrl(vecs_768, 256)
    e1_256_preds, e1_256_confs, e1_256_probs, e1_256_folds = run_e1_oof(vecs_256, ids, labels_reg, groups)

    # E2 Holdouts
    print("Running E2a (Nazario holdout)...")
    nazario_mask = np.array([s == "nazario" for s in sources])
    e2a_preds, e2a_confs, e2a_probs = fit_and_predict(vecs_768[~nazario_mask], [labels_reg[i] for i in range(len(ids)) if not nazario_mask[i]], vecs_768[nazario_mask])

    print("Running E2b (Nigerian_5 holdout)...")
    nig5_mask = np.array([s == "nigerian_5" for s in sources])
    e2b_preds, e2b_confs, e2b_probs = fit_and_predict(vecs_768[~nig5_mask], [labels_reg[i] for i in range(len(ids)) if not nig5_mask[i]], vecs_768[nig5_mask])

    # Recompute Jev baseline stats
    jev_clean_attacks_total = sum(1 for eid, r in jev_obs.items() if corpus[eid]["source"] in CLEAN_SOURCES and corpus[eid]["label_registered"] == "attack")
    jev_clean_attacks_correct = sum(1 for eid, r in jev_obs.items() if corpus[eid]["source"] in CLEAN_SOURCES and corpus[eid]["label_registered"] == "attack" and r["label_pred"] == "attack")
    jev_clean_recall = jev_clean_attacks_correct / jev_clean_attacks_total
    
    # Jev auto-share at registered T=0.30
    jev_auto_total = sum(1 for r in jev_obs.values() if r["label_pred"] in ("attack", "safe") and (r.get("confidence") or 0.0) >= 0.30)
    jev_auto_share_030 = jev_auto_total / len(jev_obs)
    
    # Jev delivered attacks on clean sources at T=0.30
    jev_clean_delivered_030 = sum(1 for eid, r in jev_obs.items() if corpus[eid]["source"] in CLEAN_SOURCES and corpus[eid]["label_registered"] == "attack" and r["label_pred"] == "safe" and (r.get("confidence") or 0.0) >= 0.30)

    # EG2 stats on clean sources (E1 Registered)
    eg2_clean_attacks_total = jev_clean_attacks_total
    eg2_clean_attacks_correct = sum(1 for i, eid in enumerate(ids) if sources[i] in CLEAN_SOURCES and labels_reg[i] == "attack" and e1_reg_preds[i] == "attack")
    eg2_clean_recall = eg2_clean_attacks_correct / eg2_clean_attacks_total

    # Matched threshold search
    t_matched = find_matched_threshold(list(zip(e1_reg_preds, e1_reg_confs)), jev_auto_share_030)
    eg2_clean_delivered_matched = sum(1 for i, eid in enumerate(ids) if sources[i] in CLEAN_SOURCES and labels_reg[i] == "attack" and e1_reg_preds[i] == "safe" and e1_reg_confs[i] >= t_matched)

    # E2 Holdout recalls
    naz_attacks_total = int(nazario_mask.sum())
    naz_correct = sum(1 for p in e2a_preds if p == "attack")
    e2a_naz_recall = naz_correct / naz_attacks_total

    nig5_attacks_total = int(nig5_mask.sum())
    nig5_correct = sum(1 for p in e2b_preds if p == "attack")
    e2b_nig_recall = nig5_correct / nig5_attacks_total

    # Embed latency
    latency_p50 = float(np.median(np.load(LATENCY_PATH))) if LATENCY_PATH.exists() else None

    # Criteria evaluation
    crit = [
        {
            "id": "C8a", "desc": "E1 attack recall on clean sources >= Jev",
            "actual": f"EG2: {eg2_clean_recall:.4f} vs Jev: {jev_clean_recall:.4f}",
            "pass": bool(eg2_clean_recall >= jev_clean_recall),
        },
        {
            "id": "C8b", "desc": "E1 delivered attacks on clean sources at matched auto-share < Jev (60)",
            "actual": f"EG2: {eg2_clean_delivered_matched} (T={t_matched:.3f}) vs Jev: {jev_clean_delivered_030} (T=0.30)",
            "pass": bool(eg2_clean_delivered_matched < jev_clean_delivered_030),
        },
        {
            "id": "C8c", "desc": "E2a nazario attack recall >= 0.80",
            "actual": f"{e2a_naz_recall:.4f} ({naz_correct}/{naz_attacks_total})",
            "pass": bool(e2a_naz_recall >= 0.80),
        },
        {
            "id": "C8d", "desc": "E2b nigerian_5 attack recall >= 0.80",
            "actual": f"{e2b_nig_recall:.4f} ({nig5_correct}/{nig5_attacks_total})",
            "pass": bool(e2b_nig_recall >= 0.80),
        },
        {
            "id": "C8e", "desc": "Embed latency CPU p50 <= 1000 ms/email",
            "actual": f"{latency_p50:.1f} ms" if latency_p50 else "N/A",
            "pass": bool(latency_p50 <= 1000.0) if latency_p50 else False,
        },
    ]

    # Overall accuracy & matrices
    mat_reg = confusion_matrix(labels_reg, e1_reg_preds)
    acc_reg = sum(mat_reg[l][l] for l in LABELS) / len(ids)
    stats_reg = per_class_metrics(mat_reg)

    mat_remap = confusion_matrix(labels_remap, e1_remap_preds)
    acc_remap = sum(mat_remap[l][l] for l in LABELS) / len(ids)
    stats_remap = per_class_metrics(mat_remap)

    mat_256 = confusion_matrix(labels_reg, e1_256_preds)
    acc_256 = sum(mat_256[l][l] for l in LABELS) / len(ids)

    # Jev on the same rows, recomputed from records (no hard-coded figures)
    jev_preds = [jev_obs[eid]["label_pred"] for eid in ids]
    mat_jev = confusion_matrix(labels_reg, jev_preds)
    acc_jev = sum(mat_jev[l][l] for l in LABELS) / len(ids)
    mat_jev_remap = confusion_matrix(labels_remap, jev_preds)
    acc_jev_remap = sum(mat_jev_remap[l][l] for l in LABELS) / len(ids)

    # Write committed records JSONL: one row per email x eval x basis (PLAN C8)
    print(f"Writing records to {records_file}...")
    naz_idx = [i for i in range(len(ids)) if nazario_mask[i]]
    nig_idx = [i for i in range(len(ids)) if nig5_mask[i]]
    record_sets = [
        ("E1_oof", "registered", range(len(ids)), e1_reg_preds, e1_reg_confs, e1_reg_probs, e1_reg_folds, labels_reg),
        ("E1_oof", "remap", range(len(ids)), e1_remap_preds, e1_remap_confs, e1_remap_probs, e1_remap_folds, labels_remap),
        ("E1_oof_mrl256", "registered", range(len(ids)), e1_256_preds, e1_256_confs, e1_256_probs, e1_256_folds, labels_reg),
        ("E2a_nazario", "registered", naz_idx, e2a_preds, e2a_confs, e2a_probs, None, labels_reg),
        ("E2b_nigerian_5", "registered", nig_idx, e2b_preds, e2b_confs, e2b_probs, None, labels_reg),
    ]
    with records_file.open("w", encoding="utf-8") as rf:
        rf.write(json.dumps({
            "kind": "run_meta", "run_id": run_id, "model": "google/embeddinggemma-2",
            "ts_utc": ts, "corpus": str(CORPUS.relative_to(REPO)), "n_emails": len(ids),
            "head": "LogisticRegression(C=1.0, class_weight='balanced')",
        }) + "\n")
        seq = 1
        for ev, basis, rows, preds, confs, probs, folds, truth in record_sets:
            for k, i in enumerate(rows):
                # E1 arrays are indexed by global row; E2 arrays by position within the holdout
                j = i if ev.startswith("E1") else k
                rf.write(json.dumps({
                    "kind": "observation", "run_id": run_id, "seq": seq, "ts_utc": ts,
                    "email_id": ids[i], "source": sources[i],
                    "eval": ev, "basis": basis, "fold": folds[i] if folds is not None else None,
                    "label_true": truth[i], "label_pred": preds[j],
                    "confidence": round(confs[j], 4), "probabilities": {c: round(v, 4) for c, v in probs[j].items()},
                }) + "\n")
                seq += 1

    # Save summary json
    summary = {
        "run_id": run_id, "ts_utc": ts, "n_emails": len(ids),
        "criteria": crit,
        "registered_basis": {"accuracy": acc_reg, "matrix": mat_reg, "per_class": stats_reg},
        "remap_basis": {"accuracy": acc_remap, "matrix": mat_remap, "per_class": stats_remap},
        "jev_same_rows": {"accuracy_registered": acc_jev, "accuracy_remap": acc_jev_remap,
                          "matrix_registered": mat_jev, "clean_attack_recall": jev_clean_recall,
                          "clean_delivered_030": jev_clean_delivered_030},
        "e2_holdouts": {"nazario_recall": e2a_naz_recall, "nigerian_5_recall": e2b_nig_recall},
        "mrl_256_sensitivity": {"accuracy": acc_256},
        "matched_gate": {
            "jev_auto_share_030": jev_auto_share_030,
            "t_matched": t_matched,
            "clean_delivered_attacks": eg2_clean_delivered_matched,
        },
        "sweep_registered": sweep(e1_reg_preds, e1_reg_confs, labels_reg),
    }
    (OUT_DIR / "results-email.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Generate Markdown report
    md_lines = [
        "# EG2 Email Triage (Battery C) — Results Report",
        "",
        f"**Date:** {ts[:10]} · **Run ID:** `{run_id}`",
        f"**Model:** `google/embeddinggemma-2` (270M text config, frozen, 768-d, max_seq=512)",
        "**Head:** LogisticRegression (C=1.0, balanced weights)",
        "**Comparator:** Jev scale run (`jev-scale-20260917T184615Z`)",
        "",
        "## 1. Registered Criteria Outcome (PLAN C7)",
        "",
        "| ID | Criterion | Actual | Result |",
        "|---|---|---|---|",
    ]
    for c in crit:
        status = "**PASS**" if c["pass"] else "**MISS**"
        md_lines.append(f"| {c['id']} | {c['desc']} | {c['actual']} | {status} |")

    md_lines.extend([
        "",
        "## 2. Overall Performance Comparison",
        "",
        "| Metric | Jev Scale | EG2 E1 (Registered) | EG2 E1 (CEAS Remap) | EG2 256-d MRL |",
        "|---|---|---|---|---|",
        f"| Exact Accuracy | {acc_jev:.4f} (remap basis {acc_jev_remap:.4f}) | **{acc_reg:.4f}** | **{acc_remap:.4f}** | {acc_256:.4f} |",
        f"| Clean Attack Recall (Nazario+Nig5) | {jev_clean_recall:.4f} | **{eg2_clean_recall:.4f}** | - | - |",
        f"| Clean Delivered Attacks (matched share) | {jev_clean_delivered_030} (@T=0.30) | **{eg2_clean_delivered_matched}** (@T={t_matched:.3f}) | - | - |",
        "",
        "## 3. Confusion Matrix (Registered Basis, n=18,314)",
        "",
        "| True \\ Pred | safe | gray | spam | attack | Recall | Precision |",
        "|---|---|---|---|---|---|---|",
    ])
    for l in LABELS:
        r_stats = stats_reg[l]
        rec = f"{r_stats['recall']:.4f}" if r_stats['recall'] is not None else "-"
        prec = f"{r_stats['precision']:.4f}" if r_stats['precision'] is not None else "-"
        md_lines.append(f"| {l} | {mat_reg[l]['safe']} | {mat_reg[l]['gray']} | {mat_reg[l]['spam']} | {mat_reg[l]['attack']} | {rec} | {prec} |")

    md_lines.extend([
        "",
        "## 4. Cross-source holdouts (PLAN C5.E2 — the fairer generalization test)",
        "",
        f"- E2a nazario: attack recall {e2a_naz_recall:.4f} ({naz_correct}/{naz_attacks_total})",
        f"- E2b nigerian_5: attack recall {e2b_nig_recall:.4f} ({nig5_correct}/{nig5_attacks_total})",
        f"- MRL 256-d accuracy {acc_256:.4f} vs 768-d {acc_reg:.4f} (registered basis)",
        "",
        "## 5. Limitations (PLAN C9)",
        "",
        "- EG2's head is supervised on in-distribution labels; Jev was zero-shot. E1 favours EG2.",
        "- Corpus era 2003–2008; CEAS_08 label semantics per `SCALE-READINGS.md` §2.",
        "- Subject-hash grouping reduces but does not remove template leakage.",
        "",
        "## 6. Deviations",
        "",
        "- Harness errata fixed before scoring (2026-10-08): records now hold every eval × basis "
        "row as PLAN C8 specifies (previously E1-registered only); the Jev comparison column is "
        "recomputed from records (previously a hard-coded 0.599); pre-written takeaway bullets "
        "authored before any data were removed and replaced with computed figures.",
    ])
    (OUT_DIR / "RESULTS-EMAIL.md").write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Report written to {OUT_DIR / 'RESULTS-EMAIL.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
