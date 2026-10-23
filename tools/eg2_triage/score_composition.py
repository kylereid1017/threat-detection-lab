"""Battery D — Jev x EG2 composition (PLAN-addendum-D-composition.md).

Reads recorded Jev scale observations and Battery C's E1 out-of-fold records + embeddings.
No model calls. Writes docs/research/eg2-email-triage/results-composition.json.

Run (after score_email.py):
  python tools/eg2_triage/score_composition.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402
from run_jev import normalized_state  # noqa: E402
from score_email import CLEAN_SOURCES, LABELS, load_corpus, load_jev_scale_observations  # noqa: E402

CORPUS = REPO / "corpus" / "email" / "scale" / "scale-corpus.jsonl"
EG2_DIR = REPO / "corpus" / "email" / "scale" / "eg2"
OUT_DIR = REPO / "docs" / "research" / "eg2-email-triage"
REC_DIR = OUT_DIR / "records"
T_JEV = 0.30
T2_REGISTERED = (0.50, 0.90)
SEED = su.SEED
PREVALENCES = (1e-3, 1e-4)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_eg2_oof(basis: str) -> dict[str, dict]:
    files = sorted(REC_DIR.glob("eg2-email-*.jsonl"))
    if not files:
        raise SystemExit("ABORT: run score_email.py first (Battery C records missing)")
    out = {}
    for line in files[-1].read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r.get("kind") == "observation" and r["eval"] == "E1_oof" and r["basis"] == basis:
            out[r["email_id"]] = r
    return out


def jev_features(obs: dict) -> list[float]:
    ans = obs.get("raw_answer") or {}
    probs = (ans.get("disposition") or {}).get("probabilities") or {}
    f = [float(probs.get(k, 0.0) or 0.0) for k in LABELS]
    f.append(float((ans.get("deception_present") or {}).get("noul", 0.0) or 0.0))
    f.append(float((ans.get("requests_credentials_or_payment") or {}).get("noul", 0.0) or 0.0))
    f.append(float(obs.get("confidence") or 0.0))
    f.extend(1.0 if obs.get("label_pred") == k else 0.0 for k in LABELS)
    return f


def missing_feature_count(obs: dict) -> int:
    ans = obs.get("raw_answer") or {}
    probs = (ans.get("disposition") or {}).get("probabilities")
    n = 0 if probs else 1
    n += 0 if (ans.get("deception_present") or {}).get("noul") is not None else 1
    n += 0 if (ans.get("requests_credentials_or_payment") or {}).get("noul") is not None else 1
    return n


def two_branch(pred: np.ndarray, conf: np.ndarray, t: float) -> np.ndarray:
    out = np.full(len(pred), "escalate", dtype=object)
    out[(pred == "attack") & (conf >= t)] = "quarantine"
    out[(pred == "safe") & (conf >= t)] = "deliver"
    return out


def outcome(decision: np.ndarray, truth: np.ndarray) -> dict:
    auto = decision != "escalate"
    wrong = ((decision == "quarantine") & (truth != "attack")) | ((decision == "deliver") & (truth != "safe"))
    return {
        "auto_share": float(auto.mean()), "human_share": float((~auto).mean()),
        "delivered_attacks": int(((decision == "deliver") & (truth == "attack")).sum()),
        "quarantined_safe": int(((decision == "quarantine") & (truth == "safe")).sum()),
        "auto_error_rate": float(wrong[auto].mean()) if auto.any() else 0.0,
    }


def policy_block(y: np.ndarray, flag: np.ndarray) -> dict:
    b = su.binary_counts(y, flag)
    r, f = b["recall"][0], b["fpr"][0]
    b["projected_precision"] = {str(p): su.projected_precision(r, f, p) for p in PREVALENCES}
    return b


def composition(basis: str, ids, corpus, jev, eg2) -> dict:
    truth = np.array([corpus[e]["label_registered" if basis == "registered" else "label_remap"] for e in ids])
    src = np.array([corpus[e]["source"] for e in ids])
    y = truth == "attack"
    jl = np.array([jev[e]["label_pred"] for e in ids])
    jc = np.array([float(jev[e].get("confidence") or 0.0) for e in ids])
    el = np.array([eg2[e]["label_pred"] for e in ids])
    ec = np.array([float(eg2[e]["confidence"]) for e in ids])
    J, E = jl == "attack", el == "attack"
    out = {"n": len(ids), "n_attack": int(y.sum()),
           "policies": {"J": policy_block(y, J), "E": policy_block(y, E),
                        "J_and_E": policy_block(y, J & E), "J_or_E": policy_block(y, J | E)}}
    pos, neg = y, ~y
    out["mcnemar"] = {
        "J_and_E_vs_J": {"negatives": su.mcnemar_exact(~(J & E)[neg], ~J[neg]),
                         "positives": su.mcnemar_exact((J & E)[pos], J[pos])},
        "E_vs_J": {"negatives": su.mcnemar_exact(~E[neg], ~J[neg]),
                   "positives": su.mcnemar_exact(E[pos], J[pos])},
    }
    # Veto (PLAN D3)
    jd = two_branch(jl, jc, T_JEV)
    conf_safe = jd == "deliver"
    clean = np.isin(src, list(CLEAN_SOURCES))
    held = conf_safe & E
    correct_safe = conf_safe & (truth == "safe")
    out["veto"] = {
        "jev_delivered_attacks": int((conf_safe & y).sum()),
        "jev_delivered_attacks_clean": int((conf_safe & y & clean).sum()),
        "after_veto_delivered_attacks": int((conf_safe & y & ~E).sum()),
        "after_veto_delivered_attacks_clean": int((conf_safe & y & clean & ~E).sum()),
        "jev_correct_safe_deliveries": int(correct_safe.sum()),
        "legit_safe_held": int((correct_safe & E).sum()),
        "legit_safe_held_pct": float((correct_safe & E).sum() / max(1, correct_safe.sum())),
        "all_held": int(held.sum()),
    }
    # Cascade (PLAN D3)
    jev_alone = outcome(jd, truth)
    cascade = {"jev_alone_T030": jev_alone, "registered": {}, "sweep": []}
    esc = jd == "escalate"
    for t2 in list(T2_REGISTERED) + [round(x, 2) for x in np.arange(0.30, 1.00, 0.01)]:
        d = jd.copy()
        d[esc] = two_branch(el[esc], ec[esc], t2)
        o = outcome(d, truth)
        o["stage2_share"] = float(esc.mean())
        o["stage2_auto_share"] = float(((d != "escalate") & esc).mean())
        if t2 in T2_REGISTERED and str(t2) not in cascade["registered"]:
            # EG2-alone comparator at matched human share (0.001 grid)
            best = None
            for step in range(1001):
                t = step / 1000
                o2 = outcome(two_branch(el, ec, t), truth)
                if o2["human_share"] >= o["human_share"] - 1e-12:
                    best = {"t": t, **o2}
                    break
            cascade["registered"][str(t2)] = {"cascade": o, "eg2_alone_matched": best}
        else:
            cascade["sweep"].append({"t2": t2, **o})
    out["cascade"] = cascade
    return out


def stacking(ids, corpus, jev, eg2_remap) -> dict:
    from scipy.sparse import csr_matrix, hstack
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score
    from sklearn.preprocessing import StandardScaler

    vecs = np.load(EG2_DIR / "embeddings-768.npy")
    order = json.loads((EG2_DIR / "ids.json").read_text(encoding="utf-8"))
    pos_of = {e: i for i, e in enumerate(order)}
    V = vecs[[pos_of[e] for e in ids]]
    Jf = np.array([jev_features(jev[e]) for e in ids])
    truth = np.array([corpus[e]["label_remap"] for e in ids])
    src = np.array([corpus[e]["source"] for e in ids])
    folds = np.array([eg2_remap[e]["fold"] for e in ids])
    texts = {}
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                texts[r["email_id"]] = normalized_state(r)
    T = [texts[e] for e in ids]

    def head():
        return LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, solver="lbfgs", random_state=SEED)

    def run(kind: str, n_per_class: int | None = None):
        P = np.zeros((len(ids), len(LABELS)))
        rng = np.random.default_rng(SEED)
        for k in range(5):
            tr, te = np.flatnonzero(folds != k), np.flatnonzero(folds == k)
            if n_per_class:
                tr = np.concatenate([rng.choice(tr[truth[tr] == c], min(n_per_class, int((truth[tr] == c).sum())), replace=False)
                                     for c in LABELS])
            if kind == "S-E":
                Xtr, Xte = V[tr], V[te]
            elif kind == "S-J":
                sc = StandardScaler().fit(Jf[tr])
                Xtr, Xte = sc.transform(Jf[tr]), sc.transform(Jf[te])
            elif kind == "S-EJ":
                sc = StandardScaler().fit(Jf[tr])
                Xtr, Xte = np.hstack([V[tr], sc.transform(Jf[tr])]), np.hstack([V[te], sc.transform(Jf[te])])
            else:  # T-IDF
                vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200000, sublinear_tf=True)
                Xtr = vec.fit_transform([T[i] for i in tr])
                Xte = vec.transform([T[i] for i in te])
            clf = head().fit(Xtr, truth[tr])
            P[np.ix_(te, [LABELS.index(c) for c in clf.classes_])] = clf.predict_proba(Xte)
            print(f"[{now()}] {kind} n={n_per_class} fold {k} done", flush=True)
        return P

    def metrics(P):
        pred = np.array(LABELS)[P.argmax(1)]
        ya = (truth == "attack").astype(int)
        clean = np.isin(src, list(CLEAN_SOURCES)) & (truth == "attack")
        return {**su.auc_with_ci(ya, P[:, LABELS.index("attack")], n_boot=500),
                "macro_f1": float(f1_score(truth, pred, average="macro")),
                "accuracy": float((pred == truth).mean()),
                "clean_attack_recall": float((pred[clean] == "attack").mean()),
                "safe_to_attack": int(((truth == "safe") & (pred == "attack")).sum())}

    res, probs = {}, {}
    for kind in ["S-E", "S-J", "S-EJ", "T-IDF"]:
        probs[kind] = run(kind)
        res[kind] = metrics(probs[kind])
    ya = (truth == "attack").astype(int)
    ai = LABELS.index("attack")
    res["D-c_SEJ_minus_SE"] = su.paired_bootstrap_auc(ya, probs["S-EJ"][:, ai], probs["S-E"][:, ai])
    res["D-d_SE_minus_TIDF"] = su.paired_bootstrap_auc(ya, probs["S-E"][:, ai], probs["T-IDF"][:, ai])
    res["label_efficiency"] = {}
    for n in (25, 100, 400):
        for kind in ["S-E", "T-IDF"]:
            res["label_efficiency"][f"{kind}@{n}"] = metrics(run(kind, n))
    res["jev_missing_feature_rows"] = int(sum(1 for e in ids if missing_feature_count(jev[e]) > 0))
    return res


def main() -> int:
    corpus = load_corpus()
    jev = load_jev_scale_observations()
    eg2_reg, eg2_remap = load_eg2_oof("registered"), load_eg2_oof("remap")
    ids = sorted(corpus)
    if not (len(ids) == len(jev) == len(eg2_reg) == len(eg2_remap) == 18314):
        raise SystemExit("ABORT: join is not 18,314 x 4")
    res = {"ts_utc": now(), "plan": "tools/eg2_triage/PLAN-addendum-D-composition.md",
           "remap": composition("remap", ids, corpus, jev, eg2_remap),
           "registered": composition("registered", ids, corpus, jev, eg2_reg)}
    res["stacking_remap"] = stacking(ids, corpus, jev, eg2_remap)
    r, s = res["remap"], res["stacking_remap"]
    pj, pje = r["policies"]["J"], r["policies"]["J_and_E"]
    v = r["veto"]
    res["criteria"] = [
        {"id": "D-a", "desc": "J∧E fewer FPs than J (McNemar p<0.05) and J∧E recall >= 0.90",
         "actual": {"fp_J": pj["fp"], "fp_JE": pje["fp"], "recall_JE": pje["recall"][0],
                    "p": r["mcnemar"]["J_and_E_vs_J"]["negatives"]["p_exact"]},
         "pass": pje["fp"] < pj["fp"] and r["mcnemar"]["J_and_E_vs_J"]["negatives"]["p_exact"] < 0.05 and pje["recall"][0] >= 0.90},
        {"id": "D-b", "desc": "Veto cuts clean-source confident-safe attack deliveries >= 50% holding <= 1.0% of correct safe deliveries",
         "actual": {"before": v["jev_delivered_attacks_clean"], "after": v["after_veto_delivered_attacks_clean"],
                    "held_pct": v["legit_safe_held_pct"]},
         "pass": v["after_veto_delivered_attacks_clean"] <= 0.5 * v["jev_delivered_attacks_clean"] and v["legit_safe_held_pct"] <= 0.01},
        {"id": "D-c", "desc": "S-EJ attack PR-AUC > S-E (bootstrap CI excludes 0)", "actual": s["D-c_SEJ_minus_SE"],
         "pass": s["D-c_SEJ_minus_SE"]["d_pr_auc_ci"][0] > 0},
        {"id": "D-d", "desc": "S-E attack PR-AUC > T-IDF (bootstrap CI excludes 0)", "actual": s["D-d_SE_minus_TIDF"],
         "pass": s["D-d_SE_minus_TIDF"]["d_pr_auc_ci"][0] > 0},
    ]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "results-composition.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps({c["id"]: c["pass"] for c in res["criteria"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
