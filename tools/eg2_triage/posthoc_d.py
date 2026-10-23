"""POST-HOC (not pre-registered) follow-ups to Batteries C/D, run 2026-10-09 after reading results.

1. Veto under cross-source holdout: Jev's confident-safe attack deliveries on nazario / nigerian_5,
   re-checked by the EG2 head that never saw that source (Battery C E2a / E2b records).
2. TF-IDF control under the same cross-source holdouts (is the collapse EG2-specific?).

Writes docs/research/eg2-email-triage/POSTHOC-D.json. Everything here is labeled post-hoc.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

from run_jev import normalized_state  # noqa: E402
from score_email import load_corpus, load_jev_scale_observations  # noqa: E402

OUT = REPO / "docs" / "research" / "eg2-email-triage"
CORPUS = REPO / "corpus" / "email" / "scale" / "scale-corpus.jsonl"
T_JEV = 0.30


def main() -> int:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    corpus = load_corpus()
    jev = load_jev_scale_observations()
    rec = sorted((OUT / "records").glob("eg2-email-*.jsonl"))[-1]
    rows = [json.loads(line) for line in rec.read_text(encoding="utf-8").splitlines()][1:]
    held = {(r["eval"], r["email_id"]): r for r in rows if r["eval"].startswith("E2")}

    res = {"label": "POST-HOC", "records": rec.name, "veto_cross_source": {}, "tfidf_cross_source": {}}
    for ev, src in [("E2a_nazario", "nazario"), ("E2b_nigerian_5", "nigerian_5")]:
        ids = [e for e, c in corpus.items() if c["source"] == src]
        conf_safe = [e for e in ids if jev[e]["label_pred"] == "safe" and float(jev[e].get("confidence") or 0) >= T_JEV]
        caught = [e for e in conf_safe if held[(ev, e)]["label_pred"] == "attack"]
        not_safe = [e for e in conf_safe if held[(ev, e)]["label_pred"] != "safe"]
        t_matched = json.loads((OUT / "results-email.json").read_text(encoding="utf-8"))["matched_gate"]["t_matched"]
        res["veto_cross_source"][src] = {"jev_confident_safe_attacks": len(conf_safe),
                                         "eg2_unseen_source_flags_attack": len(caught),
                                         "eg2_unseen_source_not_safe": len(not_safe),
                                         "jev_attack_recall_on_source": sum(1 for e in ids if jev[e]["label_pred"] == "attack") / len(ids),
                                         "eg2_heldout_confident_safe_T030": sum(1 for e in ids if held[(ev, e)]["label_pred"] == "safe" and held[(ev, e)]["confidence"] >= T_JEV),
                                         "eg2_heldout_confident_safe_T_matched": sum(1 for e in ids if held[(ev, e)]["label_pred"] == "safe" and held[(ev, e)]["confidence"] >= t_matched),
                                         "t_matched": t_matched}

    # Strict veto (EG2 must also call it safe) vs registered lenient veto, in-distribution (E1 remap)
    e1 = {r["email_id"]: r for r in rows if r["eval"] == "E1_oof" and r["basis"] == "remap"}
    cs = [e for e in corpus if jev[e]["label_pred"] == "safe" and float(jev[e].get("confidence") or 0) >= T_JEV]
    cs_safe = [e for e in cs if corpus[e]["label_remap"] == "safe"]
    cs_att = [e for e in cs if corpus[e]["label_remap"] == "attack"]
    res["strict_veto_e1_remap"] = {
        "jev_confident_safe_attacks": len(cs_att),
        "attacks_remaining": sum(1 for e in cs_att if e1[e]["label_pred"] == "safe"),
        "jev_correct_safe_deliveries": len(cs_safe),
        "legit_safe_held": sum(1 for e in cs_safe if e1[e]["label_pred"] != "safe"),
    }

    texts = {}
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                texts[r["email_id"]] = normalized_state(r)
    all_ids = sorted(corpus)
    for src in ["nazario", "nigerian_5"]:
        tr = [e for e in all_ids if corpus[e]["source"] != src]
        te = [e for e in all_ids if corpus[e]["source"] == src]
        vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200000, sublinear_tf=True)
        Xtr = vec.fit_transform([texts[e] for e in tr])
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, random_state=20261008)
        clf.fit(Xtr, [corpus[e]["label_registered"] for e in tr])
        pred = clf.predict(vec.transform([texts[e] for e in te]))
        vals, counts = np.unique(pred, return_counts=True)
        res["tfidf_cross_source"][src] = {"n": len(te), "attack_recall": float((pred == "attack").mean()),
                                          "pred_counts": {str(v): int(c) for v, c in zip(vals, counts)}}
    (OUT / "POSTHOC-D.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


def posthoc_v_operating_point() -> dict:
    """POST-HOC (2026-10-09): EG2 A3 recall at the vision LLM's own false-alarm rate (Battery V)."""
    import stats_util as su
    from battery_a_urls import load_sample
    url_dir = REPO / "docs" / "research" / "eg2-url-benchmark"
    df = load_sample()
    y = (df["label_name"] == "phishing").astype(int).values
    a_rec = sorted((url_dir / "records").glob("battery-a-*.jsonl"))[-1]
    a = {r["file_name"]: r for r in (json.loads(l) for l in a_rec.read_text(encoding="utf-8").splitlines()[1:])}
    p3 = np.array([a[k]["p"]["a3_interleaved"] for k in df["file_name"]])
    v = json.loads((url_dir / "results-v.json").read_text(encoding="utf-8"))
    out = {"label": "POST-HOC"}
    for arm in v["arms"]:
        fpr = v["arms"][arm]["fpr"][0]
        out[arm] = {"vlm_recall": v["arms"][arm]["recall"][0], "vlm_fpr": fpr, "a3_at_same_fpr": su.tpr_at_fpr(y, p3, fpr)}
    (url_dir / "POSTHOC-V.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--v":
        print(json.dumps(posthoc_v_operating_point(), indent=2))
        sys.exit(0)
    sys.exit(main())
