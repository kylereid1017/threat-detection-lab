"""Batteries L (labels), G (gate), N (brand impersonation), K (kits) — PLAN-addendum-LGNKR.md.

All four run on cached Battery A / X embeddings and recorded verdicts. N embeds ~31 short text
queries; nothing else calls a model.

  python tools/eg2_triage/battery_lgnk.py --l | --g | --n | --k
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402
from battery_a_urls import EMB_DIR as A_EMB, load_sample  # noqa: E402
from battery_x_crossdataset import EMB as X_EMB, load_x  # noqa: E402

OUT = REPO / "docs" / "research" / "eg2-url-benchmark"
REC = OUT / "records"
SEED = 20261009
SLD = {"co", "com", "net", "org", "gov", "ac", "edu"}

# brand (Phishpedia label) -> (display name for the query, official registrable domains, ccTLD-variant label)
BRANDS = {
    "Office365": ("Microsoft Office 365", {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com"}, None),
    "Outlook": ("Microsoft Outlook", {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"}, None),
    "PayPal Inc.": ("PayPal", {"paypal.com", "paypal.me"}, "paypal"),
    "AT&T Inc.": ("AT&T", {"att.com", "att.net", "yahoo.com"}, None),
    "Orange": ("Orange", set(), "orange"),
    "Chase Personal Banking": ("Chase bank", {"chase.com", "jpmorganchase.com"}, None),
    "Microsoft OneDrive": ("Microsoft OneDrive", {"microsoft.com", "microsoftonline.com", "live.com", "onedrive.com", "office.com"}, None),
    "Facebook, Inc.": ("Facebook", {"facebook.com", "fb.com", "meta.com", "messenger.com"}, None),
    "Amazon.com Inc.": ("Amazon", set(), "amazon"),
    "Netflix Inc.": ("Netflix", {"netflix.com"}, None),
    "Bank of America": ("Bank of America", {"bankofamerica.com", "bofa.com"}, None),
    "DHL Airways, Inc.": ("DHL", set(), "dhl"),
    "LinkedIn Corporation": ("LinkedIn", {"linkedin.com"}, None),
    "Dropbox, Inc.": ("Dropbox", {"dropbox.com"}, None),
    "Apple Inc.": ("Apple ID", {"apple.com", "icloud.com"}, None),
    "Yahoo! Inc": ("Yahoo Mail", set(), "yahoo"),
    "Adobe Inc.": ("Adobe", {"adobe.com"}, None),
    "Wells Fargo & Company": ("Wells Fargo", {"wellsfargo.com", "wf.com"}, None),
    "M & T Bank Coporation": ("M&T Bank", {"mtb.com"}, None),
    "Instagram": ("Instagram", {"instagram.com"}, None),
    "DocuSign": ("DocuSign", {"docusign.com", "docusign.net"}, None),
    "Itau Unibanco S.A": ("Itaú Unibanco", {"itau.com.br"}, None),
    "Google Inc.": ("Google", {"gmail.com"}, "google"),
    "WeTransfer": ("WeTransfer", {"wetransfer.com", "we.tl"}, None),
    "DGI (French Tax Authority)": ("French tax authority impots.gouv.fr", {"impots.gouv.fr"}, None),
    "RuneScape": ("RuneScape", {"runescape.com", "jagex.com"}, None),
    "WhatsApp": ("WhatsApp", {"whatsapp.com", "whatsapp.net"}, None),
    "Bank of Montreal": ("Bank of Montreal BMO", {"bmo.com"}, None),
    "Credit Agricole S.A.": ("Crédit Agricole", set(), "credit-agricole"),
    "Square, Inc.": ("Square", {"squareup.com"}, None),
    "Rakuten": ("Rakuten", set(), "rakuten"),
}
NAMES = list(BRANDS)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def regdom(url: str) -> str:
    try:
        host = (urlparse(url.strip()).hostname or "").lower()
    except ValueError:
        return ""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def official(url: str, brand: str) -> bool:
    _, doms, label = BRANDS[brand]
    rd = regdom(url)
    return rd in doms or (label is not None and rd.split(".")[0] == label)


def a_data():
    df = load_sample()
    y = (df["label_name"] == "phishing").astype(int).values
    groups = (df["file_name"].str.split("/").str[0] + "/" + df["file_name"].str.split("/").str[1]).values
    return df, y, groups


def load_vlm_map(name: str) -> dict:
    out = {}
    for line in (REC / name).read_text(encoding="utf-8").splitlines()[1:]:
        r = json.loads(line)
        if r["key"] not in out or not r.get("error"):
            out[r["key"]] = r
    return out


# ---------------------------------------------------------------- L
def run_l() -> int:
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupShuffleSplit
    df, y, groups = a_data()
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=SEED).split(y, y, groups))
    v4 = load_vlm_map("vlm-a-v3.jsonl")
    visible = np.array([(v4.get(k) or {}).get("verdict") == "phishing" for k in df["file_name"]])
    res = {"ts_utc": now(), "split": {"train": len(tr), "test": len(te)}, "arms": {}}
    for arm in ("a3_interleaved", "a1_url"):
        XA, XX = np.load(A_EMB / f"{arm}.npy"), np.load(X_EMB / f"{arm}.npy")
        neg_te = te[y[te] == 0]
        for variant in ("all_labels", "visible_labels"):
            if arm == "a1_url" and variant == "visible_labels":
                continue
            pos_pool = tr[(y[tr] == 1) & (visible[tr] if variant == "visible_labels" else True)]
            neg_pool = tr[y[tr] == 0]
            curve = {}
            for n in (10, 25, 50, 100, 150):
                k = min(n, len(pos_pool))
                stats = []
                for seed in range(20):
                    rng = np.random.default_rng(seed)
                    idx = np.concatenate([rng.choice(pos_pool, k, replace=False), rng.choice(neg_pool, min(n, len(neg_pool)), replace=False)])
                    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42).fit(XA[idx], y[idx])
                    ci = list(clf.classes_).index(1)
                    px, pn = clf.predict_proba(XX)[:, ci], clf.predict_proba(XA[neg_te])[:, ci]
                    yy = np.r_[np.ones(len(px)), np.zeros(len(pn))]
                    ss = np.r_[px, pn]
                    stats.append([float((px >= 0.5).mean()), float((pn >= 0.5).mean()), float(roc_auc_score(yy, ss)),
                                  su.tpr_at_fpr(yy, ss, 0.01)["tpr"]])
                s = np.array(stats)
                curve[n] = {"n_pos_used": int(k), **{name: {"median": float(np.median(s[:, j])), "p10": float(np.percentile(s[:, j], 10)),
                                                            "p90": float(np.percentile(s[:, j], 90))}
                                                     for j, name in enumerate(["x_recall_t05", "a_fpr_t05", "roc_auc", "x_recall_at_fpr1"])}}
            res["arms"][f"{arm}/{variant}"] = curve
    c50 = res["arms"]["a3_interleaved/all_labels"][50]
    res["criteria"] = [
        {"id": "L-a", "desc": "A3 n=50: median X recall at 0.5 >= 0.90", "actual": c50["x_recall_t05"], "pass": c50["x_recall_t05"]["median"] >= 0.90},
        {"id": "L-b", "desc": "A3 n=50: median ROC-AUC >= 0.95", "actual": c50["roc_auc"], "pass": c50["roc_auc"]["median"] >= 0.95},
    ]
    (OUT / "results-l.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    for key, curve in res["arms"].items():
        print(key)
        for n, c in curve.items():
            print(f"  n={n:>3} (pos {c['n_pos_used']:>3}) Xrec@.5 {c['x_recall_t05']['median']:.3f} [{c['x_recall_t05']['p10']:.3f},{c['x_recall_t05']['p90']:.3f}]  "
                  f"Afpr@.5 {c['a_fpr_t05']['median']:.3f}  AUC {c['roc_auc']['median']:.3f}  Xrec@FPR1% {c['x_recall_at_fpr1']['median']:.3f}")
    print({c["id"]: c["pass"] for c in res["criteria"]})
    return 0


# ---------------------------------------------------------------- G
def run_g() -> int:
    df, y, _ = a_data()
    a_rec = sorted(REC.glob("battery-a-*.jsonl"))[-1]
    a = {r["file_name"]: r for r in (json.loads(l) for l in a_rec.read_text(encoding="utf-8").splitlines()[1:])}
    pa = np.array([a[k]["p"]["a3_interleaved"] for k in df["file_name"]])
    _, xs = load_x()
    px = np.load(X_EMB / "a3_interleaved-p.npy")
    res = {"ts_utc": now(), "llms": {}}
    for tag, fa, fx in (("haiku_5_5", "vlm-a-v3_h55.jsonl", "vlm-x-v3_h55.jsonl"), ("haiku_4_5", "vlm-a-v3.jsonl", "vlm-x-v3.jsonl")):
        va, vx = load_vlm_map(fa), load_vlm_map(fx)
        la = np.array([(va.get(k) or {}).get("verdict") == "phishing" for k in df["file_name"]])
        lx = np.array([(vx.get(s["key"]) or {}).get("verdict") == "phishing" for s in xs])
        def summarize(fa_flag, fx_flag, share_a, share_x):
            return {"x_recall": su.wilson(int(fx_flag.sum()), len(fx_flag)),
                    "a_fpr": su.wilson(int((fa_flag & (y == 0)).sum()), int((y == 0).sum())),
                    "a_phish_recall_noisy": su.wilson(int((fa_flag & (y == 1)).sum()), int((y == 1).sum())),
                    "llm_share_a": share_a, "llm_share_x": share_x,
                    "llm_share_all": (share_a * len(pa) + share_x * len(px)) / (len(pa) + len(px))}
        block = {"eg2_alone": summarize(pa >= 0.5, px >= 0.5, 0.0, 0.0), "llm_alone": summarize(la, lx, 1.0, 1.0), "gates": {}}
        for lo, hi in ((0.2, 0.8), (0.1, 0.9), (0.05, 0.95)):
            ma, mx = (pa > lo) & (pa < hi), (px > lo) & (px < hi)
            fa_flag = (pa >= hi) | (ma & la)
            fx_flag = (px >= hi) | (mx & lx)
            block["gates"][f"{lo}-{hi}"] = summarize(fa_flag, fx_flag, float(ma.mean()), float(mx.mean()))
        res["llms"][tag] = block
    g, e, l = res["llms"]["haiku_5_5"]["gates"]["0.1-0.9"], res["llms"]["haiku_5_5"]["eg2_alone"], res["llms"]["haiku_5_5"]["llm_alone"]
    res["criteria"] = [{"id": "G-a", "desc": "Haiku 5.5 @ (0.1,0.9): A FPR <= EG2 alone, X recall >= LLM alone, LLM share <= 50%",
                        "actual": {"gate_fpr": g["a_fpr"][0], "eg2_fpr": e["a_fpr"][0], "gate_x_recall": g["x_recall"][0],
                                   "llm_x_recall": l["x_recall"][0], "llm_share": g["llm_share_all"]},
                        "pass": g["a_fpr"][0] <= e["a_fpr"][0] and g["x_recall"][0] >= l["x_recall"][0] and g["llm_share_all"] <= 0.5}]
    (OUT / "results-g.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    for tag, b in res["llms"].items():
        print(tag)
        for name, s in [("eg2_alone", b["eg2_alone"]), ("llm_alone", b["llm_alone"])] + list(b["gates"].items()):
            print(f"  {name:10s} Xrec {s['x_recall'][0]:.3f}  Afpr {s['a_fpr'][0]:.4f}  Aphish(noisy) {s['a_phish_recall_noisy'][0]:.3f}  LLM share {s['llm_share_all']:.3f}")
    print({c["id"]: c["pass"] for c in res["criteria"]})
    return 0


# ---------------------------------------------------------------- N
def run_n() -> int:
    import torch
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics import roc_auc_score
    df, y, _ = a_data()
    _, xs = load_x()
    model = SentenceTransformer("google/embeddinggemma-2", config_kwargs={"audio_config": None},
                                model_kwargs={"torch_dtype": torch.float32})
    Q = model.encode([f"task: search result | query: a {BRANDS[b][0]} login page" for b in NAMES],
                     normalize_embeddings=True, convert_to_numpy=True)
    IA, IX = np.load(A_EMB / "a2_image.npy"), np.load(X_EMB / "a2_image.npy")
    SA, SX = IA @ Q.T, IX @ Q.T
    # N1
    inset = [i for i, s in enumerate(xs) if s["brand"] in BRANDS]
    order = np.argsort(-SX, axis=1)
    top1 = np.mean([NAMES[order[i, 0]] == xs[i]["brand"] for i in inset])
    top3 = np.mean([xs[i]["brand"] in [NAMES[j] for j in order[i, :3]] for i in inset])
    # N2
    def score(S, urls):
        b = S.argmax(1)
        m = S.max(1)
        return np.array([0.0 if official(u, NAMES[bi]) else float(mi) for u, bi, mi in zip(urls, b, m)]), b
    sx, bx = score(SX, [s["url"] for s in xs])
    legit = np.flatnonzero(y == 0)
    sa, ba = score(SA[legit], df["url"].values[legit])
    yy = np.r_[np.ones(len(sx)), np.zeros(len(sa))]
    auc = float(roc_auc_score(yy, np.r_[sx, sa]))
    rng = random.Random(SEED)
    perm = list(range(len(sa)))
    rng.shuffle(perm)
    h1, h2 = np.array(perm[: len(sa) // 2]), np.array(perm[len(sa) // 2:])
    neg1 = sa[h1]
    tau = next((v for v in np.unique(np.r_[sx, sa]) if (neg1 >= v).mean() <= 0.01), np.inf)
    hostsub = np.array([s["subset"] == "x_host" for s in xs])
    # N3
    S = IX @ IX.T
    np.fill_diagonal(S, -np.inf)
    nn = S.argmax(1)
    nn_same = float(np.mean([xs[i]["brand"] == xs[nn[i]]["brand"] for i in range(len(xs))]))
    res = {"ts_utc": now(), "n_brands": len(NAMES), "n1": {"n": len(inset), "top1": float(top1), "top3": float(top3)},
           "n2": {"roc_auc": auc, "tau": float(tau), "x_recall": su.wilson(int((sx >= tau).sum()), len(sx)),
                  "x_host_recall": su.wilson(int((sx[hostsub] >= tau).sum()), int(hostsub.sum())),
                  "a_fpr_holdout": su.wilson(int((sa[h2] >= tau).sum()), len(h2))},
           "n3": {"nn_same_brand": nn_same, "median_nn_sim": float(np.median(S.max(1)))}}
    res["criteria"] = [{"id": "N-a", "desc": "N1 top-3 brand accuracy >= 0.70", "actual": res["n1"]["top3"], "pass": res["n1"]["top3"] >= 0.70},
                       {"id": "N-b", "desc": "N2 impersonation score ROC-AUC >= 0.90", "actual": auc, "pass": auc >= 0.90}]
    per = [{"key": s["key"], "brand_true": s["brand"], "brand_pred": NAMES[bx[i]], "sim": float(SX[i].max()),
            "official": official(s["url"], NAMES[bx[i]]), "score": float(sx[i]), "nn_key": xs[nn[i]]["key"],
            "nn_brand": xs[nn[i]]["brand"], "nn_sim": float(S[i, nn[i]])} for i, s in enumerate(xs)]
    (OUT / "results-n.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (REC / "n-per-page.json").write_text(json.dumps(per), encoding="utf-8")
    print(json.dumps({k: res[k] for k in ("n1", "n2", "n3")}, indent=1, default=str))
    print({c["id"]: c["pass"] for c in res["criteria"]})
    return 0


# ---------------------------------------------------------------- K
def run_k() -> int:
    from scipy.cluster.hierarchy import fcluster, linkage
    _, xs = load_x()
    E = np.load(X_EMB / "a2_image.npy")
    Z = linkage(E, method="average", metric="cosine")

    def when(s):
        try:
            return datetime.strptime(s["folder"].split("+")[-1][:10], "%Y-%m-%d")
        except ValueError:
            return None

    res = {"ts_utc": now(), "n": len(xs), "thresholds": {}}
    for t in (0.10, 0.05):
        lab = fcluster(Z, t=t, criterion="distance")
        clusters = {}
        for i, c in enumerate(lab):
            clusters.setdefault(int(c), []).append(i)
        multi = [m for m in clusters.values() if len(m) >= 2]
        multidom = [m for m in multi if len({regdom(xs[i]["url"]) for i in m}) >= 2]
        pur_num = sum(max(sum(1 for i in m if xs[i]["brand"] == b) for b in {xs[i]["brand"] for i in m}) for m in multi)
        spans = []
        for m in multidom:
            ds = [d for d in (when(xs[i]) for i in m) if d]
            if len(ds) >= 2:
                spans.append((max(ds) - min(ds)).days)
        biggest = sorted(multidom, key=len, reverse=True)[:5]
        res["thresholds"][str(t)] = {
            "clusters": len(clusters), "pages_in_multi": sum(len(m) for m in multi) / len(xs),
            "multi_domain_clusters": len(multidom), "pages_in_multi_domain": sum(len(m) for m in multidom) / len(xs),
            "purity_multi": pur_num / max(1, sum(len(m) for m in multi)),
            "span_days_median": float(np.median(spans)) if spans else None, "span_days_max": max(spans) if spans else None,
            "largest": [{"size": len(m), "domains": len({regdom(xs[i]['url']) for i in m}),
                         "brands": sorted({xs[i]['brand'] for i in m}), "keys": [xs[i]["key"] for i in m]} for m in biggest],
        }
    p = res["thresholds"]["0.1"]
    res["criteria"] = [{"id": "K-a", "desc": "Weighted brand purity >= 0.90 at 0.10", "actual": p["purity_multi"], "pass": p["purity_multi"] >= 0.90}]
    (OUT / "results-k.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    for t, b in res["thresholds"].items():
        print(t, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in b.items() if k != "largest"})
        for c in b["largest"][:3]:
            print("   cluster", c["size"], "pages /", c["domains"], "domains", c["brands"])
    print({c["id"]: c["pass"] for c in res["criteria"]})
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    for flag in ("--l", "--g", "--n", "--k"):
        g.add_argument(flag, action="store_true")
    a = ap.parse_args()
    return run_l() if a.l else run_g() if a.g else run_n() if a.n else run_k()


def run_g_posthoc() -> dict:
    """POST-HOC (2026-10-09): the registered (lo, hi) bands sent ~all pages to the LLM because EG2's raw
    scores are compressed (poor calibration). Variants defined on score rank / flags instead:
      band_k  : the k% of pages (A u X pooled, label-free) closest to 0.5 go to the LLM; the rest follow EG2.
      confirm : the LLM sees only pages EG2 flags; final flag = both.
    """
    df, y, _ = a_data()
    a_rec = sorted(REC.glob("battery-a-*.jsonl"))[-1]
    a = {r["file_name"]: r for r in (json.loads(l) for l in a_rec.read_text(encoding="utf-8").splitlines()[1:])}
    pa = np.array([a[k]["p"]["a3_interleaved"] for k in df["file_name"]])
    _, xs = load_x()
    px = np.load(X_EMB / "a3_interleaved-p.npy")
    pooled = np.abs(np.r_[pa, px] - 0.5)
    out = {"label": "POST-HOC", "llms": {}}
    for tag, fa, fx in (("haiku_5_5", "vlm-a-v3_h55.jsonl", "vlm-x-v3_h55.jsonl"), ("haiku_4_5", "vlm-a-v3.jsonl", "vlm-x-v3.jsonl")):
        va, vx = load_vlm_map(fa), load_vlm_map(fx)
        la = np.array([(va.get(k) or {}).get("verdict") == "phishing" for k in df["file_name"]])
        lx = np.array([(vx.get(s["key"]) or {}).get("verdict") == "phishing" for s in xs])
        rows = {}
        for k in (10, 20, 30):
            cut = np.percentile(pooled, k)
            ma, mx = np.abs(pa - 0.5) <= cut, np.abs(px - 0.5) <= cut
            fa_, fx_ = np.where(ma, la, pa >= 0.5), np.where(mx, lx, px >= 0.5)
            rows[f"band_{k}"] = (fa_, fx_, (ma.sum() + mx.sum()) / (len(pa) + len(px)))
        rows["confirm"] = ((pa >= 0.5) & la, (px >= 0.5) & lx, ((pa >= 0.5).sum() + (px >= 0.5).sum()) / (len(pa) + len(px)))
        out["llms"][tag] = {name: {"x_recall": su.wilson(int(f_x.sum()), len(f_x)),
                                   "a_fpr": su.wilson(int((f_a & (y == 0)).sum()), int((y == 0).sum())),
                                   "llm_share_all": float(share)} for name, (f_a, f_x, share) in rows.items()}
    (OUT / "POSTHOC-G.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for tag, b in out["llms"].items():
        print(tag)
        for name, s in b.items():
            print(f"  {name:8s} Xrec {s['x_recall'][0]:.3f}  Afpr {s['a_fpr'][0]:.4f}  LLM share {s['llm_share_all']:.3f}")
    return out


if __name__ == "__main__":
    if "--g-posthoc" in sys.argv:
        run_g_posthoc()
        sys.exit(0)
    sys.exit(main())
