"""Battery A — URL + screenshot re-run with per-sample records (PLAN-addendum-A-urls.md).

Phases (run in order; each is resumable):
  --jev     Jev zero-shot on the URL alone (append-only records; network only)
  --embed   EG2 embeddings for arms A1 (URL), A2 (image), A3 (interleaved), cached locally
  --score   all CV, statistics, slices, composition; writes records + results-a.json + RESULTS-A.md

Run:
  python tools/eg2_triage/battery_a_urls.py --jev
  python tools/eg2_triage/battery_a_urls.py --embed
  python tools/eg2_triage/battery_a_urls.py --score
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402

DATA_DIR = REPO / "corpus" / "urls" / "shresthsamyak"
EMB_DIR = DATA_DIR / "eg2"
OUT_DIR = REPO / "docs" / "research" / "eg2-url-benchmark"
REC_DIR = OUT_DIR / "records"
ORIGINAL_JSON = OUT_DIR / "url_multimodal_benchmark_results.json"

MODEL_ID = "google/embeddinggemma-2"
PREFIX = "task: classification | query: url: "
BATCH = 16
N_LEGIT = 672
SEED_ORIG = 42
SEED = su.SEED
JEV_T = 0.30
ARMS_EMB = ["a1_url", "a2_image", "a3_interleaved"]

SHARED_HOSTS = [
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com",
    "canva.site", "my.canva.site", "canva.com", "sharepoint.com", "1drv.ms", "onedrive.live.com",
    "azurewebsites.net", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "r2.dev",
    "vercel.app", "netlify.app", "github.io", "webflow.io", "wixsite.com", "weebly.com", "glitch.me",
    "square.site", "godaddysites.com", "blogspot.com", "typeform.com", "jotform.com", "notion.site",
    "dropbox.com", "box.com", "wetransfer.com", "linktr.ee", "flowcode.com", "qrco.de", "bit.ly",
    "tinyurl.com", "t.co", "clk.li", "2no.co", "rebrand.ly", "cutt.ly", "is.gd", "ow.ly", "s.id",
    "shorturl.at", "rb.gy", "t.ly",
]
HARDNEG_TYPES = {"login", "signup", "payment", "checkout"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_sample() -> pd.DataFrame:
    """Identical to benchmark_urls.load_dataset_records(limit_per_class=672) (PLAN A1)."""
    df = pd.read_csv(DATA_DIR / "metadata.csv")
    valid = []
    for _, row in df.iterrows():
        if pd.isna(row["url"]):
            continue
        p = DATA_DIR / row["file_name"]
        if p.exists() and p.stat().st_size > 0:
            valid.append(row)
    res = pd.DataFrame(valid)
    phish = res[res["label_name"] == "phishing"]
    legit_all = res[res["label_name"] == "legitimate"]
    legit = legit_all.sample(n=min(N_LEGIT, len(legit_all)), random_state=SEED_ORIG)
    out = pd.concat([phish, legit]).sample(frac=1.0, random_state=SEED_ORIG).reset_index(drop=True)
    if (out["label_name"] == "phishing").sum() != 336 or (out["label_name"] == "legitimate").sum() != 672:
        raise SystemExit(f"ABORT: sample counts differ from PLAN A1: {out['label_name'].value_counts().to_dict()}")
    return out


# ---------------------------------------------------------------- Jev phase

def jev_state(url: str) -> str:
    return f"From: (unknown)\nSubject: (none)\n\n{url}"


def jev_records_file() -> Path | None:
    files = sorted(REC_DIR.glob("jev-url-*.jsonl"))
    return files[-1] if files else None


def load_jev(clean_only: bool = True) -> dict[str, dict]:
    f = jev_records_file()
    out: dict[str, dict] = {}
    if f is None:
        return out
    for line in f.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r.get("kind") != "observation":
            continue
        if clean_only and r.get("error"):
            continue
        out[r["file_name"]] = r
    return out


def run_jev() -> int:
    import clients  # noqa: E402
    from run_jev import QUESTIONS  # noqa: E402

    df = load_sample()
    REC_DIR.mkdir(parents=True, exist_ok=True)
    f = jev_records_file()
    if f is None:
        run_id = "jev-url-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        f = REC_DIR / f"{run_id}.jsonl"
        f.write_text(json.dumps({
            "kind": "run_meta", "run_id": run_id, "model_requested": "jev-latest", "provider": "typesafe",
            "ts_utc": now(), "sample": "PLAN-addendum-A A1 (336 phishing / 672 legitimate)",
            "state_template": "From: (unknown)\\nSubject: (none)\\n\\n{url}", "questions": QUESTIONS,
            "note": "one row per URL; ids only (dataset file_name); append-only",
        }) + "\n", encoding="utf-8")
    done = set(load_jev(clean_only=True))
    seq = sum(1 for _ in f.open(encoding="utf-8"))
    errors = 0
    with f.open("a", encoding="utf-8") as fh:
        for _, row in df.iterrows():
            key = row["file_name"]
            if key in done:
                continue
            rec = {"kind": "observation", "run_id": f.stem, "seq": seq, "ts_utc": now(), "model": "jev-latest",
                   "file_name": key, "label_true": row["label_name"], "label_pred": None, "confidence": None,
                   "raw_answer": None, "latency_ms": None, "input_tokens": None, "output_tokens": None, "error": None}
            try:
                resp, elapsed = clients.jev_system_one(jev_state(str(row["url"]).strip()), QUESTIONS, model="jev-latest")
                ans = resp.get("answers", {})
                disp = ans.get("disposition", {})
                rec.update(label_pred=disp.get("choice"), confidence=disp.get("confidence"), raw_answer=ans,
                           latency_ms=round(elapsed * 1000, 1), model=resp.get("model", "jev-latest"),
                           input_tokens=resp.get("usage", {}).get("input_tokens"),
                           output_tokens=resp.get("usage", {}).get("output_tokens"))
            except Exception as exc:  # noqa: BLE001
                rec["error"] = str(exc)[:500]
                errors += 1
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            seq += 1
            if seq % 50 == 0:
                print(f"[{now()}] {seq} rows, errors={errors}", flush=True)
            if errors >= 25:
                print("STOP: 25 errors; re-run --jev to resume")
                return 2
    print(f"jev done -> {f} (errors this pass: {errors})")
    return 0


# ---------------------------------------------------------------- embed phase

def run_embed() -> int:
    import torch
    from sentence_transformers import SentenceTransformer

    df = load_sample()
    EMB_DIR.mkdir(parents=True, exist_ok=True)
    keys = df["file_name"].tolist()
    (EMB_DIR / "keys.json").write_text(json.dumps(keys), encoding="utf-8")
    model = SentenceTransformer(MODEL_ID, config_kwargs={"audio_config": None},
                                model_kwargs={"torch_dtype": torch.float32})
    dtypes = {str(p.dtype) for p in model.parameters()}
    if dtypes - {"torch.float32", "torch.bfloat16"}:
        raise SystemExit(f"ABORT: dtype {dtypes}")
    log = (EMB_DIR / "embed-log.jsonl").open("a", encoding="utf-8")
    for arm in ARMS_EMB:
        path = EMB_DIR / f"{arm}.npy"
        if path.exists():
            continue
        items = []
        for _, row in df.iterrows():
            url_text = PREFIX + str(row["url"]).strip()
            img = str((DATA_DIR / row["file_name"]).resolve())
            if arm == "a1_url":
                items.append(url_text)
            elif arm == "a2_image":
                items.append({"text": "<|image|>", "image": [img]})
            else:
                items.append({"text": f"{url_text} <|image|>", "image": [img]})
        vecs, ms = [], []
        t0 = time.perf_counter()
        for i in range(0, len(items), BATCH):
            b = items[i:i + BATCH]
            t = time.perf_counter()
            v = model.encode(b, batch_size=len(b), normalize_embeddings=True,
                             convert_to_numpy=True, show_progress_bar=False)
            ms.extend([(time.perf_counter() - t) * 1000 / len(b)] * len(b))
            vecs.append(v.astype(np.float32))
            if (i // BATCH) % 10 == 0:
                print(f"[{now()}] {arm} {i + len(b)}/{len(items)} {np.mean(ms):.0f} ms/item", flush=True)
        mat = np.vstack(vecs)
        if not np.isfinite(mat).all():
            raise SystemExit(f"ABORT: non-finite embeddings in {arm}")
        np.save(path, mat)
        np.save(EMB_DIR / f"{arm}-ms.npy", np.array(ms, dtype=np.float32))
        log.write(json.dumps({"ts_utc": now(), "arm": arm, "rows": len(items), "ms_p50": float(np.median(ms)),
                              "wall_s": round(time.perf_counter() - t0, 1)}) + "\n")
        log.flush()
    return 0


# ---------------------------------------------------------------- score phase

def lr():
    from sklearn.linear_model import LogisticRegression
    return LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=SEED_ORIG)


def oof(X: np.ndarray, y: np.ndarray, splits, scale: bool = False) -> tuple[np.ndarray, np.ndarray]:
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    p = np.zeros(len(y))
    fold = np.zeros(len(y), dtype=int)
    for k, (tr, te) in enumerate(splits):
        clf = make_pipeline(StandardScaler(), lr()) if scale else lr()
        clf.fit(X[tr], y[tr])
        p[te] = clf.predict_proba(X[te])[:, list(clf.classes_).index(1)]
        fold[te] = k
    return p, fold


def host_of(url: str) -> str:
    try:
        return (urlparse(str(url).strip()).hostname or "").lower()
    except ValueError:
        return ""


def on_shared(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in SHARED_HOSTS)


def arm_summary(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> dict:
    flag = p >= thr
    out = su.binary_counts(y, flag)
    out.update(su.auc_with_ci(y, p))
    out["tpr_at_fpr_1pct"] = su.tpr_at_fpr(y, p, 0.01)
    out["tpr_at_fpr_0"] = su.tpr_at_fpr(y, p, 0.0)
    out["brier"] = su.brier(y, p)
    out["ece10"] = su.ece_equal_mass(y, p)
    return out


def run_score() -> int:
    from scipy.stats import spearmanr
    from sklearn.metrics import confusion_matrix
    from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

    df = load_sample()
    keys = json.loads((EMB_DIR / "keys.json").read_text(encoding="utf-8"))
    if keys != df["file_name"].tolist():
        raise SystemExit("ABORT: embedding key order differs from sample")
    y = (df["label_name"] == "phishing").astype(int).values
    X = {a: np.load(EMB_DIR / f"{a}.npy") for a in ARMS_EMB}
    X["a4_concat"] = np.hstack([X["a1_url"], X["a2_image"]])
    meta_a = np.log(df["file_size_bytes"].astype(float).values)[:, None]
    meta_b = np.column_stack([
        np.log(df["file_size_bytes"].astype(float).values),
        df["redirect_count"].fillna(0).astype(float).values,
        np.log1p(df["page_load_time_ms"].fillna(0).astype(float).values),
    ])
    groups = (df["file_name"].str.split("/").str[0] + "/" + df["file_name"].str.split("/").str[1]).values

    # CV-R reproduction (PLAN A3)
    cv_r = list(StratifiedKFold(5, shuffle=True, random_state=SEED_ORIG).split(X["a1_url"], y))
    orig = {r["arm"].split(":")[0]: r for r in json.loads(ORIGINAL_JSON.read_text(encoding="utf-8"))}
    repro = {}
    for a, name in zip(ARMS_EMB, ["Arm 1", "Arm 2", "Arm 3"]):
        p, _ = oof(X[a], y, cv_r)
        tn, fp, fn, tp = confusion_matrix(y, (p >= 0.5).astype(int)).ravel()
        o = orig[name]
        repro[a] = {"now": [int(tn), int(fp), int(fn), int(tp)], "committed": [o["tn"], o["fp"], o["fn"], o["tp"]]}
        repro[a]["match"] = repro[a]["now"] == repro[a]["committed"]

    # CV-G primary (PLAN A3)
    cv_g = list(StratifiedGroupKFold(5, shuffle=True, random_state=SEED).split(X["a1_url"], y, groups))
    P, F = {}, {}
    for a in ["a1_url", "a2_image", "a3_interleaved", "a4_concat"]:
        P[a], F[a] = oof(X[a], y, cv_g)
    P["a5_scoreavg"] = (P["a1_url"] + P["a2_image"]) / 2
    P["a0a_filesize"], _ = oof(meta_a, y, cv_g, scale=True)
    P["a0b_capture_meta"], _ = oof(meta_b, y, cv_g, scale=True)

    jev = load_jev()
    missing = [k for k in keys if k not in jev]
    jev_p = np.array([float(((jev.get(k) or {}).get("raw_answer") or {}).get("disposition", {})
                            .get("probabilities", {}).get("attack", 0.0)) for k in keys])
    jev_lab = np.array([(jev.get(k) or {}).get("label_pred") for k in keys])
    jev_conf = np.array([float((jev.get(k) or {}).get("confidence") or 0.0) for k in keys])
    P["j_jev_url"] = jev_p

    arms = {a: arm_summary(y, P[a]) for a in P if a != "j_jev_url"}
    jev_flag = jev_lab == "attack"
    arms["j_jev_url"] = su.binary_counts(y, jev_flag)
    arms["j_jev_url"].update(su.auc_with_ci(y, jev_p))
    arms["j_jev_url"]["argmax_counts"] = pd.Series(jev_lab).value_counts(dropna=False).to_dict()

    # Paired tests (PLAN A4)
    def correct(p):
        return (p >= 0.5).astype(int) == y

    pos, neg = y == 1, y == 0
    pairs = [("a3_interleaved", "a1_url"), ("a3_interleaved", "a2_image"),
             ("a3_interleaved", "a4_concat"), ("a2_image", "a1_url")]
    paired = {}
    for a, b in pairs:
        ca, cb = correct(P[a]), correct(P[b])
        paired[f"{a}_vs_{b}"] = {
            "positives": su.mcnemar_exact(ca[pos], cb[pos]),
            "negatives": su.mcnemar_exact(ca[neg], cb[neg]),
            "bootstrap": su.paired_bootstrap_auc(y, P[a], P[b]),
        }

    # Complementarity (PLAN A4)
    m1, m2 = ~correct(P["a1_url"]), ~correct(P["a2_image"])
    overlap = {
        "positives": {"url_miss": int((m1 & pos).sum()), "image_miss": int((m2 & pos).sum()),
                      "both_miss": int((m1 & m2 & pos).sum()),
                      "url_miss_image_caught": int((m1 & ~m2 & pos).sum()),
                      "image_miss_url_caught": int((m2 & ~m1 & pos).sum())},
        "negatives": {"url_fp": int((m1 & neg).sum()), "image_fp": int((m2 & neg).sum()),
                      "both_fp": int((m1 & m2 & neg).sum())},
        "spearman_within_pos": float(spearmanr(P["a1_url"][pos], P["a2_image"][pos])[0]),
        "spearman_within_neg": float(spearmanr(P["a1_url"][neg], P["a2_image"][neg])[0]),
        "oracle_or_recall": float(((~m1 | ~m2) & pos).sum() / pos.sum()),
    }

    # Slices (PLAN A5)
    hosts = df["url"].map(host_of).values
    shared = np.array([on_shared(h) for h in hosts])
    hardneg = neg & df["page_type"].isin(HARDNEG_TYPES).values
    slices = {"s_host": {"n_pos": int((shared & pos).sum()), "n_neg": int((shared & neg).sum()), "arms": {}},
              "s_hardneg": {"n_neg": int(hardneg.sum()), "arms": {}}}
    for a in ["a1_url", "a2_image", "a3_interleaved", "a4_concat", "j_jev_url"]:
        flag = jev_flag if a == "j_jev_url" else P[a] >= 0.5
        slices["s_host"]["arms"][a] = {"recall": su.wilson(int((flag & shared & pos).sum()), int((shared & pos).sum())),
                                       "fpr": su.wilson(int((flag & shared & neg).sum()), int((shared & neg).sum()))}
        slices["s_hardneg"]["arms"][a] = {"fpr": su.wilson(int((flag & hardneg).sum()), int(hardneg.sum()))}

    # Composition (PLAN A6)
    a3_flag = P["a3_interleaved"] >= 0.5
    jev_conf_safe = (jev_lab == "safe") & (jev_conf >= JEV_T)
    render = ~jev_conf_safe
    gate_flag = render & a3_flag
    comp = {
        "J": su.binary_counts(y, jev_flag),
        "A3": su.binary_counts(y, a3_flag),
        "J_and_A3": su.binary_counts(y, jev_flag & a3_flag),
        "J_or_A3": su.binary_counts(y, jev_flag | a3_flag),
        "render_gate": {**su.binary_counts(y, gate_flag), "render_share": float(render.mean()),
                        "phish_delivered_without_render": int((jev_conf_safe & pos).sum())},
    }
    # A-f: A3 recall at an FPR <= Jev's FPR
    jev_fpr = comp["J"]["fpr"][0]
    a3_at_jev_fpr = su.tpr_at_fpr(y, P["a3_interleaved"], jev_fpr)

    crit = [
        {"id": "A-a", "desc": "CV-R reproduction matches committed confusion matrices",
         "actual": {a: repro[a]["now"] for a in repro}, "pass": all(r["match"] for r in repro.values())},
        {"id": "A-b", "desc": "A3 fewer FPs than A1 (McNemar exact p<0.05)",
         "actual": paired["a3_interleaved_vs_a1_url"]["negatives"],
         "pass": paired["a3_interleaved_vs_a1_url"]["negatives"]["p_exact"] < 0.05
         and arms["a3_interleaved"]["fp"] < arms["a1_url"]["fp"]},
        {"id": "A-c", "desc": "A3 beats A2 on FPs or misses (McNemar exact p<0.05)",
         "actual": {k: paired["a3_interleaved_vs_a2_image"][k] for k in ("positives", "negatives")},
         "pass": any(paired["a3_interleaved_vs_a2_image"][k]["p_exact"] < 0.05
                     and paired["a3_interleaved_vs_a2_image"][k]["a_only_right"] > paired["a3_interleaved_vs_a2_image"][k]["b_only_right"]
                     for k in ("positives", "negatives"))},
        {"id": "A-d", "desc": "A3 PR-AUC > A4 late fusion (bootstrap CI excludes 0)",
         "actual": paired["a3_interleaved_vs_a4_concat"]["bootstrap"],
         "pass": paired["a3_interleaved_vs_a4_concat"]["bootstrap"]["d_pr_auc_ci"][0] > 0},
        {"id": "A-e", "desc": "Confound probe A0a ROC-AUC < 0.75",
         "actual": arms["a0a_filesize"]["roc_auc"], "pass": arms["a0a_filesize"]["roc_auc"] < 0.75},
        {"id": "A-f", "desc": "A3 recall > Jev-on-URL recall at FPR <= Jev's FPR",
         "actual": {"a3": a3_at_jev_fpr, "jev_recall": comp["J"]["recall"][0], "jev_fpr": jev_fpr},
         "pass": a3_at_jev_fpr["tpr"] > comp["J"]["recall"][0]},
    ]

    run_id = "battery-a-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    REC_DIR.mkdir(parents=True, exist_ok=True)
    with (REC_DIR / f"{run_id}.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": "run_meta", "run_id": run_id, "ts_utc": now(), "cv": "CV-G",
                             "plan": "tools/eg2_triage/PLAN-addendum-A-urls.md"}) + "\n")
        for i, k in enumerate(keys):
            fh.write(json.dumps({"kind": "observation", "file_name": k, "label_true": int(y[i]),
                                 "fold_g": int(F["a1_url"][i]),
                                 "p": {a: round(float(P[a][i]), 5) for a in P},
                                 "jev_label": jev_lab[i], "jev_conf": float(jev_conf[i])}) + "\n")
    summary = {"run_id": run_id, "ts_utc": now(), "n": len(y), "n_pos": int(pos.sum()), "n_neg": int(neg.sum()),
               "jev_missing": len(missing), "criteria": crit, "reproduction": repro, "arms": arms,
               "paired": paired, "overlap": overlap, "slices": slices, "composition": comp,
               "embed_latency_ms_p50": {a: float(np.median(np.load(EMB_DIR / f"{a}-ms.npy"))) for a in ARMS_EMB}}
    (OUT_DIR / "results-a.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps({c["id"]: c["pass"] for c in crit}, indent=1))
    print(f"wrote {OUT_DIR / 'results-a.json'} and records/{run_id}.jsonl")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--jev", action="store_true")
    g.add_argument("--embed", action="store_true")
    g.add_argument("--score", action="store_true")
    a = ap.parse_args()
    if a.jev:
        return run_jev()
    if a.embed:
        return run_embed()
    return run_score()


if __name__ == "__main__":
    sys.exit(main())
