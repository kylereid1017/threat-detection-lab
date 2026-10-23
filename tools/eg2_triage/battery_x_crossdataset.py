"""Battery X — cross-dataset generalization on Phishpedia (PLAN-addendum-VX-urls.md).

  --prepare   index the archive (screenshots + URL metadata only; HTML is never extracted),
              sample X-host / X-rand, extract the sampled screenshots
  --jev       Jev on the URL alone (Battery A contract); append-only records
  --embed     EG2 A1 / A2 / A3 embeddings for the sample (cached)
  --score     heads fit on all Battery A sites -> recall on X; results-x.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402
from battery_a_urls import EMB_DIR as A_EMB, PREFIX, host_of, jev_state, load_sample, on_shared  # noqa: E402

PP = REPO / "corpus" / "urls" / "phishpedia"
ZIP = PP / "phish_sample_30k.zip"
SHOTS = PP / "shots"
INDEX = PP / "sample.json"
EMB = PP / "eg2"
OUT_DIR = REPO / "docs" / "research" / "eg2-url-benchmark"
REC_DIR = OUT_DIR / "records"
SEED = 20261009
CAP = 600
BATCH = 16
ARMS = ["a1_url", "a2_image", "a3_interleaved"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_url(raw: str) -> str | None:
    """info.txt holds a Python dict literal (e.g. {'url': ..., 'brand': ...}); parse it without eval."""
    import ast
    import re
    try:
        d = ast.literal_eval(raw.strip())
        url = d.get("url") if isinstance(d, dict) else None
    except (ValueError, SyntaxError):
        m = re.search(r"'url':\s*'([^']+)'", raw)
        url = m.group(1) if m else None
    url = (url or "").strip()
    return url if url.lower().startswith(("http://", "https://")) else None


def prepare() -> int:
    zf = zipfile.ZipFile(ZIP)
    folders: dict[str, dict] = {}
    for zi in zf.infolist():
        parts = zi.filename.replace("\\", "/").rstrip("/").split("/")
        if len(parts) < 2:
            continue
        folder, leaf = "/".join(parts[:-1]), parts[-1].lower()
        if leaf in ("shot.png", "info.txt"):
            folders.setdefault(folder, {})[leaf] = zi.filename
    entries, seen = [], set()
    for folder in sorted(folders):
        d = folders[folder]
        if "shot.png" not in d or "info.txt" not in d:
            continue
        url = parse_url(zf.read(d["info.txt"]).decode("utf-8", "replace"))
        if not url or url in seen:
            continue
        seen.add(url)
        brand = folder.split("/")[-1].split("+")[0]
        entries.append({"folder": folder, "shot": d["shot.png"], "url": url, "brand": brand,
                        "host": host_of(url), "shared": on_shared(host_of(url))})
    rng = random.Random(SEED)
    host = [e for e in entries if e["shared"]]
    rest = [e for e in entries if not e["shared"]]
    x_host = rng.sample(host, min(CAP, len(host)))
    x_rand = rng.sample(rest, min(CAP, len(rest)))
    SHOTS.mkdir(parents=True, exist_ok=True)
    sample = []
    for subset, group in (("x_host", x_host), ("x_rand", x_rand)):
        for e in group:
            key = f"{subset}/{len(sample):04d}"
            out = SHOTS / f"{len(sample):04d}.png"
            out.write_bytes(zf.read(e["shot"]))
            sample.append({**e, "key": key, "subset": subset, "image": str(out)})
    meta = {"ts_utc": now(), "folders": len(folders), "usable_dedup": len(entries), "shared_available": len(host),
            "rest_available": len(rest), "x_host": len(x_host), "x_rand": len(x_rand), "seed": SEED}
    INDEX.write_text(json.dumps({"meta": meta, "sample": sample}, indent=1), encoding="utf-8")
    print(json.dumps(meta, indent=1))
    return 0


def load_x() -> tuple[dict, list[dict]]:
    d = json.loads(INDEX.read_text(encoding="utf-8"))
    return d["meta"], d["sample"]


def load_x_items():
    """For battery_v_vlm: (key, label, image_path, url, extra)."""
    return [(s["key"], 1, Path(s["image"]), s["url"], {"subset": s["subset"], "brand": s["brand"]}) for s in load_x()[1]]


def run_jev() -> int:
    import clients  # noqa: E402
    from run_jev import QUESTIONS  # noqa: E402
    _, sample = load_x()
    REC_DIR.mkdir(parents=True, exist_ok=True)
    f = REC_DIR / "jev-url-x.jsonl"
    done = set()
    if f.exists():
        done = {json.loads(l)["key"] for l in f.read_text(encoding="utf-8").splitlines()
                if json.loads(l).get("kind") == "observation" and not json.loads(l).get("error")}
    else:
        f.write_text(json.dumps({"kind": "run_meta", "ts_utc": now(), "model_requested": "jev-latest",
                                 "state_template": "From: (unknown)\\nSubject: (none)\\n\\n{url}"}) + "\n", encoding="utf-8")
    with f.open("a", encoding="utf-8") as fh:
        for s in sample:
            if s["key"] in done:
                continue
            rec = {"kind": "observation", "ts_utc": now(), "key": s["key"], "subset": s["subset"], "label_pred": None,
                   "confidence": None, "p_attack": None, "error": None}
            try:
                resp, el = clients.jev_system_one(jev_state(s["url"]), QUESTIONS, model="jev-latest")
                disp = resp.get("answers", {}).get("disposition", {})
                rec.update(label_pred=disp.get("choice"), confidence=disp.get("confidence"),
                           p_attack=(disp.get("probabilities") or {}).get("attack"), latency_ms=round(el * 1000, 1))
            except Exception as exc:  # noqa: BLE001
                rec["error"] = str(exc)[:400]
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
    return 0


def run_embed() -> int:
    import torch
    from sentence_transformers import SentenceTransformer
    _, sample = load_x()
    EMB.mkdir(parents=True, exist_ok=True)
    model = SentenceTransformer("google/embeddinggemma-2", config_kwargs={"audio_config": None},
                                model_kwargs={"torch_dtype": torch.float32})
    for arm in ARMS:
        path = EMB / f"{arm}.npy"
        if path.exists():
            continue
        items = []
        for s in sample:
            u = PREFIX + s["url"]
            items.append(u if arm == "a1_url" else {"text": "<|image|>" if arm == "a2_image" else f"{u} <|image|>",
                                                     "image": [s["image"]]})
        vecs, t0 = [], time.perf_counter()
        for i in range(0, len(items), BATCH):
            vecs.append(model.encode(items[i:i + BATCH], batch_size=BATCH, normalize_embeddings=True,
                                     convert_to_numpy=True, show_progress_bar=False).astype(np.float32))
            if (i // BATCH) % 10 == 0:
                print(f"[{now()}] {arm} {i + BATCH}/{len(items)} {(time.perf_counter() - t0) / (i + BATCH):.2f} s/item", flush=True)
        mat = np.vstack(vecs)
        if not np.isfinite(mat).all():
            raise SystemExit(f"ABORT: non-finite embeddings in {arm}")
        np.save(path, mat)
    return 0


def run_score() -> int:
    from sklearn.linear_model import LogisticRegression
    meta, sample = load_x()
    df = load_sample()
    y_a = (df["label_name"] == "phishing").astype(int).values
    if json.loads((A_EMB / "keys.json").read_text(encoding="utf-8")) != df["file_name"].tolist():
        raise SystemExit("ABORT: Battery A embedding order differs from sample")
    a_rec = sorted(REC_DIR.glob("battery-a-*.jsonl"))[-1]
    a_oof = {r["file_name"]: r for r in (json.loads(l) for l in a_rec.read_text(encoding="utf-8").splitlines()[1:])}
    subset = np.array([s["subset"] for s in sample])
    res = {"ts_utc": now(), "meta": meta, "a_records": a_rec.name, "arms": {}}
    for arm in ARMS:
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
        clf.fit(np.load(A_EMB / f"{arm}.npy"), y_a)
        p = clf.predict_proba(np.load(EMB / f"{arm}.npy"))[:, list(clf.classes_).index(1)]
        oof = np.array([a_oof[k]["p"][arm] for k in df["file_name"]])
        t2 = su.threshold_for_fpr(y_a, oof, 0.01)
        block = {"t2": t2}
        for sub in ("x_host", "x_rand"):
            m = subset == sub
            block[sub] = {"n": int(m.sum()),
                          "recall_t1": su.wilson(int((p[m] >= 0.5).sum()), int(m.sum())),
                          "recall_t2": su.wilson(int((p[m] >= t2).sum()), int(m.sum()))}
        res["arms"][arm] = block
        np.save(EMB / f"{arm}-p.npy", p)
    jf = REC_DIR / "jev-url-x.jsonl"
    jev = {r["key"]: r for r in (json.loads(l) for l in jf.read_text(encoding="utf-8").splitlines()[1:]) if not r.get("error")}
    jflag = np.array([(jev.get(s["key"]) or {}).get("label_pred") == "attack" for s in sample])
    res["arms"]["j_jev_url"] = {sub: {"n": int((subset == sub).sum()),
                                      "recall": su.wilson(int((jflag & (subset == sub)).sum()), int((subset == sub).sum()))}
                                for sub in ("x_host", "x_rand")}
    res["jev_missing"] = sum(1 for s in sample if s["key"] not in jev)
    p3 = np.load(EMB / "a3_interleaved-p.npy")
    brands = {}
    for s, pv_ in zip(sample, p3):
        b = brands.setdefault(s["brand"], [0, 0])
        b[0] += 1
        b[1] += int(pv_ >= 0.5)
    res["top_brands_a3_t1"] = {k: {"n": v[0], "recall": v[1] / v[0]} for k, v in sorted(brands.items(), key=lambda kv: -kv[1][0])[:10]}
    for arm, name in (("v3", "v3_vlm"), ("v3_h55", "v3_vlm_h55")):
        vx = REC_DIR / f"vlm-x-{arm}.jsonl"
        if not vx.exists():
            continue
        v = {r["key"]: r for r in (json.loads(l) for l in vx.read_text(encoding="utf-8").splitlines()[1:]) if not r.get("error")}
        vflag = np.array([(v.get(s["key"]) or {}).get("verdict") == "phishing" for s in sample])
        res["arms"][name] = {sub: {"n_scored": sum(1 for s in sample if s["subset"] == sub and s["key"] in v),
                                   "recall": su.wilson(int((vflag & (subset == sub)).sum()), int((subset == sub).sum()))}
                             for sub in ("x_host", "x_rand")}
    a3 = res["arms"]["a3_interleaved"]
    jv = res["arms"]["j_jev_url"]
    res["criteria"] = [
        {"id": "X-a", "desc": "A3 recall on X-rand at T1 >= 0.80", "actual": a3["x_rand"]["recall_t1"],
         "pass": a3["x_rand"]["recall_t1"][0] >= 0.80},
        {"id": "X-b", "desc": "A3 recall on X-host at T1 >= 0.80 (descriptive if n<50)", "actual": a3["x_host"],
         "pass": a3["x_host"]["recall_t1"][0] >= 0.80, "descriptive_only": a3["x_host"]["n"] < 50},
        {"id": "X-c", "desc": "A3 recall > Jev recall on X-rand and X-host",
         "actual": {sub: [a3[sub]["recall_t1"][0], jv[sub]["recall"][0]] for sub in ("x_host", "x_rand")},
         "pass": all(a3[sub]["recall_t1"][0] > jv[sub]["recall"][0] for sub in ("x_host", "x_rand"))},
    ]
    (OUT_DIR / "results-x.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps({c["id"]: c["pass"] for c in res["criteria"]}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    for flag in ("--prepare", "--jev", "--embed", "--score"):
        g.add_argument(flag, action="store_true")
    a = ap.parse_args()
    return prepare() if a.prepare else run_jev() if a.jev else run_embed() if a.embed else run_score()


if __name__ == "__main__":
    sys.exit(main())
