"""Battery R — robustness of the EG2 page reader to benign page changes (PLAN-addendum-LGNKR.md).

  --embed   build the 6 transforms of 100 flagged Phishpedia screenshots and embed them (A3)
  --llm     Haiku 5.5 (V3 contract) on originals + hue180 + mirror (<= 300 calls, shared $5 cap)
  --score   flip rates and score changes -> results-r.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402
from battery_a_urls import EMB_DIR as A_EMB, PREFIX, load_sample  # noqa: E402
from battery_x_crossdataset import EMB as X_EMB, load_x  # noqa: E402

PP = REPO / "corpus" / "urls" / "phishpedia" / "robust"
OUT = REPO / "docs" / "research" / "eg2-url-benchmark"
SEED = 20261009
TRANSFORMS = ["jpeg30", "half_res", "crop15", "blur2", "hue180", "mirror"]
BENIGN = ["jpeg30", "half_res", "crop15", "blur2"]
LLM_SETS = ["orig", "hue180", "mirror"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def full_a_head():
    from sklearn.linear_model import LogisticRegression
    df = load_sample()
    y = (df["label_name"] == "phishing").astype(int).values
    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    return clf.fit(np.load(A_EMB / "a3_interleaved.npy"), y)


def chosen() -> list[int]:
    p = np.load(X_EMB / "a3_interleaved-p.npy")
    flagged = [i for i in range(len(p)) if p[i] >= 0.5]
    return sorted(random.Random(SEED).sample(flagged, 100))


def transform(img, name: str):
    from PIL import Image, ImageFilter
    w, h = img.size
    if name == "jpeg30":
        import io
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=30)
        return Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    if name == "half_res":
        return img.resize((w // 2, h // 2), Image.BILINEAR).resize((w, h), Image.BILINEAR)
    if name == "crop15":
        dx, dy = int(w * 0.15), int(h * 0.15)
        return img.crop((dx, dy, w - dx, h - dy)).resize((w, h), Image.BILINEAR)
    if name == "blur2":
        return img.filter(ImageFilter.GaussianBlur(2))
    if name == "hue180":
        hsv = np.array(img.convert("HSV"))
        hsv[..., 0] = (hsv[..., 0].astype(int) + 128) % 256
        return Image.fromarray(hsv, "HSV").convert("RGB")
    if name == "mirror":
        return img.transpose(Image.FLIP_LEFT_RIGHT)
    raise ValueError(name)


def run_embed() -> int:
    import torch
    from PIL import Image
    from sentence_transformers import SentenceTransformer
    _, sample = load_x()
    idx = chosen()
    PP.mkdir(parents=True, exist_ok=True)
    (PP / "chosen.json").write_text(json.dumps(idx), encoding="utf-8")
    model = SentenceTransformer("google/embeddinggemma-2", config_kwargs={"audio_config": None},
                                model_kwargs={"torch_dtype": torch.float32})
    for name in TRANSFORMS:
        out = PP / f"{name}.npy"
        if out.exists():
            continue
        (PP / name).mkdir(exist_ok=True)
        items = []
        for i in idx:
            s = sample[i]
            path = PP / name / f"{i:04d}.png"
            if not path.exists():
                transform(Image.open(s["image"]).convert("RGB"), name).save(path)
            items.append({"text": f"{PREFIX}{s['url']} <|image|>", "image": [str(path)]})
        t0, vecs = time.perf_counter(), []
        for b in range(0, len(items), 16):
            vecs.append(model.encode(items[b:b + 16], batch_size=16, normalize_embeddings=True,
                                     convert_to_numpy=True, show_progress_bar=False).astype(np.float32))
        mat = np.vstack(vecs)
        if not np.isfinite(mat).all():
            raise SystemExit(f"ABORT: non-finite embeddings in {name}")
        np.save(out, mat)
        print(f"[{now()}] {name} done in {time.perf_counter() - t0:.0f}s", flush=True)
    return 0


def run_llm() -> int:
    import battery_v_vlm as v
    from concurrent.futures import ThreadPoolExecutor
    _, sample = load_x()
    idx = json.loads((PP / "chosen.json").read_text(encoding="utf-8"))
    model = "anthropic/claude-haiku-5.5"
    for name in LLM_SETS:
        f = v.REC_DIR / f"vlm-r-{name}.jsonl"
        done = set()
        if f.exists():
            done = {json.loads(l)["key"] for l in f.read_text(encoding="utf-8").splitlines()[1:]
                    if not json.loads(l).get("error")}
        else:
            f.write_text(json.dumps({"kind": "run_meta", "ts_utc": now(), "model": model, "set": f"r-{name}",
                                     "contract": "Battery V (as run, h55 deviations)"}) + "\n", encoding="utf-8")

        def work(i):
            key = f"r/{name}/{i:04d}"
            if key in done or v.spent() >= v.SPEND_CAP:
                return None
            img = Path(sample[i]["image"]) if name == "orig" else PP / name / f"{i:04d}.png"
            rec = {"kind": "observation", "ts_utc": now(), "key": key, "verdict": None, "p_phishing": None,
                   "cost_usd": 0.0, "error": None}
            try:
                resp, el = v.call_portal(img, sample[i]["url"], model)
                u = resp.get("usage", {})
                rec["cost_usd"] = float(u["cost"]) if u.get("cost") is not None else 0.0
                rec["served_model"] = resp.get("model")
                text = next((b["text"] for b in resp.get("content", []) if b.get("type") == "text"), None)
                if text is None:
                    rec["error"] = f"no verdict (stop_reason={resp.get('stop_reason')})"
                else:
                    d = v.parse_verdict(text)
                    rec["verdict"], rec["p_phishing"] = d["verdict"], float(d["p_phishing"])
            except Exception as exc:  # noqa: BLE001
                rec["error"] = str(exc)[:300]
            return rec

        with ThreadPoolExecutor(4) as ex:
            recs = [r for r in ex.map(work, idx) if r]
        with f.open("a", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        print(f"{name}: {len(recs)} calls, spent now ${v.spent():.3f}")
    return 0


def run_score() -> int:
    _, sample = load_x()
    idx = json.loads((PP / "chosen.json").read_text(encoding="utf-8"))
    clf = full_a_head()
    p0 = np.load(X_EMB / "a3_interleaved-p.npy")[idx]
    t2 = json.loads((OUT / "results-x.json").read_text(encoding="utf-8"))["arms"]["a3_interleaved"]["t2"]
    res = {"ts_utc": now(), "n": len(idx), "t2": t2, "eg2": {}, "llm": {}}
    for name in TRANSFORMS:
        p = clf.predict_proba(np.load(PP / f"{name}.npy"))[:, list(clf.classes_).index(1)]
        base_t2 = p0 >= t2
        res["eg2"][name] = {
            "flip_rate_t1": su.wilson(int((p < 0.5).sum()), len(p)),
            "flip_rate_t2": su.wilson(int((base_t2 & (p < t2)).sum()), int(base_t2.sum())),
            "mean_delta_p": float(np.mean(p - p0)),
        }
    import battery_v_vlm as v
    llm = {}
    for name in LLM_SETS:
        f = v.REC_DIR / f"vlm-r-{name}.jsonl"
        if f.exists():
            rows = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()[1:]]
            llm[name] = {r["key"].split("/")[-1]: r for r in rows if not r.get("error")}
    if "orig" in llm:
        base = {k for k, r in llm["orig"].items() if r["verdict"] == "phishing"}
        res["llm"]["orig_flagged"] = len(base)
        for name in ("hue180", "mirror"):
            if name in llm:
                flips = sum(1 for k in base if (llm[name].get(k) or {}).get("verdict") != "phishing")
                res["llm"][name] = {"flip_rate": su.wilson(flips, len(base))}
    res["criteria"] = [{"id": "R-a", "desc": "EG2 flip rate at 0.5 <= 10% for jpeg30, half_res, crop15, blur2",
                        "actual": {k: round(res["eg2"][k]["flip_rate_t1"][0], 3) for k in BENIGN},
                        "pass": all(res["eg2"][k]["flip_rate_t1"][0] <= 0.10 for k in BENIGN)}]
    (OUT / "results-r.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: [round(x["flip_rate_t1"][0], 3), round(x["flip_rate_t2"][0] or 0, 3), round(x["mean_delta_p"], 3)]
                      for k, x in res["eg2"].items()}, indent=1))
    print("llm", json.dumps(res["llm"], default=str), "| R-a", res["criteria"][0]["pass"])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    for flag in ("--embed", "--llm", "--score"):
        g.add_argument(flag, action="store_true")
    a = ap.parse_args()
    return run_embed() if a.embed else run_llm() if a.llm else run_score()


if __name__ == "__main__":
    sys.exit(main())
