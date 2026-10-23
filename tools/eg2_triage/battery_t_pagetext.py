"""Battery T — does page text close the gap? (PLAN-addendum-T-pagetext.md)

  --ocr     Windows OCR on every A + X screenshot -> records/ocr-a.jsonl, ocr-x.jsonl
  --jev     Jev on J1 (link + page text) and J2 (page text only), A + X -> records/jev-t-*.jsonl
  --embed   EG2 text embedding for E1t (url + page text), A + X -> corpus .../t/
  --score   recall / FPR per arm, paired tests, criteria -> results-t.json

Run in order; each phase is resumable (append-only records / cached embeddings).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402
from battery_a_urls import (DATA_DIR, EMB_DIR as A_EMB, HARDNEG_TYPES, PREFIX, load_sample,  # noqa: E402
                            load_jev as load_jev_a)
from battery_x_crossdataset import EMB as X_EMB, load_x  # noqa: E402

OUT = REPO / "docs" / "research" / "eg2-url-benchmark"
REC = OUT / "records"
T_EMB = REPO / "corpus" / "urls" / "t_pagetext"
OCR_PS1 = REPO / "tools" / "eg2_triage" / "winocr.ps1"
MODEL_ID = "google/embeddinggemma-2"
MAXCHARS = 2000
BATCH = 16


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- image inventory

def a_items() -> list[tuple[str, int, str]]:
    """(key=file_name, label phishing=1, absolute image path) for the A sample."""
    df = load_sample()
    return [(r["file_name"], int(r["label_name"] == "phishing"), str((DATA_DIR / r["file_name"]).resolve()))
            for _, r in df.iterrows()]


def a_url() -> dict[str, str]:
    df = load_sample()
    return {r["file_name"]: str(r["url"]).strip() for _, r in df.iterrows()}


def x_items() -> list[tuple[str, int, str]]:
    _, sample = load_x()
    return [(s["key"], 1, str(Path(s["image"]).resolve())) for s in sample]


def x_url() -> dict[str, str]:
    _, sample = load_x()
    return {s["key"]: s["url"] for s in sample}


# ---------------------------------------------------------------- OCR phase

def run_ocr() -> int:
    REC.mkdir(parents=True, exist_ok=True)
    for name, items in (("a", a_items()), ("x", x_items())):
        out = REC / f"ocr-{name}.jsonl"
        done = set()
        if out.exists():
            done = {json.loads(l)["path"] for l in out.read_text(encoding="utf-8").splitlines() if l.strip()}
        todo = [p for _, _, p in items if p not in done]
        if not todo:
            print(f"ocr-{name}: all {len(items)} done")
            continue
        listf = T_EMB / f"ocr-list-{name}.txt"
        T_EMB.mkdir(parents=True, exist_ok=True)
        listf.write_text("\n".join(todo), encoding="ascii")
        print(f"[{now()}] ocr-{name}: {len(todo)} images -> {out}", flush=True)
        t0 = time.time()
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(OCR_PS1),
                            "-List", str(listf), "-Out", str(out)], capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-2000:])
            raise SystemExit(f"ocr-{name} failed rc={r.returncode}")
        print(f"[{now()}] ocr-{name} done in {time.time() - t0:.0f}s", flush=True)
    return 0


def load_ocr(name: str) -> dict[str, str]:
    """path -> text (first MAXCHARS chars); empty string on error or no text."""
    out = REC / f"ocr-{name}.jsonl"
    m = {}
    for l in out.read_text(encoding="utf-8").splitlines():
        if not l.strip():
            continue
        r = json.loads(l)
        m[r["path"]] = (r.get("text") or "")[:MAXCHARS] if not r.get("error") else ""
    return m


def text_for(items, ocr) -> dict[str, str]:
    return {k: ocr.get(p, "") for k, _, p in items}


# ---------------------------------------------------------------- Jev phase

def j1_state(url: str, text: str) -> str:
    body = text if text else "(no text found)"
    return (f"From: (unknown)\nSubject: (none)\n\n{url}\n\n"
            f"[Text visible on the page at that link, read from a screenshot]\n{body}")


def j2_state(text: str) -> str:
    body = text if text else "(no text found)"
    return f"From: (unknown)\nSubject: (none)\n\n[Text visible on a linked web page, read from a screenshot]\n{body}"


def run_jev() -> int:
    import clients  # noqa: E402
    from run_jev import QUESTIONS  # noqa: E402
    for name, items, urls in (("a", a_items(), a_url()), ("x", x_items(), x_url())):
        ocr = text_for(items, load_ocr(name))
        for arm, mk in (("j1", lambda u, t: j1_state(u, t)), ("j2", lambda u, t: j2_state(t))):
            f = REC / f"jev-t-{arm}-{name}.jsonl"
            done = set()
            if f.exists():
                done = {json.loads(l)["key"] for l in f.read_text(encoding="utf-8").splitlines()[1:]
                        if not json.loads(l).get("error")}
            else:
                f.write_text(json.dumps({"kind": "run_meta", "ts_utc": now(), "model": "jev-latest",
                                         "arm": arm, "set": name, "plan": "PLAN-addendum-T-pagetext.md"}) + "\n",
                             encoding="utf-8")
            errors = 0
            with f.open("a", encoding="utf-8") as fh:
                for key, label, _ in items:
                    if key in done:
                        continue
                    state = mk(urls[key], ocr[key])
                    rec = {"kind": "observation", "ts_utc": now(), "key": key, "label_true": label,
                           "label_pred": None, "confidence": None, "error": None}
                    try:
                        resp, el = clients.jev_system_one(state, QUESTIONS, model="jev-latest")
                        disp = resp.get("answers", {}).get("disposition", {})
                        rec.update(label_pred=disp.get("choice"), confidence=disp.get("confidence"),
                                   latency_ms=round(el * 1000, 1))
                    except Exception as exc:  # noqa: BLE001
                        rec["error"] = str(exc)[:300]
                        errors += 1
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    fh.flush()
                    if errors >= 25:
                        print(f"STOP {arm}-{name}: 25 errors; re-run --jev to resume")
                        return 2
            print(f"jev-t {arm}-{name} done (errors {errors})", flush=True)
    return 0


def load_jev_t(arm: str, name: str) -> dict[str, str]:
    f = REC / f"jev-t-{arm}-{name}.jsonl"
    return {r["key"]: r["label_pred"] for r in (json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()[1:])
            if not r.get("error")}


# ---------------------------------------------------------------- embed phase (E1t)

def run_embed() -> int:
    import torch
    from sentence_transformers import SentenceTransformer
    T_EMB.mkdir(parents=True, exist_ok=True)
    model = None
    for name, items, urls in (("a", a_items(), a_url()), ("x", x_items(), x_url())):
        out = T_EMB / f"e1t-{name}.npy"
        keysf = T_EMB / f"e1t-{name}-keys.json"
        if out.exists():
            continue
        ocr = text_for(items, load_ocr(name))
        if model is None:
            model = SentenceTransformer(MODEL_ID, config_kwargs={"audio_config": None},
                                        model_kwargs={"torch_dtype": torch.float32})
        texts = [f"{PREFIX}{urls[k]} | page text: {ocr[k]}" for k, _, _ in items]
        vecs = []
        for i in range(0, len(texts), BATCH):
            vecs.append(model.encode(texts[i:i + BATCH], batch_size=BATCH, normalize_embeddings=True,
                                     convert_to_numpy=True, show_progress_bar=False).astype(np.float32))
            if (i // BATCH) % 20 == 0:
                print(f"[{now()}] e1t-{name} {i}/{len(texts)}", flush=True)
        mat = np.vstack(vecs)
        if not np.isfinite(mat).all():
            raise SystemExit(f"ABORT: non-finite e1t-{name}")
        np.save(out, mat)
        keysf.write_text(json.dumps([k for k, _, _ in items]), encoding="utf-8")
    return 0


# ---------------------------------------------------------------- score phase

def lr():
    from sklearn.linear_model import LogisticRegression
    return LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)


def rate(flags) -> list:
    flags = list(flags)
    return su.wilson(int(sum(flags)), len(flags)) if flags else [None, None, None]


def run_score() -> int:
    from sklearn.model_selection import StratifiedGroupKFold
    a_it, x_it = a_items(), x_items()
    ocr_a, ocr_x = text_for(a_it, load_ocr("a")), text_for(x_it, load_ocr("x"))
    df = load_sample()
    y_a = (df["label_name"] == "phishing").astype(int).values
    a_keys = [r["file_name"] for _, r in df.iterrows()]
    groups = [k.split("/")[1] if "/" in k else k for k in a_keys]
    a_legit = [k for k, lab, _ in a_it if lab == 0]
    hard = {r["file_name"] for _, r in df.iterrows()
            if r["label_name"] == "legitimate" and any(t in r["file_name"] for t in HARDNEG_TYPES)}
    x_sub = {s["key"]: s["subset"] for s in load_x()[1]}
    xh = [k for k, _, _ in x_it if x_sub[k] == "x_host"]
    xr = [k for k, _, _ in x_it if x_sub[k] == "x_rand"]

    res = {"ts_utc": now(), "maxchars": MAXCHARS, "arms": {}, "ocr": {}, "deviations": []}
    for name, items, ocr in (("a", a_it, ocr_a), ("x", x_it, ocr_x)):
        empt = [1 for k, _, _ in items if not ocr[k]]
        res["ocr"][name] = {"n": len(items), "empty": len(empt),
                            "empty_rate": round(len(empt) / len(items), 4)}

    # Jev arms J0/J1/J2. J0 for A = the timestamped Battery-A Jev file (keyed by file_name);
    # the X file (jev-url-x.jsonl, keyed by "key") must not be picked up here.
    a_jev_files = sorted(f for f in REC.glob("jev-url-*.jsonl") if "-x" not in f.stem)
    j0a = {}
    for l in a_jev_files[-1].read_text(encoding="utf-8").splitlines():
        r = json.loads(l)
        if r.get("kind") == "observation" and not r.get("error"):
            j0a[r["file_name"]] = r["label_pred"]
    jx0 = {r["key"]: r["label_pred"] for r in
           (json.loads(l) for l in (REC / "jev-url-x.jsonl").read_text(encoding="utf-8").splitlines())
           if r.get("kind") == "observation" and not r.get("error")}
    jev = {"J0": {"a": j0a, "x": jx0},
           "J1": {"a": load_jev_t("j1", "a"), "x": load_jev_t("j1", "x")},
           "J2": {"a": load_jev_t("j2", "a"), "x": load_jev_t("j2", "x")}}

    def jflag(d, keys):
        return [d.get(k) == "attack" for k in keys]

    for arm in ("J0", "J1", "J2"):
        da, dx = jev[arm]["a"], jev[arm]["x"]
        res["arms"][arm] = {
            "x_host_recall": rate(jflag(dx, xh)), "x_rand_recall": rate(jflag(dx, xr)),
            "a_legit_fpr": rate(jflag(da, a_legit)),
            "a_hardneg_fpr": rate(jflag(da, [k for k in a_legit if k in hard])),
            "label_mix_x": {lab: sum(dx.get(k) == lab for k in x_sub) for lab in ("safe", "gray", "spam", "attack")},
        }

    # EG2 arms: E3 (screenshot, existing) and E1t (url+text)
    a_rec = sorted(REC.glob("battery-a-*.jsonl"))[-1]
    a_oof = {r["file_name"]: r for r in
             (json.loads(l) for l in a_rec.read_text(encoding="utf-8").splitlines()[1:])}
    e3_x = np.load(X_EMB / "a3_interleaved-p.npy")
    x_key_order = [s["key"] for s in load_x()[1]]
    e3_xmap = dict(zip(x_key_order, e3_x))
    # E3 X recall at 0.5
    res["arms"]["E3"] = {"x_host_recall": rate([e3_xmap[k] >= 0.5 for k in xh]),
                         "x_rand_recall": rate([e3_xmap[k] >= 0.5 for k in xr])}
    # E1t: CV-G OOF on A for threshold, full-A head on X
    Xa = np.load(T_EMB / "e1t-a.npy"); Xx = np.load(T_EMB / "e1t-x.npy")
    assert json.loads((T_EMB / "e1t-a-keys.json").read_text()) == a_keys
    skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    oof = np.zeros(len(y_a))
    for tr, te in skf.split(Xa, y_a, groups):
        oof[te] = lr().fit(Xa[tr], y_a[tr]).predict_proba(Xa[te])[:, list(lr().fit(Xa[tr], y_a[tr]).classes_).index(1)]
    t2 = su.threshold_for_fpr(y_a, oof, 0.01)
    clf = lr().fit(Xa, y_a)
    px = clf.predict_proba(Xx)[:, list(clf.classes_).index(1)]
    e1t_x = dict(zip([k for k, _, _ in x_it], px))
    e1t_oof = dict(zip(a_keys, oof))
    res["arms"]["E1t"] = {
        "x_host_recall_t1": rate([e1t_x[k] >= 0.5 for k in xh]),
        "x_rand_recall_t1": rate([e1t_x[k] >= 0.5 for k in xr]),
        "x_host_recall_t2": rate([e1t_x[k] >= t2 for k in xh]),
        "a_legit_fpr_t1": rate([e1t_oof[k] >= 0.5 for k in a_legit]),
        "t2": float(t2),
        "roc_auc": su.auc_with_ci(y_a, oof)["roc_auc"],
    }

    # Paired McNemar: J1 vs J0 on correctness. X-host: correct = flagged (all phishing).
    # A-legit: correct = NOT flagged. mcnemar_exact(correct_j1, correct_j0).
    import numpy as _np
    corr_j1_xh = _np.array([jev["J1"]["x"].get(k) == "attack" for k in xh])
    corr_j0_xh = _np.array([jev["J0"]["x"].get(k) == "attack" for k in xh])
    corr_j1_al = _np.array([jev["J1"]["a"].get(k) != "attack" for k in a_legit])
    corr_j0_al = _np.array([jev["J0"]["a"].get(k) != "attack" for k in a_legit])
    res["paired"] = {"j1_vs_j0_xhost_correctness": su.mcnemar_exact(corr_j1_xh, corr_j0_xh),
                     "j1_vs_j0_alegit_correctness": su.mcnemar_exact(corr_j1_al, corr_j0_al)}

    j1h = res["arms"]["J1"]["x_host_recall"][0]
    j0h = res["arms"]["J0"]["x_host_recall"][0]
    e3h = res["arms"]["E3"]["x_host_recall"][0]
    e1th = res["arms"]["E1t"]["x_host_recall_t1"][0]
    res["criteria"] = [
        {"id": "T-a", "desc": "J1 X-host recall >= J0 X-host recall + 0.20",
         "actual": {"j1": j1h, "j0": j0h, "delta": round(j1h - j0h, 3)}, "pass": j1h >= j0h + 0.20},
        {"id": "T-b", "desc": "J1 X-host recall >= 0.90", "actual": j1h, "pass": j1h >= 0.90},
        {"id": "T-c", "desc": "J1 A-legit FPR <= J0 A-legit FPR",
         "actual": {"j1": res["arms"]["J1"]["a_legit_fpr"][0], "j0": res["arms"]["J0"]["a_legit_fpr"][0]},
         "pass": res["arms"]["J1"]["a_legit_fpr"][0] <= res["arms"]["J0"]["a_legit_fpr"][0]},
        {"id": "T-d", "desc": "E1t X-host recall T1 >= E3 X-host recall T1 - 0.05",
         "actual": {"e1t": e1th, "e3": e3h}, "pass": e1th >= e3h - 0.05},
    ]
    (OUT / "results-t.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"ocr": res["ocr"], "criteria": [(c["id"], c["pass"]) for c in res["criteria"]],
                      "J": {a: res["arms"][a] for a in ("J0", "J1", "J2")},
                      "E1t": res["arms"]["E1t"], "E3": res["arms"]["E3"]}, indent=1, default=str))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    for flag in ("ocr", "jev", "embed", "score"):
        g.add_argument(f"--{flag}", action="store_true")
    a = ap.parse_args()
    if a.ocr:
        return run_ocr()
    if a.jev:
        return run_jev()
    if a.embed:
        return run_embed()
    return run_score()


if __name__ == "__main__":
    raise SystemExit(main())
