"""Battery Q — analyst questions answered by the page (PLAN-addendum-Q-questions.md)

  --eg2     EG2 zero-shot cosine for the 5 phrasal questions, A-legit + X -> records/q-eg2-*.npy
  --jev     Jev noul on the 7 questions over page text (needs Battery T OCR) -> records/q-jev-*.jsonl
  --llm     Haiku 5.5 answers the 7 questions from the screenshot -> records/q-h-*.jsonl  [needs proxy]
  --score   per-question rates, rule R1, agreement, explanation coverage, criteria -> results-q.json

EG2 and Jev run offline / on TypeSafe; only --llm needs the Haiku proxy.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402
from battery_a_urls import EMB_DIR as A_EMB, HARDNEG_TYPES, load_sample  # noqa: E402
from battery_x_crossdataset import EMB as X_EMB, load_x  # noqa: E402
from battery_t_pagetext import a_items, a_url, j1_state, load_ocr, text_for, x_items, x_url  # noqa: E402

OUT = REPO / "docs" / "research" / "eg2-url-benchmark"
REC = OUT / "records"
MODEL_ID = "google/embeddinggemma-2"
H55 = "anthropic/claude-haiku-5.5"

QUESTIONS = {
    "login_form": "Does the page show a login or sign-in form (fields for a username, email, phone number or password)?",
    "asks_secrets": "Does the page ask the visitor to enter a password, payment card, bank details, or identity details?",
    "brand_shown": "Does the page display the name or logo of a well-known company or service?",
    "brand_domain_mismatch": "Does a brand shown on the page belong to a different organization than the one that owns the URL's domain?",
    "file_share_lure": "Does the page invite the visitor to view, download or unlock a shared document, file, invoice, fax or voicemail?",
    "urgency_or_threat": "Does the page pressure the visitor with urgency, threats, or account problems (suspended, locked, expiring, verify now)?",
    "dead_or_parked": "Is the page blank, an error, a parked or for-sale domain, or a hosting placeholder?",
}
BOOL_KEYS = [k for k in QUESTIONS if k != "brand_shown"]
EG2_PHRASES = {
    "login_form": "a web page with a login form asking for a username and password",
    "asks_secrets": "a web page asking for a password, credit card or bank details",
    "file_share_lure": "a web page offering to view or download a shared document or file",
    "urgency_or_threat": "a web page warning that an account is suspended or must be verified urgently",
    "dead_or_parked": "a blank, error or parked domain web page",
}
SEED = 20261009


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def a_legit_items():
    return [(k, lab, p) for k, lab, p in a_items() if lab == 0]


# ---------------------------------------------------------------- EG2 arm (offline)

def run_eg2() -> int:
    a_keys = json.loads((A_EMB / "keys.json").read_text(encoding="utf-8"))
    df = load_sample()
    legit_mask = (df["label_name"] == "legitimate").values
    Xa = np.load(A_EMB / "a2_image.npy")[legit_mask]
    a_legit_keys = [k for k, m in zip(a_keys, legit_mask) if m]
    Xx = np.load(X_EMB / "a2_image.npy")
    x_keys = [s["key"] for s in load_x()[1]]

    import torch
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer(MODEL_ID, config_kwargs={"audio_config": None},
                               model_kwargs={"torch_dtype": torch.float32})
    qk = list(EG2_PHRASES)
    Q = model.encode([f"task: search result | query: {EG2_PHRASES[k]}" for k in qk],
                     normalize_embeddings=True, convert_to_numpy=True).astype(np.float32)
    out = {"ts_utc": now(), "questions": qk,
           "a_legit": {"keys": a_legit_keys, "scores": (Xa @ Q.T).tolist()},
           "x": {"keys": x_keys, "scores": (Xx @ Q.T).tolist()}}
    (REC / "q-eg2.json").write_text(json.dumps(out), encoding="utf-8")
    print(f"q-eg2: {len(a_legit_keys)} A-legit, {len(x_keys)} X, {len(qk)} phrases")
    return 0


# ---------------------------------------------------------------- Jev arm (TypeSafe)

def run_jev() -> int:
    import clients  # noqa: E402
    jev_q = {k: {"type": "noul", "instructions": v} for k, v in QUESTIONS.items() if k != "brand_shown"}
    for name, items, urls in (("a", a_legit_items(), a_url()), ("x", x_items(), x_url())):
        ocr = text_for(items, load_ocr(name))
        f = REC / f"q-jev-{name}.jsonl"
        done = set()
        if f.exists():
            done = {json.loads(l)["key"] for l in f.read_text(encoding="utf-8").splitlines()[1:]
                    if not json.loads(l).get("error")}
        else:
            f.write_text(json.dumps({"kind": "run_meta", "ts_utc": now(), "model": "jev-latest", "set": name,
                                     "questions": list(jev_q), "plan": "PLAN-addendum-Q-questions.md"}) + "\n",
                         encoding="utf-8")
        errors = 0
        with f.open("a", encoding="utf-8") as fh:
            for key, label, _ in items:
                if key in done:
                    continue
                state = j1_state(urls[key], ocr[key])
                rec = {"kind": "observation", "ts_utc": now(), "key": key, "label_true": label,
                       "answers": None, "error": None}
                try:
                    resp, el = clients.jev_system_one(state, jev_q, model="jev-latest")
                    ans = resp.get("answers", {})
                    rec["answers"] = {k: (ans.get(k) or {}).get("noul") for k in jev_q}
                except Exception as exc:  # noqa: BLE001
                    rec["error"] = str(exc)[:300]
                    errors += 1
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                if errors >= 25:
                    print(f"STOP q-jev-{name}: 25 errors")
                    return 2
        print(f"q-jev-{name} done (errors {errors})", flush=True)
    return 0


# ---------------------------------------------------------------- Haiku arm (proxy)

SYSTEM_Q = (
    "You are a security analyst reviewing web pages. Answer each question about the page in the "
    "screenshot; its URL is given. Reply with only a JSON object with these keys: "
    + ", ".join(f'"{k}"' for k in BOOL_KEYS) + " (each true or false), and \"brand_shown\" (the "
    "brand's name as a string, or null if none). Questions: "
    + " ".join(f"{k}: {v}" for k, v in QUESTIONS.items()))


def run_llm() -> int:
    import battery_v_vlm as v
    from concurrent.futures import ThreadPoolExecutor
    for name, items, urls in (("a", a_legit_items(), a_url()), ("x", x_items(), x_url())):
        f = REC / f"q-h-{name}.jsonl"
        done = set()
        if f.exists():
            done = {json.loads(l)["key"] for l in f.read_text(encoding="utf-8").splitlines()[1:]
                    if not json.loads(l).get("error")}
        else:
            f.write_text(json.dumps({"kind": "run_meta", "ts_utc": now(), "model": H55, "set": name,
                                     "system": SYSTEM_Q, "plan": "PLAN-addendum-Q-questions.md"}) + "\n",
                         encoding="utf-8")
        todo = [(k, p, urls[k]) for k, _, p in items if k not in done]

        def work(t):
            key, path, url = t
            if v.spent() >= v.SPEND_CAP:
                return None
            rec = {"kind": "observation", "ts_utc": now(), "key": key, "answers": None, "cost_usd": 0.0, "error": None}
            try:
                payload = {"model": H55, "max_tokens": 2048, "temperature": 0.0,
                           "messages": [{"role": "system", "content": SYSTEM_Q},
                                        {"role": "user", "content": [
                                            {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + v.image_b64(Path(path))}},
                                            {"type": "text", "text": f"URL: {url}"}]}]}
                import clients
                headers = {"Authorization": "Bearer local-proxy", "Content-Type": "application/json",
                           "User-Agent": "tdl-eg2-triage/0.1"}
                resp, el = clients.post_json(clients.PORTAL_CHAT_URL, payload, headers, timeout=120.0)
                choice = (resp.get("choices") or [{}])[0]
                text = (choice.get("message") or {}).get("content")
                u = resp.get("usage") or {}
                rec["cost_usd"] = float(u["cost"]) if u.get("cost") is not None else 0.0
                rec["served_model"] = resp.get("model")
                d = json.loads(text[text.find("{"): text.rindex("}") + 1])
                rec["answers"] = {k: bool(d.get(k)) for k in BOOL_KEYS}
                rec["answers"]["brand_shown"] = d.get("brand_shown")
            except Exception as exc:  # noqa: BLE001
                rec["error"] = str(exc)[:300]
            return rec

        with ThreadPoolExecutor(4) as ex:
            recs = [r for r in ex.map(work, todo) if r]
        with f.open("a", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"q-h-{name}: {len(recs)} calls, spent ${v.spent():.3f}", flush=True)
    return 0


# ---------------------------------------------------------------- score

def load_q_jev(name):
    f = REC / f"q-jev-{name}.jsonl"
    return {r["key"]: r["answers"] for r in (json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()[1:])
            if not r.get("error")}


def load_q_h(name):
    f = REC / f"q-h-{name}.jsonl"
    if not f.exists():
        return {}
    return {r["key"]: r["answers"] for r in (json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()[1:])
            if not r.get("error")}


def rate(flags):
    flags = list(flags)
    return su.wilson(int(sum(flags)), len(flags)) if flags else [None, None, None]


def run_score() -> int:
    x_sub = {s["key"]: s["subset"] for s in load_x()[1]}
    xh = [k for k in x_sub if x_sub[k] == "x_host"]
    xr = [k for k in x_sub if x_sub[k] == "x_rand"]
    df = load_sample()
    hard = {r["file_name"] for _, r in df.iterrows()
            if r["label_name"] == "legitimate" and any(t in r["file_name"] for t in HARDNEG_TYPES)}
    a_legit = [k for k, _, _ in a_legit_items()]

    qh_a, qh_x = load_q_h("a"), load_q_h("x")
    qj_a, qj_x = load_q_jev("a"), load_q_jev("x")
    res = {"ts_utc": now(), "questions": QUESTIONS, "haiku_available": bool(qh_x), "deviations": [], "arms": {}}

    def yes(d, keys, q):
        return [bool(d.get(k, {}).get(q)) for k in keys if k in d]

    # Haiku rates and rule R1
    if qh_x:
        res["arms"]["Q-H"] = {"questions": {}}
        for q in QUESTIONS:
            res["arms"]["Q-H"]["questions"][q] = {
                "yes_x_host": rate(yes(qh_x, xh, q)), "yes_a_legit": rate(yes(qh_a, a_legit, q))}

        def r1(d, k):
            a = d.get(k, {})
            return bool(a.get("asks_secrets") and (a.get("brand_domain_mismatch") or a.get("file_share_lure")))
        res["arms"]["Q-H"]["rule_r1"] = {
            "x_host_recall": rate([r1(qh_x, k) for k in xh if k in qh_x]),
            "x_rand_recall": rate([r1(qh_x, k) for k in xr if k in qh_x]),
            "a_legit_fpr": rate([r1(qh_a, k) for k in a_legit if k in qh_a]),
            "a_hardneg_fpr": rate([r1(qh_a, k) for k in a_legit if k in hard and k in qh_a])}
        # explanation coverage vs V3 flags
        v3 = {r["key"]: (r.get("verdict") == "phishing") for r in
              (json.loads(l) for l in (REC / "vlm-x-v3_h55.jsonl").read_text(encoding="utf-8").splitlines())
              if r.get("kind") == "observation" and not r.get("error")}
        flagged = [k for k in xh + xr if v3.get(k) and k in qh_x]
        covered = [k for k in flagged if any(qh_x[k].get(q) for q in
                   ("asks_secrets", "brand_domain_mismatch", "file_share_lure", "urgency_or_threat"))]
        res["arms"]["Q-H"]["explanation_coverage"] = rate([k in covered for k in flagged])

    # Jev-noul arms: report ROC-AUC of each noul vs label on X(pos) + A-legit(neg)
    y = np.array([1] * len(xh + xr) + [0] * len(a_legit))
    res["arms"]["Q-J"] = {"questions": {}}
    for q in [k for k in QUESTIONS if k != "brand_shown"]:
        sx = [qj_x.get(k, {}).get(q) for k in xh + xr]
        sa = [qj_a.get(k, {}).get(q) for k in a_legit]
        s = sx + sa
        if any(v is None for v in s):
            keep = [i for i, v in enumerate(s) if v is not None]
            yk = y[keep]; sk = np.array([s[i] for i in keep])
        else:
            yk, sk = y, np.array(s)
        res["arms"]["Q-J"]["questions"][q] = {"roc_auc": su.auc_with_ci(yk, sk)["roc_auc"],
                                              "yes_x": rate([v >= 0.5 for v in sx if v is not None]),
                                              "yes_a": rate([v >= 0.5 for v in sa if v is not None])}

    # agreement Q-H vs Q-J (binary) on shared keys
    if qh_x:
        res["agreement_h_vs_j"] = {}
        for q in ("login_form", "asks_secrets"):
            shared = [k for k in x_sub if k in qh_x and k in qj_x] + [k for k in a_legit if k in qh_a and k in qj_a]
            hh, jj = [], []
            for k in shared:
                d_h = qh_x.get(k) or qh_a.get(k); d_j = qj_x.get(k) or qj_a.get(k)
                hh.append(bool(d_h.get(q))); jj.append(bool((d_j.get(q) or 0) >= 0.5))
            agree = sum(a == b for a, b in zip(hh, jj)) / len(hh) if hh else None
            res["agreement_h_vs_j"][q] = {"n": len(hh), "agreement": agree}

    # EG2 ROC-AUC per phrase
    eg2 = json.loads((REC / "q-eg2.json").read_text(encoding="utf-8"))
    qk = eg2["questions"]
    xk, xs = eg2["x"]["keys"], np.array(eg2["x"]["scores"])
    ak, as_ = eg2["a_legit"]["keys"], np.array(eg2["a_legit"]["scores"])
    res["arms"]["Q-E"] = {"questions": {}}
    yq = np.array([1] * len(xk) + [0] * len(ak))
    for i, q in enumerate(qk):
        s = np.concatenate([xs[:, i], as_[:, i]])
        res["arms"]["Q-E"]["questions"][q] = {"roc_auc": su.auc_with_ci(yq, s)["roc_auc"]}

    # criteria (Haiku-dependent ones are pending until the proxy arm runs)
    crit = []
    if qh_x:
        r1b = res["arms"]["Q-H"]["rule_r1"]
        crit.append({"id": "Q-a", "desc": "Q-H rule R1: X-host recall >= 0.80 and A-legit FPR <= 0.05",
                     "actual": {"x_host_recall": r1b["x_host_recall"][0], "a_legit_fpr": r1b["a_legit_fpr"][0]},
                     "pass": r1b["x_host_recall"][0] >= 0.80 and r1b["a_legit_fpr"][0] <= 0.05})
        crit.append({"id": "Q-d", "desc": "Explanation coverage >= 0.95",
                     "actual": res["arms"]["Q-H"]["explanation_coverage"][0],
                     "pass": res["arms"]["Q-H"]["explanation_coverage"][0] >= 0.95})
        # Q-c is direct Q-H vs Q-J agreement; no audit needed.
        ag = res.get("agreement_h_vs_j", {})
        if ag:
            crit.append({"id": "Q-c", "desc": "Q-H vs Q-J agreement >= 0.80 for login_form and asks_secrets",
                         "actual": {q_: ag[q_]["agreement"] for q_ in ("login_form", "asks_secrets")},
                         "pass": all(ag[q_]["agreement"] >= 0.80 for q_ in ("login_form", "asks_secrets"))})
        # Q-b needs the audit labels (AUDIT-Q-LABELS.json); computed in --score if present
        audit = REC.parent / "AUDIT-Q-LABELS.json"
        if audit.exists():
            lbl = json.loads(audit.read_text(encoding="utf-8"))["labels"]
            def acc(q):
                ok = tot = 0
                for key, truth in lbl.items():
                    d = qh_x.get(key) or qh_a.get(key)
                    if d is None or q not in truth:
                        continue
                    tot += 1; ok += int(bool(d.get(q)) == bool(truth[q]))
                return ok / tot if tot else None
            accs = {q: acc(q) for q in ("login_form", "asks_secrets", "brand_domain_mismatch")}
            res["audit_accuracy_qh"] = accs
            crit.append({"id": "Q-b", "desc": "Q-H accuracy >=0.85 for login_form, asks_secrets, brand_domain_mismatch",
                         "actual": accs, "pass": all(v is not None and v >= 0.85 for v in accs.values())})
            res["deviations"].append("Q-b uses audit labels from AUDIT-Q-LABELS.json (Q-c is direct Q-H vs Q-J agreement)")
        else:
            res["deviations"].append("Q-b pending: AUDIT-Q-LABELS.json not yet created")
    else:
        res["deviations"].append("Q-a/Q-b/Q-c/Q-d pending: Haiku proxy arm (q-h-*) not yet run")
    res["criteria"] = crit
    (OUT / "results-q.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"haiku": bool(qh_x), "criteria": [(c["id"], c["pass"]) for c in crit],
                      "Q-E_auc": {q: round(res["arms"]["Q-E"]["questions"][q]["roc_auc"], 3) for q in qk},
                      "Q-J_auc": {q: round(res["arms"]["Q-J"]["questions"][q]["roc_auc"], 3)
                                  for q in res["arms"]["Q-J"]["questions"]}}, indent=1, default=str))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    for flag in ("eg2", "jev", "llm", "score"):
        g.add_argument(f"--{flag}", action="store_true")
    a = ap.parse_args()
    if a.eg2:
        return run_eg2()
    if a.jev:
        return run_jev()
    if a.llm:
        return run_llm()
    return run_score()


if __name__ == "__main__":
    raise SystemExit(main())
