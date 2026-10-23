"""Battery V — vision-LLM zero-shot comparator (PLAN-addendum-VX-urls.md).

  --run --arm v2|v3 [--set a|x]   call the model; append-only records, resumable
  --score                          compare against EG2 A3 (Battery A records) -> results-v.json

Spend cap: $5.00 across V and X (computed from returned usage), enforced before every call.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import clients  # noqa: E402
import stats_util as su  # noqa: E402
from battery_a_urls import DATA_DIR, HARDNEG_TYPES, host_of, load_sample, on_shared  # noqa: E402

OUT_DIR = REPO / "docs" / "research" / "eg2-url-benchmark"
REC_DIR = OUT_DIR / "records"
MODEL = "claude-haiku-4-5"
PRICE_IN, PRICE_OUT = 1.00, 5.00  # USD per million tokens (list price, 2026-09)
SPEND_CAP = 5.00
WIDTH = 1092
WORKERS = 4

SYSTEM = ("You are a security analyst reviewing web pages. Decide whether the page is phishing "
          "(it impersonates a brand, service, or login to obtain credentials, payment, or personal "
          "data, or is otherwise deceptive or malicious) or legitimate. Give p_phishing as your "
          "probability that it is phishing.")
SCHEMA = {
    "type": "json_schema",
    "schema": {
        "type": "object",
        "properties": {"verdict": {"type": "string", "enum": ["phishing", "legitimate"]},
                       "p_phishing": {"type": "number"}},
        "required": ["verdict", "p_phishing"],
        "additionalProperties": False,
    },
}
_lock = threading.Lock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def image_b64(path: Path) -> str:
    from PIL import Image
    im = Image.open(path).convert("RGB")
    if im.width > WIDTH:
        im = im.resize((WIDTH, round(im.height * WIDTH / im.width)), Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, format="JPEG", quality=85)
    return base64.standard_b64encode(buf.getvalue()).decode("ascii")


def call(img_path: Path, url: str | None) -> tuple[dict, float]:
    """Direct Messages API with structured output (the registered transport)."""
    content = [{"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64(img_path)}}]
    content.append({"type": "text", "text": f"URL: {url}" if url else "Classify this page."})
    headers = {"x-api-key": clients.load_key("ANTHROPIC_API_KEY"), "anthropic-version": clients.ANTHROPIC_VERSION,
               "Content-Type": "application/json", "User-Agent": "tdl-eg2-triage/0.1"}
    payload = {"model": MODEL, "max_tokens": 128, "temperature": 0.0, "system": SYSTEM,
               "messages": [{"role": "user", "content": content}], "output_config": {"format": SCHEMA}}
    return clients.post_json(clients.ANTHROPIC_URL, payload, headers, timeout=120.0)


# DEVIATION (2026-10-09): the direct API account had no credit, so V runs through the account-backed
# local proxy (`hermes proxy start --provider nous`, OpenAI-compatible) used for the Sept comparators.
# Same model, prompt, temperature and image; JSON is enforced by instruction (the proxy may not honor
# response_format) and parsed leniently. The served model id is recorded per call.
PORTAL_MODEL = "anthropic/claude-haiku-4.5"
MODELS = {"": "anthropic/claude-haiku-4.5", "_h55": "anthropic/claude-haiku-5.5"}  # arm suffix -> model (PLAN-addendum-V55)


def model_for(arm: str) -> str:
    return MODELS["_h55" if arm.endswith("_h55") else ""]


# DEVIATION (Haiku 5.5 arm): the model reasons before answering, and with max_tokens=128 the reasoning
# exhausted the budget, leaving no verdict on ~20% of calls (first attempt kept as
# vlm-a-v3_h55.aborted-max128.jsonl). The h55 arms run at the model's default reasoning with max_tokens=2048.
MAX_TOKENS = {"": 128, "_h55": 2048}


def max_tokens_for(model: str) -> int:
    return MAX_TOKENS["_h55" if model.endswith("haiku-5.5") else ""]
STOP = ["}\n```", "}\n\n"]
JSON_RULE = ' Reply with only a JSON object: {"verdict": "phishing" or "legitimate", "p_phishing": number from 0 to 1}.'


def call_portal(img_path: Path, url: str | None, model: str = PORTAL_MODEL) -> tuple[dict, float]:
    content = [{"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + image_b64(img_path)}},
               {"type": "text", "text": f"URL: {url}" if url else "Classify this page."}]
    # Stop right after the JSON object: the model appends a prose rationale the battery does not use.
    # Cost-only change (verdict tokens precede it); logged as part of the transport deviation.
    payload = {"model": model, "max_tokens": max_tokens_for(model), "temperature": 0.0, "stop": STOP,
               "messages": [{"role": "system", "content": SYSTEM + JSON_RULE}, {"role": "user", "content": content}]}
    headers = {"Authorization": "Bearer local-proxy", "Content-Type": "application/json", "User-Agent": "tdl-eg2-triage/0.1"}
    resp, el = clients.post_json(clients.PORTAL_CHAT_URL, payload, headers, timeout=120.0)
    choice = (resp.get("choices") or [{}])[0]
    text = (choice.get("message") or {}).get("content")
    u = resp.get("usage") or {}
    # normalise to the Messages-API shape used by run()
    return ({"stop_reason": choice.get("finish_reason"), "model": resp.get("model"),
             "content": [{"type": "text", "text": text}] if text else [],
             "usage": {"input_tokens": u.get("prompt_tokens", 0), "output_tokens": u.get("completion_tokens", 0),
                       "cost": u.get("cost")}}, el)


def parse_verdict(text: str) -> dict:
    """JSON object from the reply; the stop sequence removes its closing brace, so restore it."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in reply")
    body = text[start:].strip()
    if "}" not in body:
        body += "}"
    d = json.loads(body[: body.rindex("}") + 1])
    if d.get("verdict") not in ("phishing", "legitimate"):
        raise ValueError(f"bad verdict {d.get('verdict')!r}")
    return d


def spent() -> float:
    total = 0.0
    for f in REC_DIR.glob("vlm-*jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r.get("kind") == "observation":
                total += r.get("cost_usd") or 0.0
    return total


def items_for(test_set: str):
    """(key, label, image_path, url, extra) tuples; X set comes from battery_x_crossdataset."""
    if test_set == "a":
        df = load_sample()
        return [(r.file_name, int(r.label_name == "phishing"), DATA_DIR / r.file_name, str(r.url).strip(), {})
                for r in df.itertuples()]
    from battery_x_crossdataset import load_x_items
    return load_x_items()


def run(arm: str, test_set: str) -> int:
    REC_DIR.mkdir(parents=True, exist_ok=True)
    f = REC_DIR / f"vlm-{test_set}-{arm}.jsonl"
    done = set()
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r.get("kind") == "observation" and not r.get("error"):
                done.add(r["key"])
    else:
        f.write_text(json.dumps({"kind": "run_meta", "ts_utc": now(), "model": model_for(arm), "transport": "hermes proxy (nous), OpenAI-compatible; see DEVIATION note", "arm": arm, "set": test_set,
                                 "system": SYSTEM + JSON_RULE, "width": WIDTH,
                                 "price_per_mtok": [PRICE_IN, PRICE_OUT], "spend_cap": SPEND_CAP}) + "\n", encoding="utf-8")
    todo = [it for it in items_for(test_set) if it[0] not in done]
    budget = {"spent": spent(), "stopped": False}
    print(f"{arm}/{test_set}: {len(todo)} to do, spent so far ${budget['spent']:.3f}", flush=True)

    def work(it):
        key, label, img, url, extra = it
        with _lock:
            if budget["spent"] >= SPEND_CAP:
                budget["stopped"] = True
                return
        rec = {"kind": "observation", "ts_utc": now(), "model": MODEL, "arm": arm, "set": test_set, "key": key,
               "label_true": label, "verdict": None, "p_phishing": None, "stop_reason": None,
               "input_tokens": None, "output_tokens": None, "cost_usd": 0.0, "latency_ms": None, "error": None, **extra}
        try:
            resp, el = call_portal(img, url if arm.startswith("v3") else None, model_for(arm))
            u = resp.get("usage", {})
            list_cost = (u.get("input_tokens", 0) * PRICE_IN + u.get("output_tokens", 0) * PRICE_OUT) / 1e6
            rec.update(stop_reason=resp.get("stop_reason"), served_model=resp.get("model"),
                       input_tokens=u.get("input_tokens"), output_tokens=u.get("output_tokens"),
                       latency_ms=round(el * 1000, 1), billed_cost_usd=u.get("cost"),
                       cost_usd=float(u["cost"]) if u.get("cost") is not None else list_cost)
            text = next((b["text"] for b in resp.get("content", []) if b.get("type") == "text"), None)
            if resp.get("stop_reason") == "refusal" or text is None:
                rec["error"] = f"no verdict (stop_reason={resp.get('stop_reason')})"
            else:
                d = parse_verdict(text)
                rec["verdict"] = d["verdict"]
                rec["p_phishing"] = float(min(1.0, max(0.0, d["p_phishing"])))
        except Exception as exc:  # noqa: BLE001
            rec["error"] = str(exc)[:400]
        with _lock:
            budget["spent"] += rec["cost_usd"]
            with f.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")

    with ThreadPoolExecutor(WORKERS) as ex:
        for i, _ in enumerate(ex.map(work, todo)):
            if i % 100 == 0:
                print(f"[{now()}] {arm}/{test_set} {i}/{len(todo)} spent ${budget['spent']:.3f}", flush=True)
    print(f"done {arm}/{test_set}; total spent ${budget['spent']:.3f}; cap hit: {budget['stopped']}")
    return 0


def load_vlm(test_set: str, arm: str) -> dict[str, dict]:
    out = {}
    f = REC_DIR / f"vlm-{test_set}-{arm}.jsonl"
    for line in f.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r.get("kind") == "observation" and (r["key"] not in out or not r.get("error")):
            out[r["key"]] = r
    return out


def score() -> int:
    df = load_sample()
    keys = df["file_name"].tolist()
    y = (df["label_name"] == "phishing").astype(int).values
    a_rec = sorted(REC_DIR.glob("battery-a-*.jsonl"))[-1]
    a = {r["file_name"]: r for r in (json.loads(l) for l in a_rec.read_text(encoding="utf-8").splitlines()[1:])}
    p_a3 = np.array([a[k]["p"]["a3_interleaved"] for k in keys])
    res = {"ts_utc": now(), "model": PORTAL_MODEL, "a_records": a_rec.name, "arms": {}, "paired": {},
           "deviations": ["Transport: account-backed local proxy (hermes proxy, nous; OpenAI-compatible) instead of the "
                          "direct Messages API, which had no credit. Same model, prompt, temperature, image.",
                          "JSON enforced by instruction and parsed leniently instead of output_config.format.",
                          "Stop sequences after the JSON object to drop an unused prose rationale (cost only).",
                          "Haiku 5.5 arms: max_tokens 2048 (default reasoning) instead of 128; the 128-token attempt "
                          "left no verdict on ~20% of calls and is retained as vlm-a-v3_h55.aborted-max128.jsonl."]}
    pos, neg = y == 1, y == 0
    shared = np.array([on_shared(host_of(u)) for u in df["url"]])
    hard = neg & df["page_type"].isin(HARDNEG_TYPES).values
    for arm in [a for a in ("v2", "v3", "v2_h55", "v3_h55") if (REC_DIR / f"vlm-a-{a}.jsonl").exists()]:
        v = load_vlm("a", arm)
        flag = np.array([(v.get(k) or {}).get("verdict") == "phishing" for k in keys])
        p = np.array([float((v.get(k) or {}).get("p_phishing") or 0.0) for k in keys])
        errs = sum(1 for k in keys if (v.get(k) or {}).get("error") or k not in v)
        lat = [r["latency_ms"] for r in v.values() if r.get("latency_ms")]
        cost = sum(r.get("cost_usd") or 0 for r in v.values())
        res["arms"][arm] = {**su.binary_counts(y, flag), **su.auc_with_ci(y, p), "no_verdict": errs,
                            "latency_ms_p50": float(np.median(lat)) if lat else None,
                            "cost_per_1k_usd": 1000 * cost / max(1, len(v)), "cost_total_usd": cost,
                            "s_host_recall": su.wilson(int((flag & shared & pos).sum()), int((shared & pos).sum())),
                            "s_hardneg_fpr": su.wilson(int((flag & hard).sum()), int(hard.sum()))}
        ca3 = (p_a3 >= 0.5).astype(int) == y
        cv = flag.astype(int) == y
        res["paired"][f"a3_vs_{arm}"] = {"positives": su.mcnemar_exact(ca3[pos], cv[pos]),
                                         "negatives": su.mcnemar_exact(ca3[neg], cv[neg]),
                                         "bootstrap": su.paired_bootstrap_auc(y, p_a3, p)}
    a3_fp = int(((p_a3 >= 0.5) & neg).sum())
    res["criteria"] = []
    for arm, tag in (("v3", ""), ("v3_h55", "-h55")):
        if arm not in res["arms"]:
            continue
        b, v3 = res["paired"][f"a3_vs_{arm}"], res["arms"][arm]
        res["criteria"] += [
            {"id": f"V-a{tag}", "desc": f"Non-inferiority: A3 - {arm} PR-AUC CI lower bound > -0.02", "actual": b["bootstrap"],
             "pass": b["bootstrap"]["d_pr_auc_ci"][0] > -0.02},
            {"id": f"V-b{tag}", "desc": f"A3 fewer FPs than {arm} (McNemar exact p<0.05)",
             "actual": {"a3_fp": a3_fp, "vlm_fp": v3["fp"], **b["negatives"]},
             "pass": a3_fp < v3["fp"] and b["negatives"]["p_exact"] < 0.05},
        ]
    (OUT_DIR / "results-v.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps({c["id"]: c["pass"] for c in res["criteria"]}))
    for arm, v in res["arms"].items():
        print(arm, "recall", round(v["recall"][0], 4), "fpr", round(v["fpr"][0], 4), "roc", round(v["roc_auc"], 4),
              "pr", round(v["pr_auc"], 4), "no_verdict", v["no_verdict"], "p50ms", v["latency_ms_p50"], "$/1k", round(v["cost_per_1k_usd"], 3))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--arm", choices=["v2", "v3", "v2_h55", "v3_h55"])
    ap.add_argument("--set", choices=["a", "x"], default="a")
    a = ap.parse_args()
    if a.run:
        return run(a.arm, a.set)
    return score()


if __name__ == "__main__":
    sys.exit(main())
