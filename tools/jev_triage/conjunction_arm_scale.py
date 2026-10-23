"""Conjunction arm on the SCALE battery — exploratory secondary analysis (A8.2).

Spec: PLAN-addendum-scale.md A8.2 (frozen 2026-09-17 before computation): first-contact
share; V0/V1/V2 conjunction variants over sender recurrence across a threshold grid,
mirroring PLAN-addendum-conjunction-arm.md conventions; ground-truth labels stand in for
prior dispositions (perfect-information bound, declared); fixed-seed shuffle control
mandatory; outputs are labeled post-hoc (spec frozen before computation).

Sender key: address parsed from the `from` field (corrected convention — see
CONJUNCTION-ARM.md Correction section). Rows with no parseable sender are EXCLUDED from
the recurrence analysis; their count is reported.

Run:  python tools/jev_triage/conjunction_arm_scale.py   (reads local records; writes nothing)
"""

from __future__ import annotations

import collections
import hashlib
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORDS = ROOT / "docs" / "research" / "jev-email-triage" / "records" / "scale"
CORPUS = ROOT / "corpus" / "email" / "scale" / "scale-corpus.jsonl"

THRESHOLDS = (0.25, 0.30, 0.35)
SHUFFLE_SEED = 7


def sender_key(record: dict) -> str:
    addr = (record.get("from") or "").strip()
    match = re.search(r"<([^>]+)>", addr)
    if match:
        addr = match.group(1).strip()
    return addr.lower()


def load():
    runs = sorted(RECORDS.glob("jev-scale-*.jsonl"))
    assert runs, "no scale Jev run found"
    run = runs[-1]
    obs = [json.loads(line) for line in run.read_text(encoding="utf-8").split("\n")
           if line.strip()]
    obs = [r for r in obs if r.get("kind") == "observation"
           and not r.get("error") and r.get("label_pred")]
    crp = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").split("\n")
           if line.strip()]
    by = {o["email_id"]: o for o in obs}
    assert all(c["email_id"] in by for c in crp), "join incomplete"
    rows, no_sender = [], 0
    for c in crp:
        key = sender_key(c)
        if not key:
            no_sender += 1
            continue
        o = by[c["email_id"]]
        rows.append((o["confidence"], o["label_pred"], c["label"], key))
    return run.name, obs, rows, no_sender, len(crp)


def dom(addr: str) -> str:
    return addr.split("@")[-1] if "@" in addr else addr


def run_variant(rows, key_mode, thr, variant):
    """Auto-act only when confident AND pred in {attack, safe} (registered two-branch rule)."""
    hist: dict = collections.defaultdict(list)
    auto = delivered_attacks = quarantined_legit = spam_q = escalated = first_contact = 0
    for conf, pred, true, addr in rows:
        k = addr if key_mode == "addr" else dom(addr)
        h = hist[k]
        ok = conf >= thr and pred in ("attack", "safe")
        if ok and variant >= 1 and not h:
            ok = False
        if ok and variant >= 2 and any(x != pred for x in h):
            ok = False
        if ok:
            auto += 1
            if pred == "safe" and true == "attack":
                delivered_attacks += 1
            if pred == "attack" and true == "safe":
                quarantined_legit += 1
            if pred == "attack" and true == "spam":
                spam_q += 1
        else:
            escalated += 1
        if not h:
            first_contact += 1
        h.append(true)
    return dict(auto=auto, deliv_att=delivered_attacks, quar_legit=quarantined_legit,
                spam_q=spam_q, esc=escalated, fc=first_contact)


def main() -> int:
    run_name, obs, rows, no_sender, corpus_size = load()
    print("conjunction arm (scale) — post-hoc (spec frozen before computation)")
    print(f"run: {run_name}; corpus rows {corpus_size}; scored {len(obs)}; "
          f"analyzed {len(rows)}; no-sender rows excluded {no_sender}")
    print(f"corpus sha256: {hashlib.sha256(CORPUS.read_bytes()).hexdigest()}")
    print()
    n = len(rows)
    for key_mode in ("addr", "domain"):
        for variant in (0, 1, 2):
            for thr in THRESHOLDS:
                r = run_variant(rows, key_mode, thr, variant)
                print("key=%-6s V%d T=%.2f auto=%5d (%5.2f%%) deliv_att=%4d quar_legit=%d "
                      "spam_q=%5d esc=%6d first_contact=%5d" %
                      (key_mode, variant, thr, r["auto"], 100.0 * r["auto"] / n,
                       r["deliv_att"], r["quar_legit"], r["spam_q"], r["esc"], r["fc"]))
    print()
    random.seed(SHUFFLE_SEED)
    shuffled = rows[:]
    random.shuffle(shuffled)
    print(f"order sensitivity, key=addr T=0.30 auto counts (corpus order -> seed-{SHUFFLE_SEED} shuffle):")
    for variant in (0, 1, 2):
        print("  V%d: %d -> %d" % (variant, run_variant(rows, "addr", 0.30, variant)["auto"],
                                   run_variant(shuffled, "addr", 0.30, variant)["auto"]))
    print()
    latencies = sorted(o["latency_ms"] for o in obs if o.get("latency_ms"))
    print("latency_ms (sequential single client), overall: n=%d p50=%.1f p95=%.1f max=%.1f"
          % (len(latencies), latencies[int(0.5 * (len(latencies) - 1))],
             latencies[int(0.95 * (len(latencies) - 1))], latencies[-1]))
    for source in sorted({o.get("source", "") for o in obs}):
        v = sorted(o["latency_ms"] for o in obs if o.get("source") == source and o.get("latency_ms"))
        if v:
            print("  %-28s n=%5d p50=%.1f p95=%.1f" %
                  (source, len(v), v[int(0.5 * (len(v) - 1))], v[int(0.95 * (len(v) - 1))]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
