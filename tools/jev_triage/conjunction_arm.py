"""Conjunction arm — exploratory analysis (post-hoc).

Spec: tools/jev_triage/PLAN-addendum-conjunction-arm.md
      (frozen 2026-09-17 BEFORE computation; this analysis is NOT pre-registered).

Run:  python tools/jev_triage/conjunction_arm.py   (from repo root)
Reads only committed records; prints the analysis grid. Writes nothing.
"""
import collections
import hashlib
import json
import os
import random
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REC = os.path.join(ROOT, "docs", "research", "jev-email-triage", "records",
                   "jev-20260917T143754Z.jsonl")
CORPUS = os.path.join(ROOT, "corpus", "email", "corpus.jsonl")


def sender_key(c):
    """Sender address key.

    2026-09-17 correction: the original version used `from_addr` only, which is absent
    on public-corpus rows and collapsed all of them into one bucket. Parse the address
    out of the display `from` header when `from_addr` is not present.
    """
    addr = (c.get("from_addr") or "").strip()
    if not addr:
        frm = c.get("from") or ""
        match = re.search(r"<([^>]+)>", frm)
        addr = (match.group(1) if match else frm).strip()
    return addr.lower()


def load():
    obs = [json.loads(l) for l in open(REC, encoding="utf-8") if l.strip()]
    obs = [r for r in obs if r.get("kind") == "observation"]
    crp = [json.loads(l) for l in open(CORPUS, encoding="utf-8") if l.strip()]
    by = {o["email_id"]: o for o in obs}
    assert len(obs) == 200 and len(crp) == 200, "unexpected input sizes"
    assert all(c["email_id"] in by for c in crp), "join incomplete"
    rows = [(by[c["email_id"]]["confidence"], by[c["email_id"]]["label_pred"],
             c["label"], sender_key(c)) for c in crp]
    return obs, rows


def dom(a):
    return a.split("@")[-1] if "@" in a else a


def run(rows, key, thr, variant):
    """Auto-act only when confident AND pred in {attack, safe} (registered rule)."""
    hist = collections.defaultdict(list)
    auto = dd = dq = sq = esc = fc = 0
    for conf, pred, true, addr in rows:
        k = addr if key == "addr" else (dom(addr) if key == "domain" else "ALL")
        h = hist[k]
        ok = conf >= thr and pred in ("attack", "safe")
        if ok and variant >= 1 and not h:
            ok = False
        if ok and variant >= 2 and any(x != pred for x in h):
            ok = False
        if ok:
            auto += 1
            if pred == "safe" and true == "attack":
                dd += 1
            if pred == "attack" and true == "safe":
                dq += 1
            if pred == "attack" and true == "spam":
                sq += 1
        else:
            esc += 1
        if not h:
            fc += 1
        h.append(true)
    return dict(auto=auto, deliv_att=dd, quar_legit=dq, spam_q=sq, esc=esc, fc=fc)


def main():
    obs, rows = load()
    sha = hashlib.sha256(open(CORPUS, "rb").read()).hexdigest()
    print("conjunction arm — post-hoc (spec frozen before computation)")
    print("corpus sha256:", sha)
    print()
    for key in ("addr", "domain"):
        for variant in (0, 1, 2):
            for thr in (0.25, 0.30, 0.35):
                r = run(rows, key, thr, variant)
                print("key=%-6s V%d T=%.2f auto=%3d deliv_att=%d quar_legit=%d "
                      "spam_q=%2d esc=%3d first_contact=%d"
                      % (key, variant, thr, r["auto"], r["deliv_att"],
                         r["quar_legit"], r["spam_q"], r["esc"], r["fc"]))
    print()
    random.seed(7)
    shuffled = rows[:]
    random.shuffle(shuffled)
    print("order sensitivity, key=addr T=0.30 auto counts (corpus order -> seed-7 shuffle):")
    for variant in (0, 1, 2):
        print("  V%d: %d -> %d" % (variant, run(rows, "addr", 0.30, variant)["auto"],
                                   run(shuffled, "addr", 0.30, variant)["auto"]))
    print()
    print("latency_ms (sequential single client):")
    allv = sorted(o["latency_ms"] for o in obs if o["latency_ms"])
    print("  %-22s n=%3d p50=%.1f p95=%.1f max=%.1f"
          % ("ALL", len(allv), allv[int(.5 * (len(allv) - 1))],
             allv[int(.95 * (len(allv) - 1))], allv[-1]))
    for s in sorted(set(o["source"] for o in obs)):
        v = sorted(o["latency_ms"] for o in obs if o["source"] == s and o["latency_ms"])
        n = len(v)
        if n:
            print("  %-22s n=%3d p50=%.1f p95=%.1f max=%.1f"
                  % (s, n, v[int(.5 * (n - 1))], v[int(.95 * (n - 1))], v[-1]))


if __name__ == "__main__":
    main()
