"""POST-HOC (not pre-registered), run 2026-10-09 after reading Batteries A / V / X.

Question: the link reader (Jev) rarely says "safe" and often says "gray" (unsure). Treat gray as
"route this to something that can see the page" instead of as a miss, and ask what each page
reader does with the links Jev routed versus the ones it was already sure about.

Reads existing records only (no new model calls):
  phishing    Phishpedia X sample (387 trusted-host + 600 random): jev-url-x.jsonl, EG2 A3 scores
              (corpus/urls/phishpedia/eg2/a3_interleaved-p.npy), vlm-x-v3*.jsonl
  legitimate  2026 benchmark legitimate sites (672): battery-a OOF records (Jev label + EG2 A3),
              vlm-a-v3*.jsonl
EG2 threshold 0.5 (T1); LLM verdict "phishing". LLM no-verdict calls count as "legitimate", as in V.
Also: Haiku 5.5 repeatability, Battery R's unaltered re-run (vlm-r-orig.jsonl) vs the X run.

Writes docs/research/eg2-url-benchmark/POSTHOC-ROUTE.json. Everything here is labeled post-hoc.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))

import stats_util as su  # noqa: E402

OUT = REPO / "docs" / "research" / "eg2-url-benchmark"
REC = OUT / "records"
PP = REPO / "corpus" / "urls" / "phishpedia"
READERS = {"eg2": "EG2 URL + screenshot", "h45": "Haiku 4.5", "h55": "Haiku 5.5"}
VLM_ARM = {"h45": "v3", "h55": "v3_h55"}


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def vlm_flags(set_: str, arm: str) -> dict[str, bool]:
    rows = [r for r in jsonl(REC / f"vlm-{set_}-{arm}.jsonl") if r.get("kind") == "observation"]
    return {r["key"]: (r.get("verdict") == "phishing") for r in rows}


def rate(flags: list[bool]) -> list[float]:
    return su.wilson(int(sum(flags)), len(flags)) if flags else [None, None, None]


def main() -> int:
    # Phishing: Phishpedia X sample
    sample = json.loads((PP / "sample.json").read_text(encoding="utf-8"))["sample"]
    p_eg2 = np.load(PP / "eg2" / "a3_interleaved-p.npy")
    jev_x = {r["key"]: r["label_pred"] for r in jsonl(REC / "jev-url-x.jsonl")
             if r.get("kind") == "observation" and not r.get("error")}
    vx = {k: vlm_flags("x", a) for k, a in VLM_ARM.items()}
    phish = []
    for s, p in zip(sample, p_eg2):
        phish.append({"key": s["key"], "subset": s["subset"], "jev": jev_x.get(s["key"], "missing"),
                      "eg2": bool(p >= 0.5), "h45": vx["h45"].get(s["key"], False),
                      "h55": vx["h55"].get(s["key"], False)})

    # Legitimate: 2026 benchmark, Battery A OOF records
    a_rec = sorted(REC.glob("battery-a-*.jsonl"))[-1]
    va = {k: vlm_flags("a", a) for k, a in VLM_ARM.items()}
    legit = []
    for r in jsonl(a_rec):
        if r.get("kind") != "observation" or r["label_true"] != 0:
            continue
        k = r["file_name"]
        legit.append({"key": k, "jev": r["jev_label"], "eg2": bool(r["p"]["a3_interleaved"] >= 0.5),
                      "h45": va["h45"].get(k, False), "h55": va["h55"].get(k, False)})

    def block(rows: list[dict], label: str) -> dict:
        out = {"n": len(rows), "jev_labels": {}}
        for lab in sorted({r["jev"] for r in rows}):
            sub = [r for r in rows if r["jev"] == lab]
            out["jev_labels"][lab] = {"n": len(sub), label: {rd: rate([r[rd] for r in sub]) for rd in READERS}}
        return out

    res = {
        "label": "POST-HOC",
        "records": {"battery_a": a_rec.name, "jev_x": "jev-url-x.jsonl",
                    "vlm": sorted(f"vlm-{s}-{a}.jsonl" for s in ("a", "x") for a in VLM_ARM.values())},
        "readers": READERS,
        "note": "Per Jev label: the share each page reader flags as phishing. On phishing rows that is the "
                "catch rate; on legitimate rows it is the false-alarm rate.",
        "phishing_x_host": block([r for r in phish if r["subset"] == "x_host"], "flagged"),
        "phishing_x_rand": block([r for r in phish if r["subset"] == "x_rand"], "flagged"),
        "legitimate_a": block(legit, "flagged"),
    }

    # Routing policies: Jev decides when it says attack, a page reader decides everything else.
    pol = {}
    for rd in READERS:
        def route(r, rd=rd):
            return True if r["jev"] == "attack" else r[rd]

        def confirm(r, rd=rd):
            return r[rd]
        pol[rd] = {
            "jev_attack_else_reader": {
                "caught_x_host": rate([route(r) for r in phish if r["subset"] == "x_host"]),
                "caught_x_rand": rate([route(r) for r in phish if r["subset"] == "x_rand"]),
                "false_alarms_a": rate([route(r) for r in legit])},
            "reader_decides_all": {
                "caught_x_host": rate([confirm(r) for r in phish if r["subset"] == "x_host"]),
                "caught_x_rand": rate([confirm(r) for r in phish if r["subset"] == "x_rand"]),
                "false_alarms_a": rate([confirm(r) for r in legit])},
        }
    res["policies"] = pol
    res["jev_alone"] = {"caught_x_host": rate([r["jev"] == "attack" for r in phish if r["subset"] == "x_host"]),
                        "caught_x_rand": rate([r["jev"] == "attack" for r in phish if r["subset"] == "x_rand"]),
                        "false_alarms_a": rate([r["jev"] == "attack" for r in legit]),
                        "said_safe_on_phishing": sum(r["jev"] == "safe" for r in phish),
                        "said_safe_on_legitimate": sum(r["jev"] == "safe" for r in legit)}

    # Repeatability: Battery R's unaltered run (r/orig/<i>) re-asked Haiku 5.5 about 100 X pages
    # hours after the X run. The model rejects a temperature setting, so both ran at default sampling.
    orig = [r for r in jsonl(REC / "vlm-r-orig.jsonl") if r.get("kind") == "observation" and not r.get("error")]
    x55 = {r["key"]: r for r in jsonl(REC / "vlm-x-v3_h55.jsonl") if r.get("kind") == "observation" and not r.get("error")}
    pairs = [(r, x55[sample[int(r["key"].rsplit("/", 1)[1])]["key"]]) for r in orig
             if sample[int(r["key"].rsplit("/", 1)[1])]["key"] in x55]
    res["h55_repeat"] = {"n": len(pairs), "same_verdict": sum(a["verdict"] == b["verdict"] for a, b in pairs),
                         "same_p": sum(a["p_phishing"] == b["p_phishing"] for a, b in pairs),
                         "max_abs_dp": max(abs(a["p_phishing"] - b["p_phishing"]) for a, b in pairs),
                         "note": "pages EG2 flagged (Battery R selection), so mostly clear-cut; not a borderline-case test"}

    (OUT / "POSTHOC-ROUTE.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
