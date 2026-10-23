"""Detail views for the Jev triage report: per-source accuracy + missed attacks.

Run:  python tools/jev_triage/audit_details.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import score  # noqa: E402

PUBLIC_SOURCES = {"spamassassin_easy_ham", "spamassassin_hard_ham", "spamassassin_spam"}


def main() -> int:
    corpus = {}
    for line in (REPO / "corpus" / "email" / "corpus.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            corpus[record["email_id"]] = record

    runs = score.load_runs()
    excluded = score.load_exclusions()
    models = {}
    for name, run in runs.items():
        provider = run["meta"].get("provider")
        key = "jev" if provider == "typesafe" else run["meta"].get("model_requested", name)
        obs = [r for r in run["observations"]
               if r["email_id"] not in excluded and not r.get("error")
               and r.get("label_pred") in score.LABELS]
        models[key] = obs

    print("== per-source-group accuracy ==")
    groups = {
        "PUBLIC_2003": lambda r: r["source"] in PUBLIC_SOURCES,
        "SYNTHETIC": lambda r: r["source"] == "synthetic",
        "HAND": lambda r: r["source"] == "hand_authored",
    }
    for model, obs in models.items():
        for group, filt in groups.items():
            subset = [r for r in obs if filt(r)]
            if not subset:
                continue
            acc = sum(1 for r in subset if r["label_pred"] == r["label_true"]) / len(subset)
            print(f"  {model:22s} {group:12s} n={len(subset):3d} acc={acc:.3f}")
        print()

    for model, obs in models.items():
        missed = [r for r in obs if r["label_true"] == "attack" and r["label_pred"] != "attack"]
        print(f"== {model}: missed attacks ({len(missed)}) ==")
        for row in missed:
            meta = corpus.get(row["email_id"], {})
            print(f"  {row['email_id']:22s} sub={meta.get('subtype', '?'):18s} "
                  f"pred={row['label_pred']:5s} conf={row['confidence']} | {meta.get('subject', '')[:60]}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
