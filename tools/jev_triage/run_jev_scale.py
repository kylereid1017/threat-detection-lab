"""Run Jev (TypeSafe System One) over the SCALE email corpus; append raw records.

Mirrors tools/jev_triage/run_jev.py conventions: same frozen questions (PLAN.md §4),
same record schema, append-only JSONL with a run_meta header row and skip-completed
resume. Fixed to the scale corpus and records/scale/ output.

Run:
  python tools/jev_triage/run_jev_scale.py              # new run
  python tools/jev_triage/run_jev_scale.py --resume     # continue the latest scale run
  python tools/jev_triage/run_jev_scale.py --limit 5    # quick smoke
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402
from run_jev import QUESTIONS, completed_ids, normalized_state  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "corpus" / "email" / "scale" / "scale-corpus.jsonl"
RECORDS_DIR = REPO / "docs" / "research" / "jev-email-triage" / "records" / "scale"

MODEL = "jev-latest"
MODEL_LABEL = "jev"


def latest_run_file() -> Path | None:
    if not RECORDS_DIR.exists():
        return None
    runs = sorted(RECORDS_DIR.glob("jev-scale-*.jsonl"))
    return runs[-1] if runs else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    if not CORPUS.exists():
        print(f"missing corpus: {CORPUS}")
        print("run: python tools/jev_triage/fetch_scale.py && python tools/jev_triage/build_corpus_scale.py")
        return 1
    corpus = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").split("\n")
              if line.strip()]
    corpus_hash = hashlib.sha256(CORPUS.read_bytes()).hexdigest()
    if args.limit:
        corpus = corpus[: args.limit]

    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    if args.resume:
        run_file = latest_run_file()
        if run_file is None:
            print("no existing scale run to resume")
            return 1
        done = completed_ids(run_file)
        print(f"resuming {run_file.name}: {len(done)} already done")
    else:
        run_id = "jev-scale-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_file = RECORDS_DIR / f"{run_id}.jsonl"
        done = set()
        meta = {
            "kind": "run_meta",
            "run_id": run_id,
            "model_requested": MODEL,
            "provider": "typesafe",
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "corpus": (str(CORPUS.relative_to(REPO)).replace("\\", "/")
                       if CORPUS.is_relative_to(REPO) else str(CORPUS)),
            "corpus_sha256": corpus_hash,
            "corpus_size": len(corpus),
            "questions": QUESTIONS,
            "pricing_ref": clients.PRICING["jev-latest"],
            "pricing_accessed": clients.PRICING_ACCESSED,
            "plan_ref": "tools/jev_triage/PLAN-addendum-scale.md",
            "note": "one row per email (kind=observation); append-only; scale battery",
        }
        run_file.write_text(json.dumps(meta, ensure_ascii=False) + "\n", encoding="utf-8")

    run_id = run_file.stem
    errors = 0
    processed = 0
    with run_file.open("a", encoding="utf-8") as handle:
        for record in corpus:
            if record["email_id"] in done:
                continue
            state = normalized_state(record)
            row = {
                "kind": "observation",
                "run_id": run_id,
                "seq": len(done) + processed + 1,
                "ts_utc": datetime.now(timezone.utc).isoformat(),
                "model": MODEL,
                "email_id": record["email_id"],
                "label_true": record["label"],
                "source": record.get("source", ""),
                "label_pred": None,
                "confidence": None,
                "raw_answer": None,
                "latency_ms": None,
                "input_tokens": None,
                "output_tokens": None,
                "error": None,
            }
            try:
                response, elapsed = clients.jev_system_one(state, QUESTIONS, model=MODEL)
                answers = response.get("answers", {})
                disposition = answers.get("disposition", {})
                row["label_pred"] = disposition.get("choice")
                row["confidence"] = disposition.get("confidence")
                row["raw_answer"] = answers
                row["latency_ms"] = round(elapsed * 1000, 1)
                usage = response.get("usage", {})
                row["input_tokens"] = usage.get("input_tokens")
                row["output_tokens"] = usage.get("output_tokens")
                row["model"] = response.get("model", MODEL)
            except Exception as exc:  # noqa: BLE001
                row["error"] = str(exc)[:500]
                errors += 1
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            processed += 1
            status = row["label_pred"] or f"ERROR: {row['error'][:60]}"
            print(f"  [{processed:5d}] {row['email_id']:12s} true={row['label_true']:6s} "
                  f"pred={status:6s} conf={row['confidence']} {row['latency_ms']}ms")
            if processed % 25 == 0:
                time.sleep(0.2)

    print(f"\ndone: {processed} new rows -> {run_file}")
    if errors:
        print(f"errors: {errors} (re-run with --resume to retry)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
