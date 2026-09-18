"""Run the cheap-LLM comparator (DeepSeek V4.1 Flash) over the scale-battery subset.

Per PLAN-addendum-scale.md A8.1: deterministic proportional stratified subset of
2,000 emails from the scale corpus (per-class allocation = round(2000 x class share);
within class, hash order), scored with the frozen PLAN.md §4 prompt via the shared
run_llm helpers. Append-only JSONL, same row schema as run_llm.py; run id prefix
`deepseek-flash` under records/scale/.

Worst-case cost bound for the registered subset (list prices, peak tier):
2,000 x 2,500 input tokens x $0.30/MTok + 2,000 x 64 output x $1.20/MTok ~= $1.65,
below the A8.1 ceiling of $3.00.

Run:
  python tools/jev_triage/run_llm_scale.py              # new run
  python tools/jev_triage/run_llm_scale.py --resume     # continue the latest run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402
from run_llm import SYSTEM_PROMPT, call_provider, extract, normalized_state, parse_reply  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "corpus" / "email" / "scale" / "scale-corpus.jsonl"
RECORDS_DIR = REPO / "docs" / "research" / "jev-email-triage" / "records" / "scale"

SUBSET_SIZE = 2000
PROVIDER = "deepseek"
MODEL = "deepseek-flash"
MAX_TOKENS = 64
PREFIX = f"{PROVIDER}-{MODEL}".replace(".", "_").replace("/", "_")


def select_subset(records: list[dict], size: int = SUBSET_SIZE) -> list[dict]:
    """A8.1 deterministic proportional stratified subset (hash order within class)."""
    by_label: dict[str, list[dict]] = {}
    for record in records:
        by_label.setdefault(record["label"], []).append(record)
    total = len(records)
    if not total:
        return []
    allocations = {label: round(size * len(rows) / total) for label, rows in by_label.items()}
    drift = size - sum(allocations.values())
    if drift:  # deterministic rounding-drift adjustment toward the largest class
        largest = max(allocations, key=lambda label: (len(by_label[label]), label))
        allocations[largest] = max(0, allocations[largest] + drift)
    selected: list[dict] = []
    for label in sorted(by_label):
        rows = sorted(by_label[label], key=lambda r: r["content_sha256"])
        selected.extend(rows[: min(allocations[label], len(rows))])
    selected.sort(key=lambda r: r["email_id"])
    return selected


def latest_run_file() -> Path | None:
    if not RECORDS_DIR.exists():
        return None
    runs = sorted(RECORDS_DIR.glob(f"{PREFIX}-*.jsonl"))
    return runs[-1] if runs else None


def completed_ids(run_file: Path | None) -> set[str]:
    done: set[str] = set()
    if run_file and run_file.exists():
        for line in run_file.read_text(encoding="utf-8").split("\n"):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "observation" and not row.get("error"):
                done.add(row["email_id"])
    return done


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if not CORPUS.exists():
        print(f"missing corpus: {CORPUS}")
        return 1
    corpus = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").split("\n")
              if line.strip()]
    corpus_hash = hashlib.sha256(CORPUS.read_bytes()).hexdigest()
    subset = select_subset(corpus)
    allocations = {}
    for record in subset:
        allocations[record["label"]] = allocations.get(record["label"], 0) + 1

    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    if args.resume:
        run_file = latest_run_file()
        if run_file is None:
            print("no existing comparator run to resume")
            return 1
        done = completed_ids(run_file)
        print(f"resuming {run_file.name}: {len(done)} already done")
    else:
        run_id = PREFIX + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_file = RECORDS_DIR / f"{run_id}.jsonl"
        done = set()
        meta = {
            "kind": "run_meta",
            "run_id": run_id,
            "model_requested": MODEL,
            "provider": PROVIDER,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "system_prompt": SYSTEM_PROMPT,
            "corpus": (str(CORPUS.relative_to(REPO)).replace("\\", "/")
                       if CORPUS.is_relative_to(REPO) else str(CORPUS)),
            "corpus_sha256": corpus_hash,
            "corpus_size": len(subset),
            "subset_rule": ("PLAN-addendum-scale.md A8.1: proportional stratified, "
                            f"round({SUBSET_SIZE} x class share), hash order within class"),
            "subset_allocations": allocations,
            "temperature": 0.0,
            "max_tokens": MAX_TOKENS,
            "pricing_ref": clients.PRICING.get(MODEL, {}),
            "pricing_accessed": clients.PRICING_ACCESSED,
            "note": "one row per email (kind=observation); append-only; scale battery comparator",
        }
        run_file.write_text(json.dumps(meta, ensure_ascii=False) + "\n", encoding="utf-8")

    run_id = run_file.stem
    processed = errors = 0
    with run_file.open("a", encoding="utf-8") as handle:
        for record in subset:
            if record["email_id"] in done:
                continue
            state = normalized_state(record)
            row = {
                "kind": "observation",
                "run_id": run_id,
                "seq": len(done) + processed + 1,
                "ts_utc": datetime.now(timezone.utc).isoformat(),
                "model": MODEL,
                "provider": PROVIDER,
                "email_id": record["email_id"],
                "label_true": record["label"],
                "source": record.get("source", ""),
                "label_pred": None,
                "confidence": None,
                "raw_answer": None,
                "latency_ms": None,
                "input_tokens": None,
                "output_tokens": None,
                "cost_usd": None,
                "max_tokens": MAX_TOKENS,
                "error": None,
            }
            try:
                response, elapsed = call_provider(PROVIDER, MODEL, state, MAX_TOKENS)
                content, input_tokens, output_tokens, cost_usd = extract(PROVIDER, response)
                label, confidence, parse_error = parse_reply(content)
                row.update({
                    "label_pred": label,
                    "confidence": confidence,
                    "raw_answer": content[:4000],
                    "latency_ms": round(elapsed * 1000, 1),
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost_usd": cost_usd,
                })
                if parse_error:
                    row["error"] = parse_error
                    errors += 1
            except Exception as exc:  # noqa: BLE001
                row["error"] = str(exc)[:500]
                errors += 1
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            processed += 1
            status = row["label_pred"] or f"ERROR: {(row['error'] or '')[:50]}"
            print(f"  [{processed:4d}] {row['email_id']:12s} true={row['label_true']:6s} "
                  f"pred={status:6s} conf={row['confidence']} {row['latency_ms']}ms")
    print(f"\ndone: {processed} new rows -> {run_file}")
    if errors:
        print(f"errors: {errors} (re-run with --resume to retry)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
