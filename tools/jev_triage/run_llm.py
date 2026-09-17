"""Run an LLM baseline (DeepSeek / Anthropic) over the email corpus.

Same normalized input as run_jev.py; the prompt is frozen here and mirrored in
PLAN.md §4. Output contract: strict JSON {"label": ..., "confidence": ...}.

Run:
  python tools/jev_triage/run_llm.py --provider deepseek --model deepseek-flash
  python tools/jev_triage/run_llm.py --provider anthropic --model claude-haiku-4-5
  ... --resume / --limit N
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "corpus" / "email" / "corpus.jsonl"
RECORDS_DIR = REPO / "docs" / "research" / "jev-email-triage" / "records"

SYSTEM_PROMPT = (
    "You are an email security triage classifier. Classify the email into exactly one "
    "category: safe, gray, spam, or attack.\n"
    "safe = wanted, legitimate mail the recipient would expect (personal, transactional, "
    "internal, subscribed).\n"
    "gray = real ambiguity: a careful analyst would neither auto-trust nor auto-block "
    "(unsolicited but plausible outreach, unclear list provenance, legitimate-looking mail "
    "with a concrete anomaly).\n"
    "spam = unsolicited bulk/promotional junk with no deceptive or malicious intent.\n"
    "attack = intent to harm or defraud (credential phishing, invoice/BEC fraud, malware "
    "lures, extortion, QR phishing, technical-support scams).\n"
    "Output strict JSON only: {\"label\": \"<one of the four>\", \"confidence\": <0.0-1.0>}. "
    "No prose, no code fences."
)

JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)
VALID_LABELS = {"safe", "gray", "spam", "attack"}


def normalized_state(record: dict) -> str:
    lines = [f"From: {record['from']}"]
    if record.get("reply_to"):
        lines.append(f"Reply-To: {record['reply_to']}")
    lines.append(f"Subject: {record['subject']}")
    lines.append("")
    lines.append(record["body"])
    return "\n".join(lines)


def parse_reply(text: str) -> tuple[str | None, float | None, str]:
    match = JSON_BLOCK_RE.search(text or "")
    if not match:
        return None, None, f"no-json: {text[:120]!r}"
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        return None, None, f"bad-json: {exc}"
    label = str(payload.get("label", "")).strip().lower()
    if label not in VALID_LABELS:
        return None, None, f"bad-label: {label!r}"
    try:
        confidence = float(payload.get("confidence"))
        confidence = min(max(confidence, 0.0), 1.0)
    except (TypeError, ValueError):
        confidence = None
    return label, confidence, ""


def latest_run_file(prefix: str) -> Path | None:
    if not RECORDS_DIR.exists():
        return None
    runs = sorted(RECORDS_DIR.glob(f"{prefix}-*.jsonl"))
    return runs[-1] if runs else None


def completed_ids(run_file: Path | None) -> set[str]:
    done = set()
    if run_file and run_file.exists():
        for line in run_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "observation" and not row.get("error"):
                done.add(row["email_id"])
    return done


def call_provider(provider: str, model: str, state: str, max_tokens: int) -> tuple[dict, float]:
    if provider == "deepseek":
        response, elapsed = clients.deepseek_chat(
            model,
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": state}],
            max_tokens=max_tokens, temperature=0.0,
        )
        return response, elapsed
    if provider == "anthropic":
        response, elapsed = clients.anthropic_messages(
            model, SYSTEM_PROMPT,
            [{"role": "user", "content": state}],
            max_tokens=max_tokens, temperature=0.0,
        )
        return response, elapsed
    if provider == "portal":
        return clients.portal_chat(model, SYSTEM_PROMPT, state, max_tokens=max_tokens)
    raise RuntimeError(f"unknown provider {provider!r}")


def extract(provider: str, response: dict) -> tuple[str, int | None, int | None, float | None]:
    if provider in ("deepseek", "portal"):
        choice = response["choices"][0]
        message = choice["message"]
        content = message.get("content")
        usage = response.get("usage", {})
        if not isinstance(content, str) or not content.strip():
            reasoning = message.get("reasoning") or ""
            raise RuntimeError(
                "empty content "
                f"(finish_reason={choice.get('finish_reason')}, "
                f"reasoning_chars={len(reasoning)}, "
                f"completion_tokens={usage.get('completion_tokens')})"
            )
        return content, usage.get("prompt_tokens"), usage.get("completion_tokens"), usage.get("cost")
    if provider == "anthropic":
        parts = [block.get("text", "") for block in response.get("content", [])
                 if block.get("type") == "text"]
        usage = response.get("usage", {})
        return "".join(parts), usage.get("input_tokens"), usage.get("output_tokens"), None
    raise RuntimeError(provider)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", required=True, choices=["deepseek", "anthropic", "portal"])
    parser.add_argument("--model", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--email-ids", default="", help="comma-separated subset filter")
    parser.add_argument("--sample", type=int, default=0,
                        help="seeded stratified sample of N emails balanced across labels")
    parser.add_argument("--max-tokens", type=int, default=64,
                        help="completion budget per call (64 held for most models; raise for verbose/thinking models)")
    args = parser.parse_args()

    corpus = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.email_ids:
        wanted = set(args.email_ids.split(","))
        corpus = [r for r in corpus if r["email_id"] in wanted]
    if args.sample:
        rng = random.Random(20260917)
        by_label: dict[str, list[dict]] = {}
        for record in corpus:
            by_label.setdefault(record["label"], []).append(record)
        per_label = max(args.sample // max(len(by_label), 1), 1)
        corpus = []
        for label in sorted(by_label):
            rows = list(by_label[label])
            rng.shuffle(rows)
            corpus.extend(rows[:per_label])
        corpus.sort(key=lambda r: r["email_id"])
    if args.limit:
        corpus = corpus[: args.limit]
    corpus_hash = hashlib.sha256(CORPUS.read_bytes()).hexdigest()

    prefix = f"{args.provider}-{args.model}".replace(".", "_").replace("/", "_")
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    if args.resume:
        run_file = latest_run_file(prefix)
        if run_file is None:
            print("no existing run to resume")
            return 1
        done = completed_ids(run_file)
        print(f"resuming {run_file.name}: {len(done)} already done")
    else:
        run_id = prefix + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_file = RECORDS_DIR / f"{run_id}.jsonl"
        done = set()
        meta = {
            "kind": "run_meta",
            "run_id": run_id,
            "model_requested": args.model,
            "provider": args.provider,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "system_prompt": SYSTEM_PROMPT,
            "corpus": str(CORPUS.relative_to(REPO)).replace("\\", "/"),
            "corpus_sha256": corpus_hash,
            "corpus_size": len(corpus),
            "subset_filter": args.email_ids or None,
            "sample": args.sample or None,
            "temperature": 0.0,
            "max_tokens": args.max_tokens,
            "pricing_ref": clients.PRICING.get(args.model, {}),
            "pricing_accessed": clients.PRICING_ACCESSED,
            "note": "one row per email (kind=observation); append-only",
        }
        run_file.write_text(json.dumps(meta, ensure_ascii=False) + "\n", encoding="utf-8")

    run_id = run_file.stem
    processed = errors = 0
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
                "model": args.model,
                "provider": args.provider,
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
                "max_tokens": args.max_tokens,
                "error": None,
            }
            try:
                response, elapsed = call_provider(args.provider, args.model, state, args.max_tokens)
                content, input_tokens, output_tokens, cost_usd = extract(args.provider, response)
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
            print(f"  [{processed:3d}] {row['email_id']:24s} true={row['label_true']:6s} "
                  f"pred={status:6s} conf={row['confidence']} {row['latency_ms']}ms")

    print(f"\ndone: {processed} new rows -> {run_file}")
    if errors:
        print(f"errors: {errors} (re-run with --resume to retry)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
