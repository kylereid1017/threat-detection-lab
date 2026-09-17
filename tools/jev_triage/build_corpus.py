"""Merge the public, synthetic, and hand-authored pieces into the final corpus.

Inputs
  corpus/email/normalized_public.jsonl        (local-only, from fetch_public_corpus.py)
  corpus/email/synthetic.jsonl                (committed, from generate_synthetic.py)
  tools/jev_triage/fixtures/hand_authored_attacks.json  (committed)

Outputs
  corpus/email/corpus.jsonl                   (local-only merged corpus the runners read)
  corpus/email/corpus-manifest.json           (committed summary: counts + hashes)

Run:  python tools/jev_triage/build_corpus.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO / "corpus" / "email"
PUBLIC = CORPUS_DIR / "normalized_public.jsonl"
SYNTHETIC = CORPUS_DIR / "synthetic.jsonl"
HAND = Path(__file__).resolve().parent / "fixtures" / "hand_authored_attacks.json"
MERGED = CORPUS_DIR / "corpus.jsonl"
MANIFEST = CORPUS_DIR / "corpus-manifest.json"

VALID_LABELS = {"safe", "gray", "spam", "attack"}
REQUIRED_FIELDS = ("email_id", "label", "from", "subject", "body")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        record["_source_file"] = path.name
        records.append(record)
    return records


def main() -> int:
    for path in (PUBLIC, SYNTHETIC, HAND):
        if not path.exists():
            print(f"missing input: {path}")
            return 1

    records = []
    records.extend(load_jsonl(PUBLIC))
    records.extend(load_jsonl(SYNTHETIC))
    hand_records = json.loads(HAND.read_text(encoding="utf-8"))
    for record in hand_records:
        record["source"] = "hand_authored"
        record["label_basis"] = "hand-authored inert attack case (fixtures/hand_authored_attacks.json)"
        record["_source_file"] = HAND.name
        records.append(record)

    errors = []
    for record in records:
        if not record.get("source"):
            record["source"] = "synthetic" if record.get("generator") else "unknown"
        if not record.get("from"):
            name = str(record.get("from_name", "")).strip()
            addr = str(record.get("from_addr", "")).strip()
            record["from"] = f"{name} <{addr}>" if name and addr else (addr or name)
    seen_ids, seen_hashes = set(), {}
    for record in records:
        for field in REQUIRED_FIELDS:
            if not str(record.get(field, "")).strip():
                errors.append(f"{record.get('email_id', '?')}: missing {field}")
        if record.get("label") not in VALID_LABELS:
            errors.append(f"{record.get('email_id', '?')}: invalid label {record.get('label')!r}")
        if record["email_id"] in seen_ids:
            errors.append(f"duplicate email_id {record['email_id']}")
        seen_ids.add(record["email_id"])
        content_hash = record.get("content_sha256") or hashlib.sha256(
            (record["subject"] + "\n" + record["body"]).encode("utf-8")
        ).hexdigest()
        record["content_sha256"] = content_hash
        if content_hash in seen_hashes:
            errors.append(
                f"content duplicate: {record['email_id']} == {seen_hashes[content_hash]}"
            )
        seen_hashes[content_hash] = record["email_id"]

    if errors:
        print("CORPUS VALIDATION FAILED:")
        for error in errors[:20]:
            print(" -", error)
        return 1

    records.sort(key=lambda r: r["email_id"])
    with MERGED.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    by_label = Counter(r["label"] for r in records)
    by_source_label = Counter((r["source"], r["label"]) for r in records)
    manifest = {
        "built_utc": datetime.now(timezone.utc).isoformat(),
        "total": len(records),
        "by_label": dict(sorted(by_label.items())),
        "by_source_label": {
            f"{source}|{label}": count
            for (source, label), count in sorted(by_source_label.items())
        },
        "input_hashes": {
            "normalized_public.jsonl": sha256_of(PUBLIC),
            "synthetic.jsonl": sha256_of(SYNTHETIC),
            "hand_authored_attacks.json": sha256_of(HAND),
        },
        "notes": [
            "corpus.jsonl is local-only: it embeds public-corpus content that is not redistributed.",
            "synthetic and hand-authored records are inert: hosts on reserved TLDs, no live URLs.",
            "labels follow tools/jev_triage/PLAN.md; public-corpus labels are category mappings "
            "(easy_ham->safe, hard_ham->gray, spam->spam).",
        ],
        "repro_command": "python tools/jev_triage/build_corpus.py",
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["by_label"], indent=2))
    print(f"by source|label: {manifest['by_source_label']}")
    print(f"wrote {len(records)} -> {MERGED}")
    print(f"manifest -> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
