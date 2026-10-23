"""Validate and assemble the SCALE merged corpus (PLAN-addendum-scale.md A2/A10).

Input
  corpus/email/scale/scale-normalized.jsonl   (local-only, from fetch_scale.py)

Outputs
  corpus/email/scale/scale-corpus.jsonl       (local-only merged corpus the runner reads)
  corpus/email/scale/scale-manifest.json      (committed summary: counts + hashes)

Validation: required fields, non-empty id/label/subject/body, valid labels, unique
email_ids, unique content hashes, and a from-field policy (blank allowed only for the
ling source, which provides no sender column).

Run:  python tools/jev_triage/build_corpus_scale.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCALE_DIR = REPO / "corpus" / "email" / "scale"
NORMALIZED = SCALE_DIR / "scale-normalized.jsonl"
MERGED = SCALE_DIR / "scale-corpus.jsonl"
MANIFEST = SCALE_DIR / "scale-manifest.json"

VALID_LABELS = {"safe", "gray", "spam", "attack"}
REQUIRED_FIELDS = ("email_id", "label", "from", "subject", "body")
# A curated CSV may lack sender values for some rows; blank `from` is allowed and
# counted per source in the manifest (source, not error).


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not NORMALIZED.exists():
        print(f"missing input: {NORMALIZED}")
        print("run: python tools/jev_triage/fetch_scale.py")
        return 1

    records = [json.loads(line) for line in NORMALIZED.read_text(encoding="utf-8").split("\n")
               if line.strip()]

    errors: list[str] = []
    seen_ids: set[str] = set()
    seen_hashes: dict[str, str] = {}
    for record in records:
        email_id = record.get("email_id", "?")
        for field in REQUIRED_FIELDS:
            if field not in record:
                errors.append(f"{email_id}: missing field {field}")
        for field in ("email_id", "label", "subject", "body"):
            if not str(record.get(field, "")).strip():
                errors.append(f"{email_id}: empty {field}")
        if record.get("label") not in VALID_LABELS:
            errors.append(f"{email_id}: invalid label {record.get('label')!r}")
        if not record.get("content_sha256"):
            errors.append(f"{email_id}: missing content_sha256")
        if email_id in seen_ids:
            errors.append(f"duplicate email_id {email_id}")
        seen_ids.add(email_id)
        content_hash = record.get("content_sha256")
        if content_hash in seen_hashes:
            errors.append(f"content duplicate: {email_id} == {seen_hashes[content_hash]}")
        if content_hash:
            seen_hashes[content_hash] = email_id

    if errors:
        print("SCALE CORPUS VALIDATION FAILED:")
        for error in errors[:20]:
            print(" -", error)
        return 1

    records.sort(key=lambda r: r["email_id"])
    with MERGED.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    by_label = Counter(r["label"] for r in records)
    by_source = Counter(r["source"] for r in records)
    by_source_label = Counter((r["source"], r["label"]) for r in records)
    empty_from = sum(1 for r in records if not str(r["from"]).strip())
    empty_from_by_source = dict(sorted(
        Counter(r["source"] for r in records if not str(r["from"]).strip()).items()))

    manifest = {
        "built_utc": datetime.now(timezone.utc).isoformat(),
        "total": len(records),
        "by_label": dict(sorted(by_label.items())),
        "by_source": dict(sorted(by_source.items())),
        "by_source_label": {
            f"{source}|{label}": count
            for (source, label), count in sorted(by_source_label.items())
        },
        "empty_from_rows": empty_from,
        "empty_from_by_source": empty_from_by_source,
        "input_hashes": {
            "scale-normalized.jsonl": sha256_of(NORMALIZED),
        },
        "notes": [
            "scale-corpus.jsonl is local-only: it embeds public-corpus content that is not redistributed.",
            "Composition, caps, and exclusions are recorded in corpus/email/scale/scale-lock.json "
            "(frozen by tools/jev_triage/PLAN-addendum-scale.md).",
            f"{empty_from} row(s) carry an empty from field (curated CSVs may lack sender values; "
            "see empty_from_by_source).",
            "Labels follow PLAN-addendum-scale.md A1/A3 mappings; phishing/fraud rows are inert text (no live payloads are fetched or executed).",
        ],
        "repro_command": "python tools/jev_triage/build_corpus_scale.py",
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["by_label"], indent=2))
    print(f"by source|label: {manifest['by_source_label']}")
    print(f"wrote {len(records)} -> {MERGED}")
    print(f"manifest -> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
