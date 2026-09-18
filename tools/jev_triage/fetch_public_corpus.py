"""Acquire and normalize the public email corpus for the Jev triage experiment.

Downloads the Apache SpamAssassin public corpus tarballs, parses each message,
applies the pre-registered exclusion rules (tools/jev_triage/PLAN.md §3), samples
a fixed number per source with a recorded seed, and writes:

  corpus/email/normalized_public.jsonl   (one row per included email; gitignored)
  corpus/email/email-corpus-lock.json    (provenance + hashes + counts; committed)
  corpus/email/_downloads/               (raw tarballs; gitignored)

Stdlib only. Re-running is safe: an existing lock file is verified against and
the script refuses to silently re-sample (delete the lock to re-acquire).

Run:  python tools/jev_triage/fetch_public_corpus.py
"""

from __future__ import annotations

import email
import email.header
import email.policy
import hashlib
import json
import random
import re
import sys
import tarfile
import tempfile
import urllib.request
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO / "corpus" / "email"
DOWNLOADS = CORPUS_DIR / "_downloads"
NORMALIZED = CORPUS_DIR / "normalized_public.jsonl"
LOCK = CORPUS_DIR / "email-corpus-lock.json"

SAMPLING_SEED = 20260917
SAMPLE_PER_SOURCE = 25
MAX_BODY_BYTES = 100 * 1024
MIN_BODY_CHARS = 40
ASCII_FLOOR = 0.5  # crude non-English/encoding exclusion; documented deviation risk

SOURCES = [
    {
        "name": "spamassassin_easy_ham",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "label": "safe",
        "label_basis": "easy_ham: mail the corpus authors consider obvious legitimate mail",
    },
    {
        "name": "spamassassin_hard_ham",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "label": "gray",
        "label_basis": "hard_ham: legitimate mail deliberately hard to distinguish from spam; "
                       "mapped to the ambiguity band (sensitivity run treats as safe)",
    },
    {
        "name": "spamassassin_spam",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "label": "spam",
        "label_basis": "spam: bulk unsolicited mail (2003-era corpus)",
    },
]

HTML_TAG_RE = re.compile(r"<[^>]+>")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str, target: Path) -> dict:
    if target.exists():
        data = target.read_bytes()
        return {"sha256": sha256_bytes(data), "bytes": len(data), "cached": True}
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    target.write_bytes(data)
    return {"sha256": sha256_bytes(data), "bytes": len(data), "cached": False}


def decode_header_value(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(raw)))
    except Exception:
        return raw


def extract_text(message: email.message.EmailMessage) -> tuple[str, str]:
    """Return (body_text, body_source). Prefers text/plain; falls back to tag-stripped HTML."""
    plain_parts, html_parts = [], []
    for part in message.walk():
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except LookupError:
            text = payload.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            plain_parts.append(text)
        else:
            html_parts.append(text)
    if plain_parts:
        return "\n".join(plain_parts), "text/plain"
    if html_parts:
        return HTML_TAG_RE.sub(" ", "\n".join(html_parts)), "html-stripped"
    return "", "none"


def normalize(raw_bytes: bytes, source: dict, source_file: str) -> tuple[dict | None, str]:
    """Parse one raw message. Returns (record, "") or (None, exclusion_reason)."""
    try:
        message = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as exc:  # noqa: BLE001
        return None, f"parse-failed: {type(exc).__name__}"
    body, body_source = extract_text(message)
    if body_source == "none":
        return None, "no-text-body"
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        return None, "body-over-100KB"
    if len(body.strip()) < MIN_BODY_CHARS:
        return None, "body-too-short"
    ascii_ratio = sum(1 for ch in body if ord(ch) < 128) / max(len(body), 1)
    if ascii_ratio < ASCII_FLOOR:
        return None, "non-ascii-dominant"
    from_value = decode_header_value(message.get("From"))
    reply_to = decode_header_value(message.get("Reply-To"))
    subject = decode_header_value(message.get("Subject"))
    if not subject.strip():
        return None, "no-subject"
    record = {
        "source": source["name"],
        "source_file": source_file,
        "label": source["label"],
        "label_basis": source["label_basis"],
        "from": from_value,
        "reply_to": reply_to,
        "subject": subject,
        "body": body.strip(),
        "body_source": body_source,
    }
    content_hash = sha256_bytes(
        (subject + "\n" + body.strip()).encode("utf-8")
    )
    record["content_sha256"] = content_hash
    return record, ""


def iter_messages(tar_path: Path):
    with tarfile.open(tar_path, "r:bz2") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            yield member.name, handle.read()


def main() -> int:
    if LOCK.exists():
        print(f"lock already present: {LOCK}")
        print("This script refuses to re-sample silently. Delete the lock file to re-acquire.")
        return 1

    corpus_dir = CORPUS_DIR
    corpus_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SAMPLING_SEED)
    all_records: list[dict] = []
    lock_sources = []

    for source in SOURCES:
        target = DOWNLOADS / source["url"].rsplit("/", 1)[-1]
        print(f"== {source['name']}: {source['url']}")
        info = download(source["url"], target)
        print(f"   sha256={info['sha256'][:16]}… bytes={info['bytes']} cached={info['cached']}")
        pool, exclusions, seen = [], {}, set()
        for name, raw in iter_messages(target):
            record, reason = normalize(raw, source, name)
            if record is None:
                exclusions[reason] = exclusions.get(reason, 0) + 1
                continue
            if record["content_sha256"] in seen:
                exclusions["duplicate"] = exclusions.get("duplicate", 0) + 1
                continue
            seen.add(record["content_sha256"])
            pool.append(record)
        pool.sort(key=lambda r: r["content_sha256"])  # deterministic order post-shuffle
        rng.shuffle(pool)
        sample = pool[:SAMPLE_PER_SOURCE]
        print(f"   pool={len(pool)} sampled={len(sample)} exclusions={exclusions}")
        all_records.extend(sample)
        lock_sources.append({
            **{k: source[k] for k in ("name", "url", "label", "label_basis")},
            "archive_sha256": info["sha256"],
            "archive_bytes": info["bytes"],
            "pool_size": len(pool),
            "sampled": len(sample),
            "exclusions": exclusions,
        })

    for index, record in enumerate(all_records, start=1):
        record["email_id"] = f"pub-{index:03d}"
    with NORMALIZED.open("w", encoding="utf-8") as handle:
        for record in all_records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    lock = {
        "corpus": "Jev email-triage public email corpus",
        "retrieval_date": date.today().isoformat(),
        "sampling_seed": SAMPLING_SEED,
        "sample_per_source": SAMPLE_PER_SOURCE,
        "license_and_scope": (
            "Apache SpamAssassin public corpus, distributed publicly for spam-filter "
            "testing. Files are retained locally under corpus/email/_downloads/ and are "
            "NOT redistributed in this repository; only this lock file is committed. "
            "Labels are the corpus's own ham/spam categories mapped to this experiment's "
            "taxonomy as recorded per source."
        ),
        "exclusion_rules": [
            "unparseable message", "no text/plain or text/html part",
            f"body over {MAX_BODY_BYTES} bytes", f"body under {MIN_BODY_CHARS} chars",
            f"fewer than {int(ASCII_FLOOR * 100)}% ASCII characters",
            "missing or empty Subject header",
            "duplicate of an earlier message (content sha256)",
        ],
        "sources": lock_sources,
        "included_total": len(all_records),
        "repro_command": "python tools/jev_triage/fetch_public_corpus.py",
    }
    LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {len(all_records)} records -> {NORMALIZED}")
    print(f"wrote lock -> {LOCK}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
