"""Acquire and normalize the SCALE public email corpus (PLAN-addendum-scale.md A1-A4).

Sources (frozen): six Apache SpamAssassin tarballs (2003/2005 releases) plus six
curated CSV datasets from Zenodo 10.5281/zenodo.8339691 (Nazario, Nazario_5,
Nigerian_5, Nigerian_Fraud, CEAS_08, Ling). Applies the uniform A4 exclusion rules,
cross-source dedupe in frozen source order (S1..S12), and deterministic per-class
caps by hash order (A2).

Outputs
  corpus/email/scale/scale-normalized.jsonl   (local; one row per included email)
  corpus/email/scale/scale-lock.json          (committed; provenance + counts + determinations)
  corpus/email/scale/_downloads_scale/        (raw archives; local)

Stdlib only. Refuses to re-run while the lock exists (delete it to re-acquire).
Any source-level failure aborts WITHOUT writing the lock (forces an explicit decision).

Run:  python tools/jev_triage/fetch_scale.py
"""

from __future__ import annotations

import collections
import csv
import io
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fetch_public_corpus as fpc  # noqa: E402  (reuse download/iter/normalize/helpers)

REPO = Path(__file__).resolve().parents[2]
SCALE_DIR = REPO / "corpus" / "email" / "scale"
DOWNLOADS = SCALE_DIR / "_downloads_scale"
NORMALIZED = SCALE_DIR / "scale-normalized.jsonl"
LOCK = SCALE_DIR / "scale-lock.json"

SAMPLING_SEED = 20260917  # parity with PLAN; caps truncate by hash order (seed-independent)
CAPS = {"safe": 6_000, "gray": 1_000, "spam": 4_500, "attack": 12_000}

SA_BASE = "https://spamassassin.apache.org/old/publiccorpus/"
ZENODO_FILE = "https://zenodo.org/api/records/8339691/files/{name}/content"

ARTIFACT_SUBJECT = "FOLDER INTERNAL DATA"
ARTIFACT_SENDER = "MAILER-DAEMON@MONKEY.ORG"

SA_SOURCES = [
    {"name": "spamassassin_easy_ham", "file": "20030228_easy_ham.tar.bz2", "label": "safe",
     "label_basis": "easy_ham: mail the corpus authors consider obvious legitimate mail (2003 release)"},
    {"name": "spamassassin_easy_ham_2", "file": "20030228_easy_ham_2.tar.bz2", "label": "safe",
     "label_basis": "easy_ham_2: same category, second 2003 release"},
    {"name": "spamassassin_hard_ham", "file": "20030228_hard_ham.tar.bz2", "label": "gray",
     "label_basis": "hard_ham: legitimate mail deliberately hard to distinguish from spam; "
                    "primary mapping gray (sensitivity run treats as safe; both reported)"},
    {"name": "spamassassin_spam", "file": "20030228_spam.tar.bz2", "label": "spam",
     "label_basis": "spam: bulk unsolicited mail (2003 release)"},
    {"name": "spamassassin_spam_2", "file": "20030228_spam_2.tar.bz2", "label": "spam",
     "label_basis": "spam_2: bulk unsolicited mail (2003 release)"},
    {"name": "spamassassin_spam_2005_2", "file": "20050311_spam_2.tar.bz2", "label": "spam",
     "label_basis": "spam_2 (2005 release): bulk unsolicited mail"},
]

CSV_SOURCES = [
    {"name": "nazario", "file": "Nazario.csv", "label": "attack", "select_label": "1",
     "label_basis": "curated Nazario phishing corpus (Zenodo 8339691); rows label==1 are phishing"},
    {"name": "nazario_5", "file": "Nazario_5.csv", "label": "attack", "select_label": "1",
     "label_basis": "curated Nazario phishing corpus, extended variant; rows label==1 are phishing"},
    {"name": "nigerian_5", "file": "Nigerian_5.csv", "label": "attack", "select_label": "1",
     "label_basis": "advance-fee fraud / social-engineering phishing; rows label==1 are malicious"},
    {"name": "nigerian_fraud", "file": "Nigerian_Fraud.csv", "label": "attack", "select_label": "1",
     "label_basis": "advance-fee fraud; rows label==1 are malicious"},
    {"name": "ceas_08", "file": "CEAS_08.csv", "label": "attack", "select_label": "1",
     "label_basis": "CEAS 2008 corpus phishing subset; rows label==1 are phishing"},
    {"name": "ling", "file": "Ling.csv", "label": "spam", "select_label": "1",
     "label_basis": "Ling-Spam corpus (spam=1 / ham=0); semantics confirmed 2026-09-17 by label "
                    "distribution (458/2401) and content samples; rows label==0 out of scope"},
]


def check_common(record: dict) -> str | None:
    """A4 exclusion rules that apply after a record exists (SA and CSV paths)."""
    subject = record["subject"]
    body = record["body"]
    if not subject.strip():
        return "no-subject"
    if len(body.encode("utf-8")) > fpc.MAX_BODY_BYTES:
        return "body-over-100KB"
    if len(body.strip()) < fpc.MIN_BODY_CHARS:
        return "body-too-short"
    ascii_ratio = sum(1 for ch in body if ord(ch) < 128) / max(len(body), 1)
    if ascii_ratio < fpc.ASCII_FLOOR:
        return "non-ascii-dominant"
    if ARTIFACT_SUBJECT in subject.upper() or ARTIFACT_SENDER in str(record.get("from", "")).upper():
        return "corpus-artifact"
    return None


def normalize_csv_row(row: dict, source: dict, source_file: str) -> tuple[dict | None, str]:
    """One curated-CSV row -> corpus record, or (None, exclusion reason)."""
    record = {
        "source": source["name"],
        "source_file": source_file,
        "label": source["label"],
        "label_basis": source["label_basis"],
        "from": str(row.get("sender") or "").strip(),
        "reply_to": "",
        "subject": str(row.get("subject") or ""),
        "body": str(row.get("body") or "").strip(),
        "body_source": "csv",
    }
    reason = check_common(record)
    if reason:
        return None, reason
    record["content_sha256"] = fpc.sha256_bytes(
        (record["subject"] + "\n" + record["body"]).encode("utf-8"))
    return record, ""


def process_sa_source(source: dict) -> dict:
    url = SA_BASE + source["file"]
    target = DOWNLOADS / source["file"]
    info = fpc.download(url, target)
    pool, exclusions, seen = [], collections.Counter(), set()
    rows_total = 0
    for name, raw in fpc.iter_messages(target):
        rows_total += 1
        record, reason = fpc.normalize(raw, source, name)
        if record is None:
            exclusions[reason] += 1
            continue
        reason = check_common(record)
        if reason:
            exclusions[reason] += 1
            continue
        if record["content_sha256"] in seen:
            exclusions["duplicate"] += 1
            continue
        seen.add(record["content_sha256"])
        pool.append(record)
    pool.sort(key=lambda r: r["content_sha256"])
    return {"source": source, "url": url, "info": info, "rows_total": rows_total,
            "out_of_scope": 0, "exclusions": dict(exclusions), "pool": pool}


def process_csv_source(source: dict) -> dict:
    url = ZENODO_FILE.format(name=source["file"])
    target = DOWNLOADS / source["file"]
    info = fpc.download(url, target)
    csv.field_size_limit(2 ** 31 - 1)
    text = target.read_bytes().decode("utf-8", "replace")
    reader = csv.DictReader(io.StringIO(text))
    columns = list(reader.fieldnames or [])
    missing = [c for c in ("subject", "body", "label") if c not in columns]
    if missing:
        raise RuntimeError(f"{source['file']}: missing required columns {missing}")
    pool, exclusions, seen = [], collections.Counter(), set()
    rows_total = out_of_scope = 0
    for row in reader:
        rows_total += 1
        label = str(row.get("label") or "").strip()
        if not label:
            exclusions["label-unparseable"] += 1
            continue
        if source.get("select_label") and label != source["select_label"]:
            out_of_scope += 1
            continue
        record, reason = normalize_csv_row(row, source, source["file"])
        if record is None:
            exclusions[reason] += 1
            continue
        if record["content_sha256"] in seen:
            exclusions["duplicate"] += 1
            continue
        seen.add(record["content_sha256"])
        pool.append(record)
    pool.sort(key=lambda r: r["content_sha256"])
    return {"source": source, "url": url, "info": info, "rows_total": rows_total,
            "out_of_scope": out_of_scope, "exclusions": dict(exclusions), "pool": pool,
            "columns": columns}


def apply_caps(union: list[dict], caps: dict | None = None) -> tuple[list[dict], dict, dict]:
    """A2 per-class caps, applied by sorted-hash order (deterministic). Returns
    (included, taken_counts, dropped_counts)."""
    caps = caps if caps is not None else CAPS
    taken: collections.Counter = collections.Counter()
    dropped: collections.Counter = collections.Counter()
    included: list[dict] = []
    for record in union:
        label = record["label"]
        if taken[label] < caps.get(label, 10 ** 9):
            taken[label] += 1
            included.append(record)
        else:
            dropped[label] += 1
    return included, dict(taken), dict(dropped)


def main() -> int:
    if LOCK.exists():
        print(f"lock already present: {LOCK}")
        print("This script refuses to re-sample silently. Delete the lock file to re-acquire.")
        return 1

    SCALE_DIR.mkdir(parents=True, exist_ok=True)
    DOWNLOADS.mkdir(parents=True, exist_ok=True)

    lock_sources, union = [], []
    seen_global: dict[str, str] = {}
    for source in SA_SOURCES + CSV_SOURCES:
        print(f"== {source['name']}: {source['file']}")
        entry = process_sa_source(source) if source.get("file", "").endswith(".tar.bz2") \
            else process_csv_source(source)
        info = entry["info"]
        print(f"   sha256={info['sha256'][:16]}... bytes={info['bytes']} cached={info['cached']}")
        duplicates = 0
        for record in entry["pool"]:
            content_hash = record["content_sha256"]
            if content_hash in seen_global:
                duplicates += 1
                continue
            seen_global[content_hash] = source["name"]
            union.append(record)
        entry["duplicates_across_sources"] = duplicates
        entry.pop("pool")
        entry["kept_after_dedupe"] = sum(1 for r in union if r["source"] == source["name"])
        entry["included_final"] = 0  # filled below (post-cap)
        lock_sources.append(entry)
        print(f"   rows={entry['rows_total']} out_of_scope={entry['out_of_scope']} "
              f"exclusions={entry['exclusions']} kept={sum(1 for r in union if r['source'] == source['name'])} "
              f"dupes_across={duplicates}")

    # A2 per-class caps, deterministic by hash order.
    class_counts = collections.Counter(r["label"] for r in union)
    included, cap_taken, cap_dropped = apply_caps(union)

    for index, record in enumerate(included, start=1):
        record["email_id"] = f"scale-{index:05d}"

    with NORMALIZED.open("w", encoding="utf-8") as handle:
        for record in included:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    by_source = collections.Counter(r["source"] for r in included)
    for entry in lock_sources:
        entry["included_final"] = by_source.get(entry["source"]["name"], 0)

    lock = {
        "corpus": "Jev email-triage SCALE public email corpus (PLAN-addendum-scale.md)",
        "retrieval_date": date.today().isoformat(),
        "sampling": "all eligible rows per source; no per-source sampling",
        "caps": CAPS,
        "sampling_seed_note": f"seed {SAMPLING_SEED} retained for parity; caps truncate by "
                              "content_sha256 sort order (deterministic, seed-independent)",
        "license_and_scope": (
            "Apache SpamAssassin public corpus (distributed publicly for spam-filter testing) and "
            "Zenodo record 8339691 'Phishing Email Curated Datasets' (CC-BY-4.0; Champa, Rabbi & "
            "Zibran - ISDFS 2024 / ICMI 2024; DOI 10.5281/zenodo.8339691). Files are retained "
            "locally under corpus/email/scale/_downloads_scale/ and are NOT redistributed in this "
            "repository; only this lock file (and ids/labels in records) is committed."),
        "exclusion_rules": [
            "unparseable message", "no text/plain or text/html part",
            "body over 100KB", "body under 40 chars", "fewer than 50% ASCII characters",
            "missing or empty Subject header",
            "corpus-conversion artifact (mbox internal-data stub)",
            "duplicate of an earlier message (content sha256; within source and across sources "
            "in frozen source order)",
            "label empty or unparseable (CSV sources)",
        ],
        "determinations": [
            "S7 Nazario.csv schema verified during availability screening 2026-09-17: columns "
            "sender, receiver, date, subject, body, urls, label; all rows label=1; one mbox "
            "internal-data stub observed -> corpus-artifact rule added before freeze.",
            "S12 Ling.csv resolved at build: columns subject, body, label (no sender); label "
            "distribution {0: 2401, 1: 458}; samples confirm Ling-Spam semantics (label 1 = bulk "
            "spam-style mail, label 0 = mailing-list traffic). Included as spam (label==1); "
            "label==0 rows recorded out of scope. 'from' is empty for these rows (source has no "
            "sender field).",
            "Cross-source dedupe is global (first-seen wins in source order S1..S12); duplicate "
            "content from a later source is dropped and counted per source.",
        ],
        "kept_with_note": [
            {"scope": "ling", "note": "no sender field in the source; 'from' recorded as empty string"},
        ],
        "sources": lock_sources,
        "class_counts_before_caps": dict(sorted(class_counts.items())),
        "class_counts_included": dict(sorted(cap_taken.items())),
        "cap_dropped": dict(sorted(cap_dropped.items())),
        "included_total": len(included),
        "repro_command": "python tools/jev_triage/fetch_scale.py",
    }
    LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {len(included)} records -> {NORMALIZED}")
    print(f"wrote lock -> {LOCK}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
