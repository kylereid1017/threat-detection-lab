"""Reproducible evaluation of the active-content SVG rule.

Reports two separate, clearly-labeled measurements:

1. benign_corpus: matches against a pinned, permissively licensed public
   SVG collection (false-positive measurement on benign artwork only);
2. synthetic_fixtures: coverage of inert hand-written positives.

It deliberately does NOT compute accuracy or recall: no representative,
legally redistributable malicious corpus exists here, and quoting a
"confusion matrix" from synthetic positives would overstate efficacy.

Usage:
    python tools/evaluate_rule.py            # requires corpus/benign
    python tools/evaluate_rule.py --no-corpus  # fixtures-only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "rules" / "yara" / "suspicious_active_content_svg.yar"
FIXTURE_POS = ROOT / "tests" / "fixtures" / "positive"
FIXTURE_NEG = ROOT / "tests" / "fixtures" / "negative"
CORPUS_DIR = ROOT / "corpus" / "benign"
CORPUS_LOCK = ROOT / "corpus" / "acquisition-lock.json"
RESULTS_PATH = ROOT / "docs" / "detections" / "evaluation-benign-corpus.json"
EXPECTED_RULE = "Suspicious_Active_Content_SVG_Attachment"


class ProvenanceError(RuntimeError):
    """Corpus provenance or integrity verification failed."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path: Path, expected: str) -> None:
    actual = sha256_file(path)
    if actual.lower() != expected.lower():
        raise ProvenanceError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")


def confusion(positives, negatives):
    """positives/negatives: iterable of (name, matched: bool)."""
    counts = {
        "true_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
        "false_positives": 0,
    }
    for _name, matched in positives:
        counts["true_positives" if matched else "false_negatives"] += 1
    for _name, matched in negatives:
        counts["false_positives" if matched else "true_negatives"] += 1
    return counts


def verify_corpus_provenance() -> dict:
    if not CORPUS_LOCK.is_file():
        raise ProvenanceError(f"missing acquisition lock: {CORPUS_LOCK}")
    lock = json.loads(CORPUS_LOCK.read_text(encoding="utf-8"))
    for key in ("source_url", "upstream_version", "archive_sha256", "license", "retrieval_date", "file_count"):
        if not lock.get(key):
            raise ProvenanceError(f"acquisition lock missing field: {key}")
    if not CORPUS_DIR.is_dir():
        raise ProvenanceError(f"corpus directory missing: {CORPUS_DIR}")
    return lock


def scan_dir(rules, directory: Path):
    results = []
    for svg in sorted(directory.rglob("*.svg")):
        matched = EXPECTED_RULE in {m.rule for m in rules.match(str(svg))}
        results.append((svg.name, matched, sha256_file(svg)))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-corpus", action="store_true",
                        help="evaluate synthetic fixtures only")
    args = parser.parse_args()

    rules = yara.compile(filepath=str(RULE_PATH))
    report = {
        "rule": EXPECTED_RULE,
        "evaluated_on": date.today().isoformat(),
        "synthetic_fixtures": {},
        "benign_corpus": None,
        "notes": [],
    }

    pos = scan_dir(rules, FIXTURE_POS)
    neg = scan_dir(rules, FIXTURE_NEG)
    pos_counts = confusion([(n, m) for n, m, _ in pos], [])
    neg_counts = confusion([], [(n, m) for n, m, _ in neg])
    report["synthetic_fixtures"] = {
        "positives": {"count": len(pos), "matched": pos_counts["true_positives"],
                      "missed": [n for n, m, _ in pos if not m]},
        "negatives": {"count": len(neg), "matched": neg_counts["false_positives"],
                      "fired": [n for n, m, _ in neg if m]},
        "disclaimer": ("Synthetic fixtures demonstrate intended behavior only; "
                       "they are not a representative malicious corpus."),
    }

    if not args.no_corpus:
        try:
            lock = verify_corpus_provenance()
        except ProvenanceError as exc:
            print(f"PROVENANCE ERROR: {exc}", file=sys.stderr)
            return 2
        corpus = scan_dir(rules, CORPUS_DIR)
        fps = [n for n, m, _ in corpus if m]
        report["benign_corpus"] = {
            "source_url": lock["source_url"],
            "upstream_version": lock["upstream_version"],
            "archive_sha256": lock["archive_sha256"],
            "license": lock["license"],
            "retrieval_date": lock["retrieval_date"],
            "files_scanned": len(corpus),
            "declared_file_count": lock["file_count"],
            "false_positives": len(fps),
            "false_positive_files": fps,
            "disclaimer": ("False positives measured on benign icon/artwork SVGs only. "
                           "No accuracy or recall is reported because no representative "
                           "malicious corpus is available."),
        }
        report["notes"].append(
            "A static icon collection measures benign-artwork false positives, "
            "not real-world phishing detection efficacy.")

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2))
    print(f"\nResults written to {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())