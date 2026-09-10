"""False-positive evaluation of the package lifecycle hook YARA rule.

Runs `rules/yara/developer_malicious_package_hooks.yar` over a corpus of
benign, real-world dependency manifests (`package.json`, `setup.py`) and
reports the measured false-positive rate with a 95% Wilson score binomial
confidence interval.

This measures ONE thing: how often the rule fires on manifests that are not
malicious. It is not a recall or accuracy measurement. No representative,
legally redistributable corpus of malicious manifests exists in this
repository, and quoting a confusion matrix from hand-written positives would
overstate efficacy.

The output JSON records aggregate counts, a taxonomy of which string
combinations caused each match, and the public package names of a bounded
sample of matches. It deliberately records no filesystem paths, so results
gathered from a local dependency tree can be published without disclosing
anything about the machine that produced them.

Usage:
    python tools/evaluate_manifest_corpus.py --corpus <dir> --corpus-label "<description>"
    python tools/evaluate_manifest_corpus.py --corpus <dir> --limit 5000 --no-write
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.swarm.telemetry_replay import wilson_score_interval  # noqa: E402

RULE_PATH = ROOT / "rules" / "yara" / "developer_malicious_package_hooks.yar"
RESULTS_PATH = ROOT / "docs" / "detections" / "evaluation-package-manifests.json"
MANIFEST_NAMES = ("package.json", "setup.py")
SAMPLE_LIMIT = 25

# Matched string identifiers grouped by the role they play in the rule
# condition, so a match can be explained rather than merely counted.
HOOK_PREFIX = "$hook_"
EXEC_PREFIX = "$exec_"
NET_DOWNLOADER = ("$net_curl", "$net_wget", "$net_urllib")
NET_SCHEME = ("$net_http", "$net_https")


class CorpusError(RuntimeError):
    """The supplied corpus is missing or unusable."""


def collect_manifests(corpus: Path, limit: int | None) -> list[Path]:
    if not corpus.is_dir():
        raise CorpusError(f"corpus directory not found: {corpus}")
    found: list[Path] = []
    for name in MANIFEST_NAMES:
        for path in corpus.rglob(name):
            if path.is_file():
                found.append(path)
                if limit is not None and len(found) >= limit:
                    return sorted(found)
    if not found:
        raise CorpusError(f"no {' or '.join(MANIFEST_NAMES)} files under {corpus}")
    return sorted(found)


def package_identity(path: Path) -> str:
    """Public package name for a manifest, or its bare filename.

    Never returns a filesystem path, so results stay publishable.
    """
    if path.name == "package.json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return "<unparseable package.json>"
        name = data.get("name")
        version = data.get("version")
        if isinstance(name, str) and name:
            return f"{name}@{version}" if isinstance(version, str) and version else name
        return "<unnamed package.json>"
    return path.name


def classify(matched_strings: set[str]) -> str:
    """Explain which branch of the rule condition a match satisfied."""
    hooks = sorted(s for s in matched_strings if s.startswith(HOOK_PREFIX))
    execs = sorted(s for s in matched_strings if s.startswith(EXEC_PREFIX))
    downloaders = sorted(s for s in matched_strings if s in NET_DOWNLOADER)
    hook_label = ",".join(h[len(HOOK_PREFIX):] for h in hooks) or "none"
    if execs:
        branch = "exec:" + ",".join(e[len(EXEC_PREFIX):] for e in execs)
    elif downloaders:
        branch = "net:" + ",".join(d.removeprefix("$net_") for d in downloaders)
    else:
        branch = "unknown"
    return f"hook:{hook_label}|{branch}"


def matched_string_ids(match) -> set[str]:
    """String identifiers involved in a yara match, across API versions."""
    ids: set[str] = set()
    for entry in getattr(match, "strings", []):
        identifier = getattr(entry, "identifier", None)
        if identifier is None and isinstance(entry, tuple) and len(entry) >= 2:
            identifier = entry[1]
        if isinstance(identifier, bytes):
            identifier = identifier.decode("utf-8", errors="replace")
        if identifier:
            ids.add(identifier)
    return ids


def evaluate(corpus: Path, limit: int | None) -> dict:
    if not RULE_PATH.is_file():
        raise CorpusError(f"rule not found: {RULE_PATH}")
    rules = yara.compile(filepath=str(RULE_PATH))
    manifests = collect_manifests(corpus, limit)

    scanned = 0
    unreadable = 0
    false_positives = 0
    taxonomy: Counter[str] = Counter()
    by_manifest_type: Counter[str] = Counter()
    samples: list[dict] = []

    for path in manifests:
        try:
            data = path.read_bytes()
        except OSError:
            unreadable += 1
            continue
        scanned += 1
        by_manifest_type[path.name] += 1
        try:
            matches = rules.match(data=data)
        except yara.Error:
            unreadable += 1
            scanned -= 1
            by_manifest_type[path.name] -= 1
            continue
        if not matches:
            continue
        false_positives += 1
        reason = classify(matched_string_ids(matches[0]))
        taxonomy[reason] += 1
        if len(samples) < SAMPLE_LIMIT:
            samples.append({"package": package_identity(path), "reason": reason})

    rate = false_positives / scanned if scanned else 0.0
    ci_low, ci_high = wilson_score_interval(false_positives, scanned) if scanned else (0.0, 0.0)

    return {
        "measurement": "benign_false_positive_rate",
        "rule": RULE_PATH.name,
        "scanned_manifests": scanned,
        "unreadable_manifests": unreadable,
        "manifests_by_filename": dict(sorted(by_manifest_type.items())),
        "false_positives": false_positives,
        "false_positive_rate": round(rate, 6),
        "wilson_ci_95": [round(ci_low, 6), round(ci_high, 6)],
        "match_taxonomy": dict(taxonomy.most_common()),
        "sample_matches": samples,
        "sample_limit": SAMPLE_LIMIT,
        "not_measured": [
            "recall against real malicious manifests",
            "precision in a production ingress pipeline",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", required=True, type=Path, help="directory to walk for manifests")
    parser.add_argument(
        "--corpus-label",
        default="unlabeled local dependency tree",
        help="human description of the corpus, recorded in the results file",
    )
    parser.add_argument("--limit", type=int, default=None, help="stop after N manifests")
    parser.add_argument("--no-write", action="store_true", help="print results without writing the JSON")
    args = parser.parse_args(argv)

    try:
        results = evaluate(args.corpus, args.limit)
    except CorpusError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    results["corpus_label"] = args.corpus_label
    results["evaluated"] = date.today().isoformat()

    fp = results["false_positives"]
    n = results["scanned_manifests"]
    lo, hi = results["wilson_ci_95"]
    print(f"corpus:            {args.corpus_label}")
    print(f"manifests scanned: {n}")
    print(f"false positives:   {fp} ({results['false_positive_rate'] * 100:.2f}%)")
    print(f"95% Wilson CI:     [{lo * 100:.2f}%, {hi * 100:.2f}%]")
    if results["match_taxonomy"]:
        print("match taxonomy:")
        for reason, count in results["match_taxonomy"].items():
            print(f"  {count:>6}  {reason}")

    if not args.no_write:
        RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        disp = RESULTS_PATH.relative_to(ROOT) if RESULTS_PATH.is_relative_to(ROOT) else RESULTS_PATH
        print(f"\nwrote {disp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
