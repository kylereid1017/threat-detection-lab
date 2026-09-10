"""Score a Sigma rule corpus for durability.

    python -m tools.brittleness.cli --rules rules/sigma --label "threat-detection-lab"
    python -m tools.brittleness.cli --rules <path> --out docs/brittleness/report.json

Runs against any Sigma corpus, including one written by someone else. That is the
point of building it as a measuring instrument rather than another detection.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.brittleness.git_corpus import CorpusError, read_rule_corpus  # noqa: E402
from tools.brittleness.metrics import analyze_corpus, analyze_text, summarize  # noqa: E402

DEFAULT_RULES = ROOT / "rules" / "sigma"
DEFAULT_OUT = ROOT / "docs" / "brittleness"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument(
        "--git-corpus",
        metavar="URL",
        help="analyze a remote rule corpus from git object storage, without "
        "writing any rule text to disk",
    )
    parser.add_argument("--path-prefix", default="", help="restrict --git-corpus to a subtree")
    parser.add_argument("--label", default="", help="corpus name recorded in the report")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument(
        "--max-rules-in-report",
        type=int,
        default=250,
        help="cap per-rule detail in the written report; the summary always covers "
        "every rule scored",
    )
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)

    corpus_read = None
    if args.git_corpus:
        try:
            corpus_read = read_rule_corpus(args.git_corpus, path_prefix=args.path_prefix)
        except CorpusError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 2
        label = args.label or args.git_corpus.rstrip("/").split("/")[-1]
        results = [analyze_text(text, name) for name, text in corpus_read.files]
    else:
        if not args.rules.is_dir():
            print(f"[-] no rule directory at {args.rules}", file=sys.stderr)
            return 2
        label = args.label or args.rules.name
        results = analyze_corpus(args.rules)

    report = summarize(results, label)
    report["generated"] = date.today().isoformat()
    if corpus_read:
        report["acquisition"] = corpus_read.to_dict()
    scored = [r for r in results if not r.parse_error]
    ranked = sorted(scored, key=lambda r: -r.composite)
    # The summary is computed over every rule. Per-rule detail is capped so a
    # 3,000-rule public corpus does not produce a multi-megabyte artifact whose
    # bulk is repetition.
    report["rules"] = [r.to_dict() for r in ranked[: args.max_rules_in_report]]
    report["rules_detail_note"] = (
        f"Per-rule detail is limited to the {args.max_rules_in_report} most fragile "
        f"of {len(scored)} scored rules. Every aggregate above covers all of them."
    )

    if not report.get("rules_scored"):
        print(f"[-] no scoreable rules under {args.rules}", file=sys.stderr)
        return 2

    print(f"corpus:              {label}")
    if corpus_read:
        print(f"revision:            {corpus_read.revision[:12]}")
        print(f"files listed/read:   {corpus_read.listed}/{len(corpus_read.files)}")
    print(f"rules scored:        {report['rules_scored']} ({report['rules_skipped']} skipped)")
    print(f"composite mean:      {report['composite_mean']:.3f}")
    bands = report["band_counts"]
    print(
        f"bands:               durable {bands['durable']}, "
        f"conditional {bands['conditional']}, fragile {bands['fragile']}"
    )
    print(f"command-line bound:  {report['share_commandline_dependent'] * 100:.1f}% of rules")
    print(f"lineage bound:       {report['share_lineage_dependent'] * 100:.1f}% of rules")
    print("\ndimension means:")
    for key, value in sorted(report["dimension_means"].items(), key=lambda kv: -kv[1]):
        print(f"  {value:.3f}  {key}")

    print(f"\nmost fragile (top {args.top}):")
    for entry in report["most_fragile"][: args.top]:
        print(f"  {entry['composite']:.3f}  {entry['band']:<12} {entry['title'][:58]}")
        for observation in entry["observations"][:2]:
            print(f"           - {observation}")

    if not args.no_write:
        args.out.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
        path = args.out / f"brittleness_{safe}.json"
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        disp = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        print(f"\nwrote {disp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
