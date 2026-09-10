"""Command line entry point for the CTI collection and enrichment pipeline.

    python -m tools.cti.cli --snapshots tests/fixtures/cti/snapshots --out docs/cti/results
    python -m tools.cti.cli --snapshots <dir> --summary-only
    python -m tools.cti.cli --score anthropic-careers.invalid
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.cti import emit  # noqa: E402
from tools.cti.pipeline import CtiPipeline  # noqa: E402
from tools.cti.relevance import score_indicator  # noqa: E402

DEFAULT_SNAPSHOTS = ROOT / "tests" / "fixtures" / "cti" / "snapshots"
DEFAULT_OUT = ROOT / "docs" / "cti" / "results"


def cmd_score(value: str) -> int:
    verdict = score_indicator(value)
    print(f"indicator: {value}")
    print(f"relevance: {verdict.score:.2f}")
    print(f"triage:    {verdict.is_triage_worthy}")
    print(f"priority:  {verdict.is_priority}")
    if verdict.reasons:
        print("reasons:")
        for reason in verdict.reasons:
            print(f"  - {reason}")
    else:
        print("reasons:   none; no signal in the frontier AI lab threat model")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--snapshots", type=Path, default=DEFAULT_SNAPSHOTS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--produced", default="", help="ISO date recorded in provenance")
    parser.add_argument("--summary-only", action="store_true", help="do not write artifacts")
    parser.add_argument("--score", metavar="VALUE", help="score one indicator and exit")
    parser.add_argument("--top", type=int, default=10, help="rows of the queue to print")
    args = parser.parse_args(argv)

    if args.score:
        return cmd_score(args.score)

    pipeline = CtiPipeline(args.snapshots, produced=args.produced)
    report = pipeline.run()
    summary = report.summary()

    print(f"records read:       {summary['records_read']}")
    print(f"raw indicators:     {summary['raw_indicators']}")
    print(f"unique indicators:  {summary['unique_indicators']}")
    print(f"triage queue:       {summary['triage_indicators']}")
    print(f"priority:           {summary['priority_indicators']}")
    print(f"queue reduction:    {summary['reduction_ratio'] * 100:.1f}% of unique indicators dropped")
    print(f"clusters:           {summary['graph']['cluster_count']}")

    failed = [r for r in report.collection if r.error]
    for result in failed:
        print(f"  source error: {result.source}: {result.error}", file=sys.stderr)
    skipped = sum(r.records_skipped for r in report.collection)
    if skipped:
        print(f"  records skipped: {skipped}", file=sys.stderr)

    if report.triage_queue:
        print("\ntop of queue:")
        for indicator in report.triage_queue[: args.top]:
            reason = indicator.relevance_reasons[0] if indicator.relevance_reasons else ""
            print(f"  {indicator.relevance:.2f}  {indicator.key:<52} {reason}")

    if not args.summary_only:
        written = pipeline.write_outputs(report, args.out)
        print("\nwrote:")
        for label, path in written.items():
            try:
                shown = path.relative_to(ROOT)
            except ValueError:
                shown = path
            print(f"  {label}: {shown}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
