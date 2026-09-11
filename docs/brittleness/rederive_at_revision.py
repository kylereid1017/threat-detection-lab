"""Re-derive a brittleness measurement at a pinned corpus revision.

The live CLI (``tools.brittleness.cli --git-corpus``) always scores the corpus
HEAD, so regenerating a report produces figures for *today's* revision. To
reproduce a specific published figure, the run has to be re-derived at the
revision that report records - that is what this helper does.

Same mechanism as the CLI: bare clone, stream every rule out of git object
storage via ``git cat-file --batch`` (no rule text is written to the
filesystem), score with ``tools.brittleness.metrics``.

    python docs/brittleness/rederive_at_revision.py \\
        https://github.com/SigmaHQ/sigma rules/ 272daf82bf77fb0bb97f1f0c4d82bc61154772e1

If the shallow fetch of the pinned revision fails (a server that refuses
fetches by object id), the helper falls back to a full clone, which carries
every ancestor of the default branch.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.brittleness.git_corpus import _batch_read, _force_rmtree, _git  # noqa: E402
from tools.brittleness.metrics import analyze_text, summarize  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    url, prefix, revision = args
    destination = Path(tempfile.gettempdir()) / "tdl-rule-corpus-pinned"
    _force_rmtree(destination)
    try:
        print(f"[*] shallow clone of {url}")
        _git(["clone", "--bare", "--depth", "1", url, str(destination)])
        try:
            _git(["fetch", "--depth", "1", "origin", revision], cwd=destination)
        except Exception:
            print("[*] fetch-by-id refused; falling back to a full clone")
            _force_rmtree(destination)
            _git(["clone", "--bare", url, str(destination)])
        resolved = _git(["rev-parse", f"{revision}^{{commit}}"], cwd=destination).strip()
        _git(["update-ref", "HEAD", resolved], cwd=destination)
        listing = _git(["ls-tree", "-r", "--name-only", "HEAD"], cwd=destination)
        wanted = [
            line
            for line in listing.splitlines()
            if line.startswith(prefix) and line.endswith((".yml", ".yaml"))
        ]
        files = list(_batch_read(destination, wanted))
        print(f"[*] revision {resolved[:12]}: {len(files)} of {len(wanted)} files read")
        results = [analyze_text(text, name) for name, text in files]
        report = summarize(results, f"pinned@{resolved[:12]}")
        bands = report["band_counts"]
        print(f"rules scored:        {report['rules_scored']} ({report['rules_skipped']} skipped)")
        print(f"composite mean:      {report['composite_mean']:.4f}")
        print(
            f"bands:               durable {bands['durable']}, "
            f"conditional {bands['conditional']}, fragile {bands['fragile']}"
        )
        print(f"command-line bound:  {report['share_commandline_dependent'] * 100:.2f}% of rules")
        print(f"lineage bound:       {report['share_lineage_dependent'] * 100:.2f}% of rules")
        print(f"documentation gap:   {report['dimension_means']['documentation_gap']:.4f}")
        return 0
    finally:
        _force_rmtree(destination)


if __name__ == "__main__":
    raise SystemExit(main())
