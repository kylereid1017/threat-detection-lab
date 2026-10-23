"""Cascade cost projection for Claude tiers (experiment #1 economics).

MEASURED quantities: per-email input/output token counts (DeepSeek run), Jev run
costs, escalation fractions from the Jev->DeepSeek cascade sweep.
PROJECTED quantities: Claude-tier costs, computed as measured token counts x
vendor list prices. Claude tokenization differs from DeepSeek's; there are no
live Claude runs in this experiment (API credits unavailable), so Claude
accuracy and latency on this corpus are NOT measured and do NOT appear below.

Run:  python tools/jev_triage/cost_projection.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402
import score  # noqa: E402

OUT = REPO / "docs" / "research" / "jev-email-triage" / "COST_PROJECTION.md"
RESULTS = REPO / "docs" / "research" / "jev-email-triage" / "results.json"

THRESHOLDS = [0.30, 0.50, 0.75]
CLAUDE_TIERS = ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-5", "claude-fable-5-1"]


def main() -> int:
    runs = score.load_runs()
    excluded = score.load_exclusions()
    jev = next(r for r in runs.values() if r["meta"].get("provider") == "typesafe")
    llm = next(r for r in runs.values() if r["meta"].get("provider") == "deepseek")

    def clean(run):
        return [r for r in run["observations"]
                if r["email_id"] not in excluded and not r.get("error")
                and r.get("label_pred") in score.LABELS]

    llm_rows = clean(llm)
    n = len(llm_rows)
    mean_in = sum(r["input_tokens"] or 0 for r in llm_rows) / n
    mean_out = sum(r["output_tokens"] or 0 for r in llm_rows) / n
    jev_rows = clean(jev)
    jev_cost_all = sum(score.email_cost(r, clients.PRICING["jev-latest"]) for r in jev_rows)

    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    cascade = next(iter(results["cascades"].values()))
    sweep = {round(row["threshold"], 2): row for row in cascade["sweep"]}

    lines = ["# Cascade cost projection — Jev in front of Claude tiers", "",
             f"Basis: {n} emails, measured mean {mean_in:.0f} input / {mean_out:.0f} output tokens "
             "(DeepSeek tokenizer, used as the token-count basis for every tier).",
             f"Jev cost for all traffic: ${jev_cost_all / n * 1000:.4f}/1k emails (measured).",
             "",
             "**Projection method:** Claude cost = measured tokens x vendor list prices "
             "(clients.py PRICING, accessed 2026-09-17). No live Claude runs exist in this "
             "experiment (API credits unavailable), so Claude accuracy/latency on this corpus "
             "is NOT measured. Token-count basis: DeepSeek tokenizer as a proxy; Claude's "
             "tokenizer will differ by roughly 10-20% on English text.",
             "",
             "| tier | pure $/1k | cascade $/1k @0.30 | savings | cascade $/1k @0.50 | savings | cascade $/1k @0.75 | savings |",
             "|---|---|---|---|---|---|---|---|"]
    for tier in CLAUDE_TIERS:
        pricing = clients.PRICING[tier]
        pure = (mean_in * pricing["input"] + mean_out * pricing["output"]) / 1e6 * 1000
        cells = []
        for threshold in THRESHOLDS:
            row = sweep[threshold]
            escalated_share = row["escalated"] / n
            cascade_per_1k = jev_cost_all / n * 1000 + escalated_share * pure
            savings = (1 - cascade_per_1k / pure) * 100
            cells += [f"${cascade_per_1k:.4f}", f"{savings:.0f}%"]
        lines.append(f"| {tier} | ${pure:.4f} | " + " | ".join(cells) + " |")

    lines += ["",
              "Measured comparison (same corpus, real runs): Jev alone $0.0414/1k at 224ms p50; "
              "DeepSeek alone $0.0983/1k at 894ms p50; Jev->DeepSeek cascade at t=0.30 "
              f"${sweep[0.30]['cascade_per_1000']:.4f}/1k with {sweep[0.30]['auto_coverage'] * 100:.1f}% "
              "auto-decided.",
              "",
              "Latency shape (measured for Jev; projected for Claude): auto-decided traffic "
              "returns in ~0.22s; escalated traffic pays Jev + Claude. Blend at t=0.30 is "
              "~0.22s for about two thirds of traffic.",
              ""]

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
