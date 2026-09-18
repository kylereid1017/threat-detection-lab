"""Generate COST_MODEL.md — measured cascade economics, with the pre-measurement projection kept alongside.

Reads docs/research/jev-email-triage/results.json (recomputed by score.py from raw
records) plus the frozen projection table from COST_PROJECTION.md (pre-measurement
artifact, values cited here as constants for comparison only).

Run:  python tools/jev_triage/cost_model.py   (after score.py)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT_DIR = REPO / "docs" / "research" / "jev-email-triage"
RESULTS = OUT_DIR / "results.json"
RECORDS = OUT_DIR / "records"
OUT = OUT_DIR / "COST_MODEL.md"

TIERS = [
    ("claude-haiku-4.5", "haiku", "claude-haiku-4-5", "claude-haiku-4-5"),
    ("claude-sonnet-5", "sonnet", "claude-sonnet-5", "claude-sonnet-5"),
    ("claude-opus-5", "opus", "claude-opus-5", "claude-opus-5"),
    ("claude-fable-5.1", "fable", "claude-fable-5_1", "claude-fable-5-1"),
]

# Frozen projection (COST_PROJECTION.md, pre-measurement, 2026-09-17):
# tier -> (pure $/1k, cascade $/1k @0.30, savings @0.30, savings @0.50, savings @0.75)
PROJECTED = {
    "claude-haiku-4-5": (0.6696, 0.2771, 59, 50, 35),
    "claude-sonnet-5": (1.3392, 0.5129, 62, 53, 38),
    "claude-opus-5": (3.3479, 1.2200, 64, 55, 40),
    "claude-fable-5-1": (6.6958, 2.3986, 64, 56, 41),
}

sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
import clients  # noqa: E402
from score import email_cost  # noqa: E402


def run_pricing(path: Path) -> dict:
    """Per-run pricing: read model_requested from the run's meta line (row-level
    field is absent in pre-patch rows; meta is authoritative)."""
    with path.open(encoding="utf-8") as fh:
        first = json.loads(fh.readline())
    return clients.PRICING.get(first.get("model_requested"), {})


def scan_retired_spend() -> tuple[float, int]:
    """Spend from retired run files: exact where billed, modeled otherwise."""
    total = 0.0
    n = 0
    retired = RECORDS / "retired"
    if not retired.is_dir():
        return total, n
    for path in sorted(retired.glob("*.jsonl")):
        pricing = run_pricing(path)
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") != "observation" or row.get("error"):
                continue
            total += email_cost(row, pricing)
            n += 1
    return total, n


def find_run(summaries: dict, sizes: dict, needle: str, corpus_size: int) -> tuple[str, dict] | None:
    candidates = [(name, s) for name, s in summaries.items()
                  if needle in str(s.get("model", "")).lower()
                  and sizes.get(name) == corpus_size]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def nearest(rows: list[dict], threshold: float) -> dict | None:
    best = None
    for row in rows:
        if row.get("threshold") is None:
            continue
        if abs(row["threshold"] - threshold) < 0.001:
            best = row
    return best


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{(1 - x) * 100:.0f}%"


def main() -> int:
    if not RESULTS.exists():
        print("results.json not found — run score.py first")
        return 1
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    summaries = data["summaries"]
    cascades = data["cascades"]
    sizes = {r["run"]: r["expected"] for r in data["reconciliation"]}

    lines = [
        "# Cascade cost model — measured (Jev in front of Claude tiers via Nous Portal)",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()} · recomputed from raw records; "
        "Portal-routed runs, 2026-09-17.",
        "",
        "Basis: 196 scored emails (200 minus 4 audit exclusions, uniform across runs). Claude calls "
        "went through a local proxy to Nous Portal; token counts and `usage.cost` are the "
        "provider's own billing figures, and spot checks matched Anthropic list prices exactly "
        "(e.g. opus probe: 29 prompt tok x $5/M = $0.000145 billed).",
        "",
        "## Pure-model economics (measured)",
        "",
        "| tier | n | accuracy | attack recall | p50 ms | $/email | $/1k |",
        "|---|---|---|---|---|---|---|",
    ]

    rows_by_tier: dict[str, dict] = {}
    for model_key, needle, proj_key, _fname in TIERS:
        found = find_run(summaries, sizes, needle, 200) or find_run(summaries, sizes, needle, 60)
        if not found:
            lines.append(f"| {model_key} | — | not run | — | — | — | — |")
            continue
        name, s = found
        rows_by_tier[model_key] = {"run": name, "summary": s}
        subset = (s.get("corpus_size") or 0) == 60
        acc = f"{s['accuracy'] * 100:.1f}%" if s.get("accuracy") is not None else "n/a"
        recall = s["per_class"]["attack"]["recall"]
        recall_s = f"{recall * 100:.0f}%" if recall is not None else "n/a"
        p50 = s["latency_ms"]["p50"]
        per_email = s["cost"]["per_email_usd_mean"]
        per_1k = s["cost"]["per_1000_usd"]
        tag = " (60-email subset)" if subset else ""
        lines.append(
            f"| {model_key}{tag} | {s['scored']} | {acc} | {recall_s} | "
            f"{p50:.0f} | ${per_email:.6f} | ${per_1k:.4f} |")

    lines += [
        "",
        "DeepSeek V4.1 Flash (measured, direct API): $0.000141/email, $0.1406/1k, 69.4% accuracy — "
        "for the full comparison see RESULTS.md.",
        "",
        "## Cascade: Jev → tier (measured LLM answers)",
        "",
        "Operational threshold = the highest auto-decide cutoff with zero attack→safe misroutes; "
        "Jev cost for all traffic included in every row.",
        "",
        "| tier | threshold | auto % | auto err % | missed attacks | final acc | cascade $/1k | pure $/1k | savings | projected savings @0.30 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for model_key, needle, proj_key, _fname in TIERS:
        entry = rows_by_tier.get(model_key)
        if not entry:
            continue
        cascade = cascades.get(entry["run"])
        if not cascade or not cascade.get("recommended_operational"):
            lines.append(f"| {model_key} | — | cascade not available (subset run) | | | | | | |")
            continue
        op = cascade["recommended_operational"]
        savings = pct(op["cascade_per_1000"] / op["pure_llm_per_1000"]) if op["pure_llm_per_1000"] else "n/a"
        proj = PROJECTED.get(proj_key)
        final_acc = f"{op['final_accuracy'] * 100:.1f}%" if op.get("final_accuracy") is not None else "n/a"
        lines.append(
            f"| {model_key} | {op['threshold']:.2f} | {(op['auto_coverage'] or 0) * 100:.1f}% | "
            f"{(op['auto_error_rate'] or 0) * 100:.2f}% | {op['auto_missed_attack']} | "
            f"{final_acc} | ${op['cascade_per_1000']:.4f} | "
            f"${op['pure_llm_per_1000']:.4f} | {savings} | {proj[2]}% |")

    # Spend accounting across every Portal run this session (records + retired).
    spend = 0.0
    rows_counted = 0
    per_run: list[tuple[str, float, int]] = []
    for path in sorted(RECORDS.glob("portal-*.jsonl")):
        pricing = run_pricing(path)
        run_total = 0.0
        run_rows = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") != "observation" or row.get("error"):
                continue
            run_total += email_cost(row, pricing)
            run_rows += 1
        per_run.append((path.name, run_total, run_rows))
        spend += run_total
        rows_counted += run_rows
    retired_total, retired_rows = scan_retired_spend()
    if retired_rows:
        per_run.append(("retired/ (superseded fable pass)", retired_total, retired_rows))
        spend += retired_total
        rows_counted += retired_rows

    lines += [
        "",
        "## Portal spend this session (tracked)",
        "",
        "| run | observations | $ (billed where returned, else list-rate) |",
        "|---|---|---|",
    ]
    for name, total, n in per_run:
        lines.append(f"| {name} | {n} | ${total:.4f} |")
    lines += [
        f"| **total tracked** | **{rows_counted}** | **${spend:.4f}** |",
        "",
        "Balance check: the portal shows $3.36; if the portal UI total agrees with the table above "
        "(± a few cents for earlier probes), the accounting is confirmed end to end.",
        "",
        "## Latency shape",
        "",
        "Auto-decided traffic returns in Jev's ~0.22s p50; escalated traffic pays Jev + tier latency. "
        "Blend depends on the auto-decide share above.",
    ]

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"tracked portal spend: ${spend:.4f} over {rows_counted} observations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
