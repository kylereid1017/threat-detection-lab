"""Score the Jev email-triage runs: effectiveness, calibration, cascade economics.

Reads append-only raw records (docs/research/jev-email-triage/records/*.jsonl) and
recomputes every published figure from them. No figure is hand-maintained here.

Outputs
  docs/research/jev-email-triage/results.json    (machine-readable aggregates)
  docs/research/jev-email-triage/RESULTS.md      (report tables)

Run:  python tools/jev_triage/score.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RECORDS_DIR = REPO / "docs" / "research" / "jev-email-triage" / "records"
OUT_DIR = REPO / "docs" / "research" / "jev-email-triage"
AUDIT = REPO / "corpus" / "email" / "corpus-audit.json"
LABELS = ["safe", "gray", "spam", "attack"]


def load_exclusions() -> set[str]:
    if not AUDIT.exists():
        return set()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    return {entry["email_id"] for entry in audit.get("excluded_from_primary_metrics", [])}

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402


def load_runs() -> dict[str, dict]:
    runs: dict[str, dict] = {}
    for path in sorted(RECORDS_DIR.glob("*.jsonl")):
        meta, observations = None, []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "run_meta":
                meta = row
            elif row.get("kind") == "observation":
                observations.append(row)
        if meta is None:
            continue
        runs[path.name] = {"meta": meta, "path": path, "observations": observations}
    return runs


def is_peak(ts_utc: str) -> bool:
    """DeepSeek peak = 01:00-04:00 and 06:00-10:00 UTC, Mon-Fri."""
    dt = datetime.fromisoformat(ts_utc)
    if dt.weekday() >= 5:
        return False
    hour = dt.hour
    return 1 <= hour < 4 or 6 <= hour < 10


def email_cost(row: dict, pricing: dict) -> float:
    if row.get("cost_usd") is not None:
        # Exact billed cost reported by the provider (Portal returns usage.cost).
        return float(row["cost_usd"])
    input_tokens = row.get("input_tokens") or 0
    output_tokens = row.get("output_tokens") or 0
    peak = is_peak(row["ts_utc"]) and "input_peak" in pricing
    input_price = pricing.get("input_peak" if peak else "input", 0.0)
    output_price = pricing.get("output_peak" if peak else "output", 0.0)
    return input_tokens / 1e6 * input_price + output_tokens / 1e6 * output_price


def confusion(observations: list[dict]) -> dict:
    matrix = {t: {p: 0 for p in LABELS} for t in LABELS}
    for row in observations:
        if row.get("error") or row.get("label_pred") not in LABELS:
            continue
        matrix[row["label_true"]][row["label_pred"]] += 1
    return matrix


def per_class(matrix: dict) -> dict:
    out = {}
    for label in LABELS:
        tp = matrix[label][label]
        actual = sum(matrix[label].values())
        predicted = sum(matrix[t][label] for t in LABELS)
        out[label] = {
            "support": actual,
            "tp": tp,
            "precision": (tp / predicted) if predicted else None,
            "recall": (tp / actual) if actual else None,
        }
    return out


def accuracy(matrix: dict) -> float | None:
    total = sum(sum(row.values()) for row in matrix.values())
    correct = sum(matrix[label][label] for label in LABELS)
    return (correct / total) if total else None


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))
    return ordered[index]


def summarize_run(run: dict) -> dict:
    meta = run["meta"]
    observations = run["observations"]
    clean = [r for r in observations if not r.get("error") and r.get("label_pred") in LABELS]
    matrix = confusion(observations)
    pricing = clients.PRICING.get(meta["model_requested"]) or clients.PRICING.get("jev-latest", {})
    latencies = [r["latency_ms"] for r in clean if r.get("latency_ms")]
    costs = [email_cost(r, pricing) for r in clean]
    errors = [r for r in observations if r.get("error")]
    by_source = {}
    for row in clean:
        src = row.get("source") or "unknown"
        bucket = by_source.setdefault(src, {"n": 0, "correct": 0})
        bucket["n"] += 1
        bucket["correct"] += 1 if row["label_pred"] == row["label_true"] else 0
    by_source = {k: {"n": v["n"], "accuracy": v["correct"] / v["n"]}
                 for k, v in sorted(by_source.items())}
    return {
        "run_id": meta.get("run_id"),
        "file": run["path"].name,
        "provider": meta.get("provider"),
        "model": meta.get("model_requested"),
        "by_source": by_source,
        "observations": len(observations),
        "scored": len(clean),
        "errors": len(errors),
        "accuracy": accuracy(matrix),
        "confusion": matrix,
        "per_class": per_class(matrix),
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "mean": (sum(latencies) / len(latencies)) if latencies else None,
        },
        "cost": {
            "total_usd": sum(costs),
            "per_email_usd_mean": (sum(costs) / len(costs)) if costs else None,
            "per_1000_usd": (sum(costs) / len(costs) * 1000) if costs else None,
        },
        "tokens": {
            "input_total": sum(r.get("input_tokens") or 0 for r in clean),
            "output_total": sum(r.get("output_tokens") or 0 for r in clean),
        },
    }


def calibration(observations: list[dict]) -> list[dict]:
    buckets = []
    for lo in [i / 10 for i in range(10)]:
        hi = lo + 0.1
        rows = [r for r in observations
                if not r.get("error") and r.get("confidence") is not None
                and lo <= r["confidence"] < (hi if hi < 1 else 1.0001)]
        if not rows:
            buckets.append({"bucket": f"{lo:.1f}-{hi:.1f}", "n": 0, "accuracy": None})
            continue
        correct = sum(1 for r in rows if r["label_pred"] == r["label_true"])
        buckets.append({"bucket": f"{lo:.1f}-{hi:.1f}", "n": len(rows),
                        "accuracy": correct / len(rows)})
    return buckets


def sweep_thresholds(jev: dict, llm: dict | None) -> list[dict]:
    """Pre-registered cascade policy (PLAN.md §6) across confidence thresholds."""
    jev_rows = {r["email_id"]: r for r in jev["observations"]
                if not r.get("error") and r.get("label_pred") in LABELS}
    llm_rows = {}
    if llm:
        llm_rows = {r["email_id"]: r for r in llm["observations"]
                    if not r.get("error") and r.get("label_pred") in LABELS}
    jev_pricing = clients.PRICING["jev-latest"]
    llm_pricing = clients.PRICING.get(llm["meta"]["model_requested"], {}) if llm else {}

    rows = []
    for step in range(0, 21):
        threshold = step / 20
        auto_correct = auto_total = 0
        auto_missed_attack = 0
        auto_pairs = []
        escalated = []
        for email_id, row in sorted(jev_rows.items()):
            confidence = row.get("confidence") or 0.0
            if row["label_pred"] == "attack" and confidence >= threshold:
                final = "attack"
                auto_total += 1
                auto_correct += 1 if row["label_true"] == final else 0
                auto_pairs.append((row["label_true"], final))
            elif row["label_pred"] == "safe" and confidence >= threshold:
                final = "safe"
                auto_total += 1
                auto_correct += 1 if row["label_true"] == final else 0
                auto_pairs.append((row["label_true"], final))
                if row["label_true"] == "attack":
                    auto_missed_attack += 1
            else:
                escalated.append(email_id)
                continue
        misroutes = {"attack_to_safe": 0, "safe_to_attack": 0, "spam_to_attack": 0,
                     "spam_to_safe": 0, "gray_to_attack": 0, "gray_to_safe": 0}
        for true_label, pred in auto_pairs:
            key = f"{true_label}_to_{pred}"
            if key in misroutes and true_label != pred:
                misroutes[key] += 1
        # build the final cascade answer set
        final_correct = auto_correct
        final_total = auto_total
        for email_id in escalated:
            if llm_rows:
                pred = llm_rows.get(email_id)
                if pred:
                    final_pred = pred["label_pred"]
                else:
                    final_pred = None
            else:
                final_pred = jev_rows[email_id]["label_pred"]
            if final_pred is not None:
                final_total += 1
                final_correct += 1 if final_pred == jev_rows[email_id]["label_true"] else 0
        jev_cost_all = sum(email_cost(r, jev_pricing) for r in jev_rows.values())
        llm_cost_escalated = sum(email_cost(llm_rows[e], llm_pricing)
                                 for e in escalated if e in llm_rows)
        llm_cost_all = sum(email_cost(r, llm_pricing) for r in llm_rows.values()) if llm_rows else None
        rows.append({
            "threshold": threshold,
            "auto_decided": auto_total,
            "auto_coverage": (auto_total / len(jev_rows)) if jev_rows else None,
            "auto_error_rate": ((auto_total - auto_correct) / auto_total) if auto_total else None,
            "auto_missed_attack": auto_missed_attack,
            "escalated": len(escalated),
            "final_accuracy": (final_correct / final_total) if final_total else None,
            "cascade_cost_usd": jev_cost_all + llm_cost_escalated,
            "cascade_per_1000": (jev_cost_all + llm_cost_escalated) / len(jev_rows) * 1000,
            "pure_llm_per_1000": (llm_cost_all / len(llm_rows) * 1000) if llm_rows else None,
            "misroutes": misroutes,
        })
    return rows


def sensitivity_hard_ham_as_safe(run: dict) -> dict:
    """Recompute metrics with hard_ham relabeled safe (pre-registered sensitivity)."""
    rows = [dict(r) for r in run["observations"]
            if not r.get("error") and r.get("label_pred") in LABELS]
    for row in rows:
        if row.get("source") == "spamassassin_hard_ham":
            row["label_true"] = "safe"
    matrix = confusion(rows)
    return {"accuracy": accuracy(matrix), "per_class": per_class(matrix)}


def aux_signal(observations: list[dict]) -> dict:
    """How the two auxiliary nouls track the true attack class."""
    by_label: dict[str, list[tuple]] = {label: [] for label in LABELS}
    for row in observations:
        answers = row.get("raw_answer") or {}
        if not isinstance(answers, dict):
            continue
        deception = (answers.get("deception_present") or {}).get("noul")
        credentials = (answers.get("requests_credentials_or_payment") or {}).get("noul")
        if deception is None and credentials is None:
            continue
        by_label[row["label_true"]].append((deception, credentials))
    out = {}
    for label, pairs in by_label.items():
        if not pairs:
            continue
        deception_values = [p[0] for p in pairs if p[0] is not None]
        credential_values = [p[1] for p in pairs if p[1] is not None]
        out[label] = {
            "n": len(pairs),
            "deception_mean": (sum(deception_values) / len(deception_values)) if deception_values else None,
            "credentials_mean": (sum(credential_values) / len(credential_values)) if credential_values else None,
        }
    return out


def fmt(value, digits=3):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def markdown_table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def main() -> int:
    runs = load_runs()
    if not runs:
        print("no runs found")
        return 1

    excluded = load_exclusions()
    dropped_per_run = {}
    for name, run in runs.items():
        all_rows = run["observations"]
        kept = [r for r in all_rows if r["email_id"] not in excluded]
        dropped_per_run[name] = len(all_rows) - len(kept)
        run["observations_all"] = all_rows
        run["observations"] = kept

    summaries = {name: summarize_run(run) for name, run in runs.items()}
    jev_name = next((n for n in summaries if summaries[n]["provider"] == "typesafe"), None)
    if not jev_name:
        print("no Jev run found")
        return 1
    jev_run = runs[jev_name]
    jev_summary = summaries[jev_name]

    llm_names = [n for n in summaries if summaries[n]["provider"] != "typesafe"
                 and summaries[n]["provider"] is not None
                 and int(runs[n]["meta"].get("corpus_size") or 0) == int(jev_run["meta"].get("corpus_size") or -1)]

    # --- reconciliation: unique non-error ids must match the corpus size; error rows
    # stay in the ledger by design (retried rows append a second, clean observation).
    reconciliation = []
    for name, run in runs.items():
        rows = run["observations_all"]
        ids = [r["email_id"] for r in rows]
        clean_ids = {r["email_id"] for r in rows if not r.get("error")}
        errors = sum(1 for r in rows if r.get("error"))
        expected = run["meta"].get("corpus_size")
        reconciliation.append({
            "run": name,
            "observations": len(ids),
            "errors": errors,
            "unique_clean_ids": len(clean_ids),
            "expected": expected,
            "unique_ids": len(set(ids)) == len(ids),
            "ok": expected is None or len(clean_ids) == expected,
        })

    results = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "exclusions": {
            "audit_file": "corpus/email/corpus-audit.json",
            "email_ids": sorted(excluded),
            "dropped_per_run": dropped_per_run,
        },
        "reconciliation": reconciliation,
        "summaries": summaries,
        "jev_calibration": calibration(jev_run["observations"]),
        "cascades": {},
        "aux_noul": aux_signal(jev_run["observations"]),
    }
    for name in llm_names:
        llm_run = runs[name]
        sweeps = sweep_thresholds(jev_run, llm_run)
        best = None
        for row in sweeps:
            if row["auto_error_rate"] is not None and row["auto_error_rate"] <= 0.02 \
               and row["final_accuracy"] is not None:
                if best is None or row["auto_coverage"] > best["auto_coverage"]:
                    best = row
        operational = None
        for row in sweeps:
            mr = row["misroutes"]
            if mr["attack_to_safe"] == 0 and mr["safe_to_attack"] == 0:
                if operational is None or row["auto_coverage"] > operational["auto_coverage"]:
                    operational = row
        results["cascades"][name] = {"sweep": sweeps, "recommended": best,
                                     "recommended_operational": operational}

    results["sensitivity_hard_ham_as_safe"] = {
        name: sensitivity_hard_ham_as_safe(run) for name, run in runs.items()
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    # --- RESULTS.md
    lines = ["# Jev Email Triage — Results", "",
             f"Generated: {results['generated_utc']} · recomputed from raw records only.",
             "",
             "## Reconciliation", "",
             markdown_table(
                 ["run", "observations", "errors", "clean ids", "expected", "ok"],
                 [[r["run"], str(r["observations"]), str(r["errors"]),
                   str(r["unique_clean_ids"]), str(r["expected"]),
                   "PASS" if r["ok"] else "FAIL"] for r in reconciliation]),
             "",
             "## Model summaries", "",
             markdown_table(
                 ["run", "model", "n scored", "errors", "accuracy", "p50 ms", "p95 ms", "$/email", "$/1k"],
                 [[s["file"], s["model"], str(s["scored"]), str(s["errors"]),
                   fmt(s["accuracy"]), fmt(s["latency_ms"]["p50"], 0), fmt(s["latency_ms"]["p95"], 0),
                   f"{s['cost']['per_email_usd_mean']:.6f}" if s["cost"]["per_email_usd_mean"] else "n/a",
                   fmt(s["cost"]["per_1000_usd"], 4)] for s in summaries.values()]),
             ""]
    for name, summary in summaries.items():
        lines += [f"### Confusion — {summary['model']} ({name})", "",
                  markdown_table(
                      ["true \\ pred"] + LABELS,
                      [[t] + [str(summary["confusion"][t][p]) for p in LABELS] for t in LABELS]),
                  "",
                  markdown_table(
                      ["class", "support", "tp", "precision", "recall"],
                      [[label, str(m["support"]), str(m["tp"]), fmt(m["precision"]), fmt(m["recall"])]
                       for label, m in summary["per_class"].items()]),
                  ""]

    lines += ["## Sensitivity: hard_ham relabeled as safe (pre-registered)", "",
              markdown_table(["run", "accuracy", "gray recall", "safe recall"],
                             [[name, fmt(s["accuracy"]), fmt(s["per_class"]["gray"]["recall"]),
                               fmt(s["per_class"]["safe"]["recall"])]
                              for name, s in results["sensitivity_hard_ham_as_safe"].items()]),
              "",
              "## Per-source accuracy", "",
              markdown_table(["run", "source", "n", "accuracy"],
                             [[name, src, str(v["n"]), fmt(v["accuracy"])]
                              for name, s in summaries.items()
                              for src, v in s["by_source"].items()]),
              "",
              "## Jev calibration (confidence decile vs accuracy)", "",
              markdown_table(["bucket", "n", "accuracy"],
                             [[c["bucket"], str(c["n"]), fmt(c["accuracy"])]
                              for c in results["jev_calibration"]]), ""]
    for name, cascade in results["cascades"].items():
        operational = cascade.get("recommended_operational")
        lines += [f"## Cascade sweep — Jev -> {summaries[name]['model']}", "",
                  markdown_table(
                      ["threshold", "auto %", "auto err %", "missed attacks", "final acc",
                       "cascade $/1k", "pure LLM $/1k"],
                      [[fmt(r["threshold"], 2), fmt((r["auto_coverage"] or 0) * 100, 1),
                        fmt((r["auto_error_rate"] or 0) * 100, 2), str(r["auto_missed_attack"]),
                        fmt(r["final_accuracy"]), fmt(r["cascade_per_1000"], 4),
                        fmt(r["pure_llm_per_1000"], 4)] for r in cascade["sweep"]]), "",
                  "Auto-decided misroute decomposition (counts):", "",
                  markdown_table(
                      ["threshold", "attack→safe", "safe→attack", "spam→attack", "spam→safe",
                       "gray→attack", "gray→safe"],
                      [[fmt(r["threshold"], 2), str(r["misroutes"]["attack_to_safe"]),
                        str(r["misroutes"]["safe_to_attack"]), str(r["misroutes"]["spam_to_attack"]),
                        str(r["misroutes"]["spam_to_safe"]), str(r["misroutes"]["gray_to_attack"]),
                        str(r["misroutes"]["gray_to_safe"])] for r in cascade["sweep"]]), ""]
        if cascade["recommended"]:
            rec = cascade["recommended"]
            lines += [f"**Registered constraint (auto-decided exact-label error ≤ 2%):** "
                      f"threshold {rec['threshold']:.2f} → "
                      f"{rec['auto_coverage'] * 100:.1f}% auto-decided, "
                      f"auto error {rec['auto_error_rate'] * 100:.2f}%, "
                      f"final accuracy {rec['final_accuracy']:.3f}, "
                      f"cascade ${rec['cascade_per_1000']:.4f}/1k vs pure ${rec['pure_llm_per_1000']:.4f}/1k.", ""]
        else:
            lines += ["**Registered constraint (auto-decided exact-label error ≤ 2%): NOT MET at any "
                      "threshold** — the exact-label metric counts every misroute equally, including "
                      "benign ones. Operational decomposition follows.", ""]
        if operational:
            lines += [f"**Operational view (post-hoc decomposition, not the registered metric):** "
                      f"threshold {operational['threshold']:.2f} → "
                      f"{operational['auto_coverage'] * 100:.1f}% auto-decided with zero "
                      "attack→safe deliveries and zero safe→attack quarantines; remaining auto "
                      f"misroutes are spam→attack {operational['misroutes']['spam_to_attack']}, "
                      f"spam→safe {operational['misroutes']['spam_to_safe']}, "
                      f"gray→attack {operational['misroutes']['gray_to_attack']}, "
                      f"gray→safe {operational['misroutes']['gray_to_safe']}.", ""]

    lines += ["## Auxiliary signals (mean noul value by true label)", "",
              markdown_table(["label", "n", "deception_present", "credentials_or_payment"],
                             [[label, str(m["n"]), fmt(m["deception_mean"]), fmt(m["credentials_mean"])]
                              for label, m in results["aux_noul"].items()]), ""]

    (OUT_DIR / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n".join(lines[:60]))
    print(f"\n... full output -> {OUT_DIR / 'RESULTS.md'}")
    print(f"machine-readable -> {OUT_DIR / 'results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
