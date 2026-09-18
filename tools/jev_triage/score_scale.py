"""Score the SCALE Jev battery: recomputes every published figure from raw records.

Reads docs/research/jev-email-triage/records/scale/*.jsonl (append-only; run_meta +
observations) and reuses the scoring conventions of tools/jev_triage/score.py
(confusion/per-class/calibration/sweep). Adds the registered criteria matrix from
PLAN-addendum-scale.md A7 (C1..C6), attack-miss confidence positions, and a
deviations block sourced from scale-deviations.json when present.

Outputs
  docs/research/jev-email-triage/results-scale.json
  docs/research/jev-email-triage/RESULTS-SCALE.md

Run:  python tools/jev_triage/score_scale.py
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RECORDS_DIR = REPO / "docs" / "research" / "jev-email-triage" / "records" / "scale"
OUT_DIR = REPO / "docs" / "research" / "jev-email-triage"
SCALE_MANIFEST = REPO / "corpus" / "email" / "scale" / "scale-manifest.json"
DEVIATIONS = OUT_DIR / "scale-deviations.json"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score as sc  # noqa: E402  (reuse: confusion, per_class, accuracy, calibration, sweep, ...)

LABELS = sc.LABELS
REGISTERED_T = 0.30


def load_scale_runs() -> dict[str, dict]:
    runs: dict[str, dict] = {}
    if not RECORDS_DIR.exists():
        return runs
    by_stem: dict[str, Path] = {}
    for path in sorted(RECORDS_DIR.glob("*.jsonl")) + sorted(RECORDS_DIR.glob("*.jsonl.gz")):
        stem = path.name[:-3] if path.name.endswith(".gz") else path.name
        existing = by_stem.get(stem)
        if existing is None or (existing.name.endswith(".gz") and not path.name.endswith(".gz")):
            by_stem[stem] = path
    for _, path in sorted(by_stem.items()):
        text = (gzip.open(path, "rt", encoding="utf-8").read()
                if path.name.endswith(".gz") else path.read_text(encoding="utf-8"))
        meta, observations = None, []
        for line in text.split("\n"):
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


def criteria(jev_run: dict, summary: dict, sweep: list[dict]) -> list[dict]:
    """PLAN-addendum-scale.md A7 registered criteria; each PASS/MISS with actuals."""
    clean = [r for r in jev_run["observations"]
             if not r.get("error") and r.get("label_pred") in LABELS]
    row30 = next((r for r in sweep if abs(r["threshold"] - REGISTERED_T) < 1e-9), None)
    attack_recall = summary["per_class"]["attack"]["recall"]
    attack_misses = [r for r in clean if r["label_true"] == "attack" and r["label_pred"] != "attack"]
    miss_confs = [r["confidence"] for r in attack_misses if r.get("confidence") is not None]
    max_miss_conf = max(miss_confs) if miss_confs else None
    cost_per_email = summary["cost"]["per_email_usd_mean"]
    p50 = summary["latency_ms"]["p50"]
    p95 = summary["latency_ms"]["p95"]

    def row(cid, desc, actual, passed):
        return {"id": cid, "criterion": desc, "actual": actual,
                "result": ("PASS" if passed else "MISS") if passed is not None else "N/A"}

    return [
        row("C1", "attack recall >= 0.90 (aggregate attack partition)",
            attack_recall, attack_recall is not None and attack_recall >= 0.90),
        row("C2", "auto-delivered true attacks at registered T=0.30 == 0",
            (row30 or {}).get("auto_missed_attack"), (row30 or {}).get("auto_missed_attack") == 0
            if row30 else None),
        row("C3", "auto-decide share >= 50% at <= 2% auto-decided exact-label error (T=0.30)",
            {"auto_coverage": (row30 or {}).get("auto_coverage"),
             "auto_error_rate": (row30 or {}).get("auto_error_rate")},
            (row30 is not None and row30["auto_coverage"] is not None
             and row30["auto_coverage"] >= 0.50 and (row30["auto_error_rate"] or 0) <= 0.02)),
        row("C4", "cost <= $0.001/email", cost_per_email,
            cost_per_email is not None and cost_per_email <= 0.001),
        row("C5", "latency p50 <= 350 ms and p95 <= 1000 ms", {"p50": p50, "p95": p95},
            p50 is not None and p95 is not None and p50 <= 350 and p95 <= 1000),
        row("C6", "every attack miss at confidence < 0.50",
            {"max_miss_confidence": max_miss_conf, "miss_count": len(attack_misses)},
            (max_miss_conf is None) or (max_miss_conf < 0.50)),
    ]


def load_deviations() -> list[str]:
    if not DEVIATIONS.exists():
        return []
    data = json.loads(DEVIATIONS.read_text(encoding="utf-8"))
    return [str(item) for item in data] if isinstance(data, list) else []


def baseline_comparison(runs: dict, summaries: dict, jev_name: str) -> dict:
    """A8.1 secondary arm: Jev vs each comparator run on their common subset ids."""
    jev_obs = {r["email_id"]: r for r in runs[jev_name]["observations"]
               if not r.get("error") and r.get("label_pred") in LABELS}
    out: dict[str, dict] = {}
    for name, run in runs.items():
        if name == jev_name or summaries[name]["provider"] in (None, "typesafe"):
            continue
        other_obs = {r["email_id"]: r for r in run["observations"]
                     if not r.get("error") and r.get("label_pred") in LABELS}
        common = sorted(set(jev_obs) & set(other_obs))
        if not common:
            continue
        entry: dict = {"n": len(common), "models": {}}
        for model_key, obs_map, meta in (("jev", jev_obs, runs[jev_name]["meta"]),
                                         (summaries[name]["model"], other_obs, run["meta"])):
            rows = [obs_map[email_id] for email_id in common]
            correct = sum(1 for r in rows if r["label_pred"] == r["label_true"])
            attack_rows = [r for r in rows if r["label_true"] == "attack"]
            attack_correct = sum(1 for r in attack_rows if r["label_pred"] == "attack")
            latencies = [r["latency_ms"] for r in rows if r.get("latency_ms")]
            pricing = sc.clients.PRICING.get(meta.get("model_requested"), {})
            costs = [sc.email_cost(r, pricing) for r in rows]
            entry["models"][model_key] = {
                "accuracy": (correct / len(rows)) if rows else None,
                "attack_recall": (attack_correct / len(attack_rows)) if attack_rows else None,
                "attack_support": len(attack_rows),
                "p50_ms": sc.percentile(latencies, 0.50),
                "p95_ms": sc.percentile(latencies, 0.95),
                "cost_per_1000": (sum(costs) / len(costs) * 1000) if costs else None,
            }
        out[name] = entry
    return out


def main() -> int:
    runs = load_scale_runs()
    if not runs:
        print(f"no scale runs found under {RECORDS_DIR}")
        return 1

    summaries = {name: sc.summarize_run(run) for name, run in runs.items()}
    jev_name = max(
        (n for n in summaries if summaries[n]["provider"] == "typesafe"),
        key=lambda n: summaries[n]["scored"], default=None)
    if not jev_name:
        print("no Jev scale run found")
        return 1
    jev_run = runs[jev_name]

    sweep = sc.sweep_thresholds(jev_run, None)
    crit = criteria(jev_run, summaries[jev_name], sweep)
    clean = [r for r in jev_run["observations"]
             if not r.get("error") and r.get("label_pred") in LABELS]
    attack_misses = sorted(
        ({"email_id": r["email_id"], "source": r.get("source"), "pred": r["label_pred"],
          "confidence": r.get("confidence"), "latency_ms": r.get("latency_ms")}
         for r in clean if r["label_true"] == "attack" and r["label_pred"] != "attack"),
        key=lambda m: (-(m["confidence"] or 0.0), m["email_id"]))

    reconciliation = [{
        "run": jev_name,
        "observations": len(jev_run["observations"]),
        "errors": sum(1 for r in jev_run["observations"] if r.get("error")),
        "unique_clean_ids": len({r["email_id"] for r in jev_run["observations"]
                                 if not r.get("error")}),
        "expected": jev_run["meta"].get("corpus_size"),
        "ok": (jev_run["meta"].get("corpus_size") is None
               or len({r["email_id"] for r in jev_run["observations"] if not r.get("error")})
               == jev_run["meta"].get("corpus_size")),
    }]

    attack_by_source = {}
    for r in clean:
        if r["label_true"] != "attack":
            continue
        src = r.get("source", "?")
        agg = attack_by_source.setdefault(src, {"support": 0, "recalled": 0})
        agg["support"] += 1
        if r["label_pred"] == "attack":
            agg["recalled"] += 1

    records_entries = []
    for entry_name, entry_run in sorted(runs.items()):
        entry_path = entry_run["path"]
        gz_path = Path(str(entry_path) + ".gz")
        records_entries.append({
            "run": entry_name,
            "file": entry_path.name,
            "sha256": hashlib.sha256(entry_path.read_bytes()).hexdigest(),
            "gz": gz_path.name if gz_path.exists() else None,
            "gz_sha256": hashlib.sha256(gz_path.read_bytes()).hexdigest() if gz_path.exists() else None,
        })
    manifest = json.loads(SCALE_MANIFEST.read_text(encoding="utf-8")) if SCALE_MANIFEST.exists() else {}
    results = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "plan_ref": "tools/jev_triage/PLAN-addendum-scale.md",
        "registered_threshold": REGISTERED_T,
        "reconciliation": reconciliation,
        "summaries": summaries,
        "criteria": crit,
        "attack_misses": attack_misses,
        "attack_recall_by_source": attack_by_source,
        "baseline_comparison": baseline_comparison(runs, summaries, jev_name),
        "calibration": sc.calibration(jev_run["observations"]),
        "sweep": sweep,
        "sensitivity_hard_ham_as_safe": sc.sensitivity_hard_ham_as_safe(jev_run),
        "aux_noul": sc.aux_signal(jev_run["observations"]),
        "provenance": {
            "records": records_entries,
            "corpus": jev_run["meta"].get("corpus"),
            "corpus_sha256": jev_run["meta"].get("corpus_sha256"),
            "scale_manifest_input_hashes": manifest.get("input_hashes", {}),
            "recompute_command": "python tools/jev_triage/score_scale.py",
        },
        "deviations": load_deviations(),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "results-scale.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    fmt = sc.fmt
    summary = summaries[jev_name]
    unresolved = {}
    for run_name, run in runs.items():
        err_ids = {r["email_id"] for r in run["observations"] if r.get("error")}
        clean_ids = {r["email_id"] for r in run["observations"] if not r.get("error")}
        unresolved[run_name] = len(err_ids - clean_ids)
    jev_sha16 = next(e["sha256"][:16] for e in records_entries if e["run"] == jev_name)
    lines = [
        "# Jev Email Triage - Scale Battery Results", "",
        f"Generated: {results['generated_utc']} - recomputed from raw records only "
        f"({jev_run['path'].name}, sha256 {jev_sha16}...).", "",
        f"Plan: `tools/jev_triage/PLAN-addendum-scale.md` - registered operating point T={REGISTERED_T:.2f}.", "",
        "Readings (post-hoc interpretation): `SCALE-READINGS.md`; conjunction arm: `CONJUNCTION-ARM-SCALE.md`.", "",
        "## Reconciliation", "",
        sc.markdown_table(["run", "observations", "errors", "clean ids", "expected", "ok"],
                          [[r["run"], str(r["observations"]), str(r["errors"]),
                            str(r["unique_clean_ids"]), str(r["expected"]),
                            "PASS" if r["ok"] else "FAIL"] for r in reconciliation]), "",
        "## Registered criteria (A7)", "",
        sc.markdown_table(["id", "criterion", "actual", "result"],
                          [[c["id"], c["criterion"], json.dumps(c["actual"], default=str), c["result"]]
                           for c in crit]), "",
        "## Model summary", "",
        sc.markdown_table(["run", "model", "n scored", "unresolved errors", "accuracy", "p50 ms", "p95 ms",
                           "$/email", "$/1k"],
                          [[summary["file"], summary["model"], str(summary["scored"]),
                            str(unresolved[jev_name]), fmt(summary["accuracy"]),
                            fmt(summary["latency_ms"]["p50"], 0), fmt(summary["latency_ms"]["p95"], 0),
                            f"{summary['cost']['per_email_usd_mean']:.6f}"
                            if summary["cost"]["per_email_usd_mean"] else "n/a",
                            fmt(summary["cost"]["per_1000_usd"], 4)]]), "",
        f"### Confusion - {summary['model']}", "",
        sc.markdown_table(["true \\ pred"] + LABELS,
                          [[t] + [str(summary["confusion"][t][p]) for p in LABELS] for t in LABELS]), "",
        sc.markdown_table(["class", "support", "tp", "precision", "recall"],
                          [[label, str(m["support"]), str(m["tp"]), fmt(m["precision"]), fmt(m["recall"])]
                           for label, m in summary["per_class"].items()]), "",
        "## Per-source accuracy", "",
        sc.markdown_table(["source", "n", "accuracy"],
                          [[src, str(v["n"]), fmt(v["accuracy"])]
                           for src, v in summary["by_source"].items()]), "",
        "## Attack recall by source", "",
        sc.markdown_table(["source", "attack support", "recalled", "recall"],
                          [[src, str(v["support"]), str(v["recalled"]),
                            fmt(v["recalled"] / v["support"]) if v["support"] else "n/a"]
                           for src, v in sorted(results["attack_recall_by_source"].items())]), "",
        "## Calibration (confidence decile vs accuracy)", "",
        sc.markdown_table(["bucket", "n", "accuracy"],
                          [[c["bucket"], str(c["n"]), fmt(c["accuracy"])]
                           for c in results["calibration"]]), "",
        "## Two-branch threshold sweep (Jev only; escalated rows take Jev's own label)", "",
        sc.markdown_table(["threshold", "auto %", "auto err %", "missed attacks", "final acc", "$/1k"],
                          [[fmt(r["threshold"], 2), fmt((r["auto_coverage"] or 0) * 100, 1),
                            fmt((r["auto_error_rate"] or 0) * 100, 2), str(r["auto_missed_attack"]),
                            fmt(r["final_accuracy"]), fmt(r["cascade_per_1000"], 4)] for r in sweep]), "",
        "Auto-decided misroute decomposition (counts):", "",
        sc.markdown_table(["threshold", "attack->safe", "safe->attack", "spam->attack", "spam->safe",
                           "gray->attack", "gray->safe"],
                          [[fmt(r["threshold"], 2), str(r["misroutes"]["attack_to_safe"]),
                            str(r["misroutes"]["safe_to_attack"]), str(r["misroutes"]["spam_to_attack"]),
                            str(r["misroutes"]["spam_to_safe"]), str(r["misroutes"]["gray_to_attack"]),
                            str(r["misroutes"]["gray_to_safe"])] for r in sweep]), "",
    ]
    if results["baseline_comparison"]:
        lines += ["## Secondary arm: cheap-LLM comparator on the common subset (A8.1)", ""]
        for name, entry in results["baseline_comparison"].items():
            lines += [f"Comparator run: `{name}` - common subset n={entry['n']}", "",
                      sc.markdown_table(
                          ["model", "accuracy", "attack recall", "attack support", "p50 ms", "p95 ms", "$/1k"],
                          [[model, fmt(m["accuracy"]), fmt(m["attack_recall"]), str(m["attack_support"]),
                            fmt(m["p50_ms"], 0), fmt(m["p95_ms"], 0), fmt(m["cost_per_1000"], 4)]
                           for model, m in entry["models"].items()]), ""]
    lines += [
        f"## Attack misses ({len(attack_misses)} total; listed by confidence, highest first)", "",
        sc.markdown_table(["email_id", "source", "predicted", "confidence"],
                          [[m["email_id"], str(m["source"]), str(m["pred"]), fmt(m["confidence"])]
                           for m in attack_misses[:100]]), "",
        "## Sensitivity: hard_ham relabeled as safe (pre-registered)", "",
        sc.markdown_table(["accuracy", "gray recall", "safe recall"],
                          [[fmt(results["sensitivity_hard_ham_as_safe"]["accuracy"]),
                            fmt(results["sensitivity_hard_ham_as_safe"]["per_class"]["gray"]["recall"]),
                            fmt(results["sensitivity_hard_ham_as_safe"]["per_class"]["safe"]["recall"])]]), "",
        "## Auxiliary signals (mean noul value by true label)", "",
        sc.markdown_table(["label", "n", "deception_present", "credentials_or_payment"],
                          [[label, str(m["n"]), fmt(m["deception_mean"]), fmt(m["credentials_mean"])]
                           for label, m in results["aux_noul"].items()]), "",
        "## Deviations and errata", "",
    ]
    deviations = results["deviations"]
    if deviations:
        lines += [f"- {d}" for d in deviations]
    else:
        lines += ["(none recorded at scoring time)"]
    lines += ["", "## Provenance", ""]
    for entry in results["provenance"]["records"]:
        gz_note = f" | gz `{entry['gz']}` sha256 `{entry['gz_sha256']}`" if entry["gz"] else ""
        lines.append(f"- records `{entry['file']}` sha256 `{entry['sha256']}`{gz_note}")
    lines += [
        f"- corpus: `{jev_run['meta'].get('corpus')}` sha256 `{jev_run['meta'].get('corpus_sha256')}`",
        f"- scale manifest input hashes: `{json.dumps(results['provenance']['scale_manifest_input_hashes'])}`",
        f"- recompute: `{results['provenance']['recompute_command']}`", ""]

    (OUT_DIR / "RESULTS-SCALE.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:45]))
    print(f"\n... full output -> {OUT_DIR / 'RESULTS-SCALE.md'}")
    print(f"machine-readable -> {OUT_DIR / 'results-scale.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
