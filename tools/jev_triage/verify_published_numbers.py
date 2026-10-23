#!/usr/bin/env python3
"""Recompute every number in the pre-triage gate brief from the raw run records.

This is an *independent* second implementation. It deliberately does not import
the study's own scoring code (``tools/jev_triage/score.py`` /
``score_scale.py``); it re-derives each metric from the append-only JSONL
records so that agreement between the two is corroboration rather than an echo.

Guarantees
----------
* **No network.** Standard library only; nothing here opens a socket.
* **Read-only.** Every file is opened in text-read mode. This tool never
  writes to, moves, or rewrites a record, a results file, or the brief.
* **No "fixing".** When a published figure cannot be reproduced, the row is
  reported as DIFF with both values. Records are evidence and are never edited
  to agree with a document.

Usage
-----
    python verify_published_numbers.py                 # full table, human readable
    python verify_published_numbers.py --section scale # one section only
    python verify_published_numbers.py --json          # machine-readable
    python verify_published_numbers.py --lab PATH      # point at the lab repo

Exit status is 0 when every claim reproduces, 1 when any claim differs.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

LABELS = ("safe", "gray", "spam", "attack")

# Published list prices, transcribed from the sources named in the run records'
# pricing_ref block. Dollars per 1M tokens.
PRICING = {
    "jev-latest": {"input": 0.042, "output": 0.0},
    "deepseek-flash": {"input": 0.15, "output": 0.60,
                       "input_peak": 0.30, "output_peak": 1.20},
    "anthropic/claude-haiku-4.5": {"input": 1.00, "output": 5.00},
    "anthropic/claude-sonnet-5": {"input": 2.00, "output": 10.00},
    "anthropic/claude-opus-5": {"input": 5.00, "output": 25.00},
    "anthropic/claude-fable-5.1": {"input": 10.00, "output": 50.00},
}

def _default_lab():
    """Locate the lab repo.

    When this file lives inside the lab repo (so a clone carries it), walk up
    from the script to find the checkout. Otherwise fall back to the usual
    sibling path. Either way `--lab` overrides.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "docs" / "research" / "jev-email-triage").is_dir():
            return parent
    # Not inside a checkout: fall back to the invocation directory; --lab overrides.
    return Path.cwd()


DEFAULT_LAB = _default_lab()


# --------------------------------------------------------------------------
# record loading
# --------------------------------------------------------------------------

def open_records(path):
    """Open a record file read-only, transparently handling .jsonl.gz.

    A fresh clone of the lab repo carries the scale records only as deterministic
    gzip -- the plaintext .jsonl is gitignored and stays on the machine that ran
    the battery. Both forms must verify identically.
    """
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def resolve_record(rec_dir, pattern):
    """Find one record file, preferring plaintext and falling back to gzip."""
    for suffix in (".jsonl", ".jsonl.gz"):
        matches = sorted(rec_dir.glob(pattern + suffix))
        if matches:
            return matches[0]
    raise FileNotFoundError("no record matching %s[.jsonl|.jsonl.gz] in %s"
                            % (pattern, rec_dir))


def read_records(path):
    """Return (run_meta, observations). Opened read-only."""
    meta = {}
    observations = []
    with open_records(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("kind") == "run_meta":
                meta = row
            elif row.get("kind") == "observation":
                observations.append(row)
    return meta, observations


def sha256_of(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_rows(observations, exclude=frozenset()):
    return [r for r in observations
            if not r.get("error")
            and r.get("label_pred") in LABELS
            and r["email_id"] not in exclude]


# --------------------------------------------------------------------------
# metric primitives (independent re-derivations)
# --------------------------------------------------------------------------

def percentile(values, q):
    """Index-rounded order statistic -- the convention the study registered.

    ordered[min(n-1, round(q*(n-1)))]. Documented here because a percentile
    claim is only meaningful alongside its convention.
    """
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))
    return ordered[idx]


def is_peak(ts_utc):
    """DeepSeek peak window: 01:00-04:00 and 06:00-10:00 UTC, Mon-Fri."""
    dt = datetime.fromisoformat(ts_utc)
    if dt.weekday() >= 5:
        return False
    return 1 <= dt.hour < 4 or 6 <= dt.hour < 10


def row_cost(row, pricing):
    if row.get("cost_usd") is not None:
        return float(row["cost_usd"])
    peak = is_peak(row["ts_utc"]) and "input_peak" in pricing
    in_price = pricing.get("input_peak" if peak else "input", 0.0)
    out_price = pricing.get("output_peak" if peak else "output", 0.0)
    return ((row.get("input_tokens") or 0) / 1e6 * in_price
            + (row.get("output_tokens") or 0) / 1e6 * out_price)


def accuracy_of(rows):
    if not rows:
        return 0.0
    return sum(1 for r in rows if r["label_pred"] == r["label_true"]) / len(rows)


def recall_of(rows, label):
    support = [r for r in rows if r["label_true"] == label]
    if not support:
        return None, 0
    hit = sum(1 for r in support if r["label_pred"] == label)
    return hit / len(support), len(support)


def two_branch(rows, threshold):
    """Registered cascade policy: auto-act only on confident attack/safe."""
    auto = auto_correct = missed_attack = 0
    for r in rows:
        conf = r.get("confidence") or 0.0
        pred = r["label_pred"]
        if pred in ("attack", "safe") and conf >= threshold:
            auto += 1
            if r["label_true"] == pred:
                auto_correct += 1
            elif pred == "safe" and r["label_true"] == "attack":
                missed_attack += 1
    return {
        "auto": auto,
        "auto_coverage": auto / len(rows) if rows else None,
        "auto_error_rate": (auto - auto_correct) / auto if auto else None,
        "auto_missed_attack": missed_attack,
    }


def calibration_buckets(rows):
    """Half-open deciles [lo, lo+0.1), top bucket closed at 1.0.

    The bucket index is derived from the confidence itself rather than by
    comparing against a computed upper edge, so no row can land in two
    buckets. Computing the edge as lo + 0.1 in binary floating point makes
    the 0.2 bucket's upper edge 0.30000000000000004 while the next bucket's
    lower edge is 0.29999999999999999, and any row at exactly 0.3 then
    satisfies both.
    """
    buckets = defaultdict(list)
    for r in rows:
        conf = r.get("confidence")
        if conf is None:
            continue
        buckets[min(int(conf * 10), 9)].append(r)
    out = []
    for i in range(10):
        member = buckets[i]
        out.append({"bucket": "%.1f-%.1f" % (i / 10, (i + 1) / 10),
                    "n": len(member),
                    "accuracy": accuracy_of(member) if member else None})
    return out


# --------------------------------------------------------------------------
# metric assembly
# --------------------------------------------------------------------------

def scale_metrics(lab):
    rec_dir = lab / "docs" / "research" / "jev-email-triage" / "records" / "scale"
    jev_path = resolve_record(rec_dir, "jev-scale-*")
    ds_path = resolve_record(rec_dir, "deepseek-*")

    meta, obs = read_records(jev_path)
    rows = clean_rows(obs)
    pricing = PRICING["jev-latest"]

    lat = [r["latency_ms"] for r in rows if r.get("latency_ms")]
    costs = [row_cost(r, pricing) for r in rows]
    sweep30 = two_branch(rows, 0.30)

    by_source_attack = {}
    for src in ("nazario", "nigerian_5", "ceas_08"):
        sub = [r for r in rows if r.get("source") == src]
        rec, sup = recall_of(sub, "attack")
        by_source_attack[src] = {"recall": rec, "support": sup}

    misses = [r for r in rows if r["label_true"] == "attack" and r["label_pred"] != "attack"]
    ceas_misses = sum(1 for r in misses if r.get("source") == "ceas_08")

    # confident-safe attack deliveries at the registered threshold, by source
    delivered = [r for r in rows if r["label_true"] == "attack"
                 and r["label_pred"] == "safe" and (r.get("confidence") or 0.0) >= 0.30]
    delivered_by_source = Counter(r.get("source") for r in delivered)
    worst = max(misses, key=lambda r: r.get("confidence") or 0.0)

    # post-hoc evident-semantics remap: ceas_08 rows are read as spam
    remap = []
    for r in rows:
        rr = dict(r)
        if rr.get("source") == "ceas_08":
            rr["label_true"] = "spam"
        remap.append(rr)
    remap_recall, remap_support = recall_of(remap, "attack")
    remap30 = two_branch(remap, 0.30)

    cal = calibration_buckets(rows)

    # comparator arm: rows scored cleanly by both models
    ds_meta, ds_obs = read_records(ds_path)
    ds_rows = clean_rows(ds_obs)
    ds_by_id = {r["email_id"]: r for r in ds_rows}
    jev_by_id = {r["email_id"]: r for r in rows}
    common = sorted(set(ds_by_id) & set(jev_by_id))
    j_sub = [jev_by_id[i] for i in common]
    d_sub = [ds_by_id[i] for i in common]
    ds_pricing = PRICING[ds_meta["model_requested"]]
    j_cost = sum(row_cost(r, pricing) for r in j_sub) / len(j_sub) * 1000
    d_cost = sum(row_cost(r, ds_pricing) for r in d_sub) / len(d_sub) * 1000

    naz_sup = by_source_attack["nazario"]["support"]
    nig_sup = by_source_attack["nigerian_5"]["support"]

    return {
        "_paths": {"jev": jev_path, "deepseek": ds_path},
        "_meta": meta,
        "n_observations": len(obs),
        "n_errors": sum(1 for r in obs if r.get("error")),
        "n_scored": len(rows),
        "corpus_size": meta.get("corpus_size"),
        "accuracy": accuracy_of(rows),
        "p50": percentile(lat, 0.50),
        "p95": percentile(lat, 0.95),
        "cost_per_1k": sum(costs) / len(costs) * 1000,
        "attack_recall": recall_of(rows, "attack")[0],
        "attack_support": recall_of(rows, "attack")[1],
        "safe_recall": recall_of(rows, "safe")[0],
        "auto_coverage": sweep30["auto_coverage"],
        "auto_error_rate": sweep30["auto_error_rate"],
        "auto_delivered_attacks": sweep30["auto_missed_attack"],
        "miss_count": len(misses),
        "max_miss_confidence": worst.get("confidence"),
        "worst_miss_id": worst.get("email_id"),
        "worst_miss_source": worst.get("source"),
        "ceas_attack_support": by_source_attack["ceas_08"]["support"],
        "ceas_miss_share": ceas_misses / len(misses) if misses else None,
        "nazario_recall": by_source_attack["nazario"]["recall"],
        "nazario_support": naz_sup,
        "nigerian_recall": by_source_attack["nigerian_5"]["recall"],
        "nigerian_support": nig_sup,
        "delivered_nazario": delivered_by_source.get("nazario", 0),
        "delivered_nigerian": delivered_by_source.get("nigerian_5", 0),
        "delivered_nazario_pct": delivered_by_source.get("nazario", 0) / naz_sup,
        "delivered_nigerian_pct": delivered_by_source.get("nigerian_5", 0) / nig_sup,
        "remap_attack_recall": remap_recall,
        "remap_attack_support": remap_support,
        "remap_accuracy": accuracy_of(remap),
        "remap_auto_delivered": remap30["auto_missed_attack"],
        "remap_auto_error_rate": remap30["auto_error_rate"],
        "clean_tail_share_of_traffic": remap30["auto_missed_attack"] / len(rows),
        "top_decile_n": cal[9]["n"],
        "top_decile_accuracy": cal[9]["accuracy"],
        "calibration": cal,
        "calibration_sum": sum(b["n"] for b in cal),
        "subset_n": len(common),
        "jev_subset_accuracy": accuracy_of(j_sub),
        "jev_subset_attack_recall": recall_of(j_sub, "attack")[0],
        "jev_subset_attack_support": recall_of(j_sub, "attack")[1],
        "jev_subset_p50": percentile([r["latency_ms"] for r in j_sub if r.get("latency_ms")], 0.50),
        "jev_subset_cost_per_1k": j_cost,
        "ds_subset_accuracy": accuracy_of(d_sub),
        "ds_subset_attack_recall": recall_of(d_sub, "attack")[0],
        "ds_subset_p50": percentile([r["latency_ms"] for r in d_sub if r.get("latency_ms")], 0.50),
        "ds_subset_cost_per_1k": d_cost,
        "cost_ratio": j_cost / d_cost,
    }


def first_eval_metrics(lab):
    rec_dir = lab / "docs" / "research" / "jev-email-triage" / "records"
    audit_path = lab / "corpus" / "email" / "corpus-audit.json"
    exclude = set()
    if audit_path.exists():
        with audit_path.open("r", encoding="utf-8") as handle:
            audit = json.load(handle)
        exclude = {e["email_id"] for e in audit.get("excluded_from_primary_metrics", [])}

    out = {"_exclusions": sorted(exclude), "models": {}}
    paths = sorted(rec_dir.glob("*.jsonl")) or sorted(rec_dir.glob("*.jsonl.gz"))
    for path in paths:
        meta, obs = read_records(path)
        model = meta.get("model_requested")
        # the fable arm ran on a frozen 60-email subset; it is not in the table
        if not model or meta.get("corpus_size") != 200:
            continue
        rows = clean_rows(obs, exclude)
        pricing = PRICING.get(model, {})
        lat = [r["latency_ms"] for r in rows if r.get("latency_ms")]
        costs = [row_cost(r, pricing) for r in rows]
        entry = {
            "n_scored": len(rows),
            "accuracy": accuracy_of(rows),
            "attack_recall": recall_of(rows, "attack")[0],
            "p50": percentile(lat, 0.50),
            "cost_per_1k": sum(costs) / len(costs) * 1000,
            "support": dict(Counter(r["label_true"] for r in rows)),
        }
        if model == "jev-latest":
            gate = two_branch(rows, 0.30)
            entry["auto_coverage_at_030"] = gate["auto_coverage"]
            entry["auto_delivered_attacks_at_030"] = gate["auto_missed_attack"]
        out["models"][model] = entry
    return out


def published_calibration(lab):
    """Scrape the calibration table out of the generated RESULTS-SCALE.md.

    Returns {bucket_label: n}. This lets the tool check the *published* table
    against the records, not just the brief -- a generated document can drift
    from its own source.
    """
    path = lab / "docs" / "research" / "jev-email-triage" / "RESULTS-SCALE.md"
    found = {}
    if not path.exists():
        return found
    in_table = False
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("## Calibration"):
                in_table = True
                continue
            if in_table:
                if line.startswith("##"):
                    break
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) >= 2 and "-" in cells[0] and cells[1].isdigit():
                    found[cells[0]] = int(cells[1])
    return found


def published_hashes(lab):
    """Scrape the provenance block of RESULTS-SCALE.md for declared hashes."""
    path = lab / "docs" / "research" / "jev-email-triage" / "RESULTS-SCALE.md"
    found = {}
    if not path.exists():
        return found
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if "sha256" not in line or "records" not in line:
                continue
            name = None
            for token in line.replace("`", " ").split():
                if token.endswith(".jsonl") or token.endswith(".jsonl.gz"):
                    name = token
                elif name and len(token) == 64 and all(c in "0123456789abcdef" for c in token):
                    found[name] = token
                    name = None
    return found


# --------------------------------------------------------------------------
# claims -- each mirrors a figure as the brief prints it
# --------------------------------------------------------------------------

def f(spec):
    """Render a recomputed value at the precision the brief prints."""
    def fmt(v):
        if v is None:
            return "n/a"
        if spec == "int":
            return "{:,}".format(int(round(v)))
        if spec.startswith("pct"):
            return "{:.{p}f}%".format(v * 100, p=int(spec[3:]))
        if spec.startswith("usd"):
            return "${:.{p}f}".format(v, p=int(spec[3:]))
        if spec.startswith("ms"):
            return "{:.0f} ms".format(v)
        if spec.startswith("f"):
            return "{:.{p}f}".format(v, p=int(spec[1:]))
        return str(v)
    return fmt


SCALE_CLAIMS = [
    ("S01", "18,314 scored emails", "18,314", "n_scored", f("int")),
    ("S02", "60.8% of mail auto-resolved", "60.8%", "auto_coverage", f("pct1")),
    ("S03", "p50 latency 220 ms", "220 ms", "p50", f("ms")),
    ("S04", "p95 latency 349 ms", "349 ms", "p95", f("ms")),
    ("S05", "$0.0432 per 1,000 emails", "$0.0432", "cost_per_1k", f("usd4")),
    ("S06", "attack recall 0.480 (registered basis)", "0.480", "attack_recall", f("f3")),
    ("S07", "1,301 auto-delivered attacks at T=0.30", "1,301", "auto_delivered_attacks", f("int")),
    ("S08", "auto-decide error rate 18.1%", "18.1%", "auto_error_rate", f("pct1")),
    ("S09", "max miss confidence 1.000", "1.000", "max_miss_confidence", f("f3")),
    ("S10", "6,238 attack misses", "6,238", "miss_count", f("int")),
    ("S11", "exact accuracy 0.599", "0.599", "accuracy", f("f3")),
    ("S12", "safe-class recall 91.7%", "91.7%", "safe_recall", f("pct1")),
    ("S13", "Nazario attack recall 89.1%", "89.1%", "nazario_recall", f("pct1")),
    ("S14", "Nazario support n = 1,523", "1,523", "nazario_support", f("int")),
    ("S15", "Nigerian fraud attack recall 98.7%", "98.7%", "nigerian_recall", f("pct1")),
    ("S16", "Nigerian fraud support n = 3,274", "3,274", "nigerian_support", f("int")),
    ("S17", "top confidence decile 93.5% accurate", "93.5%", "top_decile_accuracy", f("pct1")),
    ("S18", "top decile n = 6,757", "6,757", "top_decile_n", f("int")),
    ("S19", "CEAS_08 is 7,203 of the 12,000 attack rows", "7,203", "ceas_attack_support", f("int")),
    ("S20", "~96% of attack misses sit in CEAS_08", "96.6%", "ceas_miss_share", f("pct1")),
    ("S21", "remap attack recall 0.956", "0.956", "remap_attack_recall", f("f3")),
    ("S22", "remap attack support n = 4,797", "4,797", "remap_attack_support", f("int")),
    ("S23", "remap auto-delivered attacks = 60", "60", "remap_auto_delivered", f("int")),
    ("S24", "remap exact accuracy 0.772", "0.772", "remap_accuracy", f("f3")),
    ("S25", "remap auto-decide error 28.1%", "28.1%", "remap_auto_error_rate", f("pct1")),
    ("S26", "60 misses = 0.33% of scored traffic", "0.33%", "clean_tail_share_of_traffic", f("pct2")),
    ("S27", "Nazario confident-safe misses = 48", "48", "delivered_nazario", f("int")),
    ("S28", "Nazario confident-safe miss rate 3.2%", "3.2%", "delivered_nazario_pct", f("pct1")),
    ("S29", "Nigerian confident-safe misses = 12", "12", "delivered_nigerian", f("int")),
    ("S30", "Nigerian confident-safe miss rate 0.4%", "0.4%", "delivered_nigerian_pct", f("pct1")),
    ("S31", "comparator common subset n = 2,000", "2,000", "subset_n", f("int")),
    ("S32", "gate subset accuracy 0.472", "0.472", "jev_subset_accuracy", f("f3")),
    ("S33", "gate subset attack recall 0.292", "0.292", "jev_subset_attack_recall", f("f3")),
    ("S34", "gate subset p50 222 ms", "222 ms", "jev_subset_p50", f("ms")),
    ("S35", "gate subset $0.0425 / 1k", "$0.0425", "jev_subset_cost_per_1k", f("usd4")),
    ("S36", "comparator accuracy 0.421", "0.421", "ds_subset_accuracy", f("f3")),
    ("S37", "comparator attack recall 0.181", "0.181", "ds_subset_attack_recall", f("f3")),
    ("S38", "comparator p50 833 ms", "833 ms", "ds_subset_p50", f("ms")),
    ("S39", "comparator $0.1026 / 1k", "$0.1026", "ds_subset_cost_per_1k", f("usd4")),
    ("S40", "gate runs at ~41% of comparator cost", "41%", "cost_ratio", f("pct0")),
]

FIRST_CLAIMS = [
    ("F01", "jev-latest", "196", "65.3%", "0.86", "0.22 s", "$0.0414"),
    ("F02", "deepseek-flash", "196", "74.0%", "0.98", "0.89 s", "$0.0983"),
    ("F03", "anthropic/claude-haiku-4.5", "196", "72.4%", "0.94", "1.07 s", "$0.7818"),
    ("F04", "anthropic/claude-sonnet-5", "196", "70.4%", "0.98", "2.53 s", "$2.0630"),
    ("F05", "anthropic/claude-opus-5", "196", "74.5%", "0.98", "3.18 s", "$5.8234"),
]


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

class Report(object):
    def __init__(self):
        self.rows = []

    def check(self, cid, claim, expected, actual, note="", passed=None):
        """Record one claim. `passed` overrides the string comparison for cases
        where the displayed value is an abbreviation of what was compared."""
        if passed is None:
            passed = expected == actual
        self.rows.append({"id": cid, "claim": claim, "brief": expected,
                          "recomputed": actual,
                          "result": "PASS" if passed else "DIFF",
                          "note": note})

    @property
    def diffs(self):
        return [r for r in self.rows if r["result"] == "DIFF"]

    def render(self):
        w_id = max(len(r["id"]) for r in self.rows)
        w_claim = max(len(r["claim"]) for r in self.rows)
        w_b = max(12, max(len(r["brief"]) for r in self.rows))
        w_a = max(10, max(len(r["recomputed"]) for r in self.rows))
        head = ("ID".ljust(w_id) + "  " + "CLAIM".ljust(w_claim) + "  "
                + "PUBLISHED".rjust(w_b) + "  " + "RECOMPUTED".rjust(w_a) + "  RESULT")
        lines = [head, "-" * len(head)]
        for r in self.rows:
            lines.append(r["id"].ljust(w_id) + "  " + r["claim"].ljust(w_claim) + "  "
                         + r["brief"].rjust(w_b) + "  " + r["recomputed"].rjust(w_a)
                         + "  " + r["result"])
            if r["note"]:
                lines.append(" " * w_id + "  `- " + r["note"])
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Recompute the brief's figures from the raw run records.")
    parser.add_argument("--lab", type=Path, default=DEFAULT_LAB,
                        help="path to the threat-detection-lab repo")
    parser.add_argument("--section", choices=["all", "scale", "first", "integrity"],
                        default="all")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args()

    if not (args.lab / "docs" / "research" / "jev-email-triage").is_dir():
        sys.stderr.write("error: no jev-email-triage records under %s\n" % args.lab)
        return 2

    report = Report()
    scale = scale_metrics(args.lab)
    first = first_eval_metrics(args.lab)
    sections = []

    if args.section in ("all", "integrity"):
        published = published_hashes(args.lab)
        for key in ("jev", "deepseek"):
            path = scale["_paths"][key]
            claimed = published.get(path.name)
            digest = sha256_of(path)
            # Compared in full; abbreviated to 16 hex characters for display only.
            report.check("I-" + key.upper(), "sha256 of " + path.name,
                         (claimed or "not published")[:16], digest[:16],
                         "" if claimed else "no published hash to compare against",
                         passed=(claimed is not None and claimed == digest))
        report.check("I-REC", "records reconcile: observations - errors = corpus size",
                     "{:,}".format(scale["corpus_size"]),
                     "{:,}".format(scale["n_observations"] - scale["n_errors"]),
                     "{:,} observations, {} error rows retained as record".format(
                         scale["n_observations"], scale["n_errors"]))
        report.check("I-CAL", "calibration deciles partition the scored set",
                     "{:,}".format(scale["n_scored"]),
                     "{:,}".format(scale["calibration_sum"]),
                     "every scored row must fall in exactly one decile")

        # Cross-check the generated results document against the same records.
        pub_cal = published_calibration(args.lab)
        if pub_cal:
            report.check("P-CAL", "published calibration table row-count sum",
                         "{:,}".format(sum(pub_cal.values())),
                         "{:,}".format(scale["n_scored"]),
                         "the deciles must partition the scored set exactly once")
            for bucket in scale["calibration"]:
                claimed = pub_cal.get(bucket["bucket"])
                if claimed is None:
                    continue
                report.check("P-" + bucket["bucket"],
                             "published decile " + bucket["bucket"] + " row count",
                             "{:,}".format(claimed), "{:,}".format(bucket["n"]))
        sections.append("INTEGRITY")

    if args.section in ("all", "scale"):
        for cid, claim, expected, key, fmt in SCALE_CLAIMS:
            report.check(cid, claim, expected, fmt(scale[key]))
        report.check("S41", "worst miss is a Nigerian-fraud row at confidence 1.000",
                     "nigerian_5", str(scale["worst_miss_source"]),
                     "email_id " + str(scale["worst_miss_id"]))
        sections.append("SCALE BATTERY")

    if args.section in ("all", "first"):
        for cid, model, n, acc, rec, p50, cost in FIRST_CLAIMS:
            m = first["models"].get(model)
            if not m:
                report.check(cid, model + ": record not found", n, "missing")
                continue
            report.check(cid, model + ": n / acc / recall / p50 / $1k",
                         " ".join([n, acc, rec, p50, cost]),
                         "{:,} {:.1f}% {:.2f} {:.2f} s ${:.4f}".format(
                             m["n_scored"], m["accuracy"] * 100, m["attack_recall"],
                             m["p50"] / 1000, m["cost_per_1k"]))
        jev = first["models"].get("jev-latest", {})
        report.check("F06", "first-evaluation auto-resolved share 64.8%", "64.8%",
                     "{:.1f}%".format(jev.get("auto_coverage_at_030", 0) * 100))
        report.check("F07", "no attack auto-delivered on the first corpus", "0",
                     str(jev.get("auto_delivered_attacks_at_030")))
        report.check("F08", "support after pre-registered exclusions",
                     "safe 50 / gray 50 / spam 46 / attack 50",
                     " / ".join("%s %s" % (k, jev.get("support", {}).get(k)) for k in LABELS),
                     "4 exclusions applied uniformly: " + ", ".join(first["_exclusions"]))
        sections.append("FIRST EVALUATION")

    if args.json:
        print(json.dumps({"sections": sections, "rows": report.rows,
                          "diffs": len(report.diffs)}, indent=2))
        return 1 if report.diffs else 0

    print("Pre-triage gate -- brief figures recomputed from raw run records")
    print("lab repo: %s" % args.lab)
    print("sections: %s" % ", ".join(sections))
    print("")
    print(report.render())
    print("")
    total = len(report.rows)
    print("%d/%d claims reproduce from the records." % (total - len(report.diffs), total))
    if report.diffs:
        print("")
        print("DIFFs (reported, not corrected -- records are evidence):")
        for r in report.diffs:
            print("  %s  %s" % (r["id"], r["claim"]))
            print("        published: %s   recomputed: %s" % (r["brief"], r["recomputed"]))
            if r["note"]:
                print("        %s" % r["note"])
    return 1 if report.diffs else 0


if __name__ == "__main__":
    sys.exit(main())
