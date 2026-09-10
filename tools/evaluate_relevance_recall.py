"""External validation of the CTI relevance scorer against real malicious packages.

Runs `tools/cti/relevance.py` over the confirmed-malicious package corpus acquired
by `tools/acquire_malicious_corpus.py` (OpenSSF `malicious-packages`, hash-pinned)
and over a control set of real benign package names.

Three measurements, and the third is the one that matters:

1. **Base rate.** What share of all confirmed-malicious packages in an ecosystem
   imitate the AI and machine-learning toolchain at all. This is a finding about
   the threat landscape, not about the scorer.

2. **Recall on the full label.** Of the malicious packages labeled as targeting
   the AI toolchain, how many the scorer surfaces. This number is inflated,
   because the reference list used to build the label shares four names with the
   scorer's own vocabulary. It is reported anyway, and marked.

3. **Held-out recall.** The same measurement restricted to reference packages
   whose names the scorer has never been told about. Nothing the scorer knows can
   help it here. This is the honest generalization test, and the only one of the
   three that says whether the approach works on a campaign it did not anticipate.

Usage:
    python tools/evaluate_relevance_recall.py --ecosystem npm
    python tools/evaluate_relevance_recall.py --ecosystem pypi --benign-corpus <dir>
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import date
from pathlib import Path
from typing import Dict, List, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.cti.relevance import (  # noqa: E402
    BRAND_TERMS,
    TRIAGE_THRESHOLD,
    damerau_levenshtein,
    normalize,
    score_indicator,
)
from tools.cti import protected_names  # noqa: E402
from tools.swarm.telemetry_replay import wilson_score_interval  # noqa: E402

CORPUS_DIR = ROOT / "corpus" / "malicious"
RESULTS_PATH = ROOT / "docs" / "detections" / "evaluation-relevance-recall.json"

#: Real, published packages that make up the AI and machine-learning toolchain a
#: researcher at a frontier lab would plausibly install. Curated by hand from
#: packages that exist on the public registries, and deliberately wider than the
#: scorer's own vocabulary so that a generalization test is possible.
#:
#: This list is the ground-truth label's entire coverage. A malicious package
#: imitating an AI tool absent from this list is counted as a true negative when
#: it is really a miss, which biases every number below toward looking better
#: than reality. That bias is the main limitation of this evaluation.
AI_TOOLCHAIN_REFERENCE: Tuple[str, ...] = (
    # Names the scorer already knows (overlap with BRAND_TERMS)
    "anthropic",
    "openai",
    "huggingface",
    "pytorch",
    "nvidia",
    "databricks",
    "wandb",
    # Held out: the scorer has never been told these exist
    "langchain",
    "llamaindex",
    "transformers",
    "tiktoken",
    "tokenizers",
    "safetensors",
    "diffusers",
    "accelerate",
    "sentencepiece",
    "onnxruntime",
    "tensorflow",
    "keras",
    "scikitlearn",
    "chromadb",
    "pinecone",
    "weaviate",
    "qdrant",
    "ollama",
    "replicate",
    "cohere",
    "mistralai",
    "vllm",
    "deepspeed",
    "bitsandbytes",
    "peft",
    "trl",
    "datasets",
    "gradio",
    "streamlit",
    "mlflow",
    "comet",
    "modelscope",
)

#: Reference names that overlap the scorer's vocabulary, computed rather than
#: hardcoded so the split cannot drift when either list changes.
KNOWN_TO_SCORER: Set[str] = {
    name for name in AI_TOOLCHAIN_REFERENCE if any(b in name or name in b for b in BRAND_TERMS)
}
HELD_OUT: Set[str] = set(AI_TOOLCHAIN_REFERENCE) - KNOWN_TO_SCORER

#: Maximum edit distance for the imitation label, by reference-name length.
#: Short names need a tight budget or unrelated packages match by coincidence.
def _edit_budget(reference: str) -> int:
    if len(reference) <= 6:
        return 1
    return 2


def label_ai_imitation(
    package_name: str, references: Sequence[str]
) -> Tuple[str, str] | None:
    """Return (reference, kind) if the package imitates an AI toolchain package.

    `kind` is "contains" for substring imitation and "typosquat" for near-miss
    spelling. Both are real lure forms: `openai-sdk-helper` and `opneai` are the
    same attack with different spelling budgets.
    """
    normalized_full = normalize(package_name)
    if not normalized_full:
        return None
    labels = [normalized_full]
    for part in package_name.lower().replace("@", "").replace("/", "-").split("-"):
        cleaned = normalize(part)
        if cleaned and cleaned not in labels:
            labels.append(cleaned)

    for reference in references:
        if reference in normalized_full:
            return (reference, "contains")

    for reference in references:
        budget = _edit_budget(reference)
        for label in labels:
            if len(label) < 4 or abs(len(label) - len(reference)) > budget:
                continue
            if damerau_levenshtein(label, reference) <= budget:
                return (reference, "typosquat")
    return None


def load_corpus(path: Path) -> List[str]:
    names: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                names.append(json.loads(line)["name"])
    return names


def load_benign_names(corpus_dir: Path, limit: int | None = None) -> List[str]:
    """Real published package names, read from a local dependency tree."""
    names: List[str] = []
    for path in corpus_dir.rglob("package.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        name = data.get("name")
        if isinstance(name, str) and name:
            names.append(name)
            if limit and len(names) >= limit:
                break
    return sorted(set(names))


def rate(count: int, total: int) -> Dict[str, object]:
    if not total:
        return {"count": 0, "total": 0, "rate": 0.0, "wilson_ci_95": [0.0, 0.0]}
    low, high = wilson_score_interval(count, total)
    return {
        "count": count,
        "total": total,
        "rate": round(count / total, 6),
        "wilson_ci_95": [round(low, 6), round(high, 6)],
    }



def coverage_sweep(
    ecosystem: str,
    labeled: Sequence[Tuple[str, str, str]],
    references: Sequence[str],
    fractions: Sequence[float] = (0.0, 0.25, 0.50, 0.75, 1.00),
    seed: int = 20260905,
) -> List[Dict[str, object]]:
    """Recall as a function of how complete the protected inventory is.

    This is the measurement that replaces the meaningless one. Asking whether the
    scorer generalizes to names it was never given is asking whether it can detect
    imitation of a package nobody knew they depended on. It cannot, and neither
    can any other approach: the answer is always zero and the question is wrong.

    The answerable question is what recall the mechanism achieves at a given level
    of inventory coverage, and whether the misses fall exactly where coverage is
    absent. If they do, recall is controlled by an operational input the defender
    owns, which is a far more useful thing to tell a deployment team than a single
    aggregate number.
    """
    rows: List[Dict[str, object]] = []
    ordered = sorted(references)
    for fraction in fractions:
        rng = random.Random(seed)
        shuffled = list(ordered)
        rng.shuffle(shuffled)
        covered = set(shuffled[: round(len(shuffled) * fraction)])
        registry = protected_names.from_names(
            covered, source=f"simulated inventory at {fraction:.0%} coverage"
        )
        in_scope = [row for row in labeled if row[1] in covered]
        out_scope = [row for row in labeled if row[1] not in covered]

        def caught(rows_: Sequence[Tuple[str, str, str]]) -> int:
            hits = 0
            for name, _ref, _kind in rows_:
                verdict = score_indicator(
                    f"{ecosystem}:{name}",
                    indicator_type="package",
                    protected=registry,
                    brands=(),
                )
                if verdict.score >= TRIAGE_THRESHOLD:
                    hits += 1
            return hits

        rows.append(
            {
                "inventory_coverage": fraction,
                "protected_names_indexed": registry.indexed_count,
                "imitations_of_covered_names": rate(caught(in_scope), len(in_scope)),
                "imitations_of_uncovered_names": rate(caught(out_scope), len(out_scope)),
            }
        )
    return rows


def evaluate(ecosystem: str, benign_dir: Path | None) -> Dict[str, object]:
    snapshot = CORPUS_DIR / f"{ecosystem}_malicious_packages.jsonl"
    lock_path = CORPUS_DIR / f"{ecosystem}_acquisition-lock.json"
    if not snapshot.is_file():
        raise FileNotFoundError(
            f"no corpus at {snapshot}; run tools/acquire_malicious_corpus.py first"
        )
    lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.is_file() else {}
    malicious = load_corpus(snapshot)

    all_refs = list(AI_TOOLCHAIN_REFERENCE)
    held_out_refs = sorted(HELD_OUT)

    ai_all: List[Tuple[str, str, str]] = []
    ai_held_out: List[Tuple[str, str, str]] = []
    for name in malicious:
        hit = label_ai_imitation(name, all_refs)
        if hit:
            ai_all.append((name, hit[0], hit[1]))
            if hit[0] in HELD_OUT:
                ai_held_out.append((name, hit[0], hit[1]))

    def surfaced(names: Sequence[Tuple[str, str, str]]) -> List[Dict[str, str]]:
        found = []
        for name, reference, kind in names:
            verdict = score_indicator(f"{ecosystem}:{name}", indicator_type="package")
            if verdict.score >= TRIAGE_THRESHOLD:
                found.append(
                    {
                        "package": name,
                        "imitates": reference,
                        "kind": kind,
                        "score": round(verdict.score, 3),
                    }
                )
        return found

    surfaced_all = surfaced(ai_all)
    surfaced_held = surfaced(ai_held_out)

    missed_held = [
        {"package": n, "imitates": r, "kind": k}
        for (n, r, k) in ai_held_out
        if not any(s["package"] == n for s in surfaced_held)
    ]

    # Mechanism measurement: the vocabulary branches are switched OFF entirely
    # (brands=()) so that only the inventory-derived branch can score. Anything
    # caught here is caught by a mechanism that does not need to be told which
    # brand is being imitated.
    full_registry = protected_names.from_names(
        all_refs, source="AI toolchain reference list as a stand-in dependency inventory"
    )
    mechanism_hits = 0
    for name, _ref, _kind in ai_all:
        verdict = score_indicator(
            f"{ecosystem}:{name}",
            indicator_type="package",
            protected=full_registry,
            brands=(),
        )
        if verdict.score >= TRIAGE_THRESHOLD:
            mechanism_hits += 1

    sweep = coverage_sweep(ecosystem, ai_all, all_refs)

    benign_flagged = 0
    benign_flagged_by_inventory = 0
    benign_names: List[str] = []
    if benign_dir and benign_dir.is_dir():
        benign_names = load_benign_names(benign_dir)
        # Split the benign set. Half becomes the simulated inventory, half stays
        # unseen. Using the whole set as both inventory and control would make the
        # false-positive rate zero by construction, since the full-name exclusion
        # rules out every name the inventory already holds.
        split = len(benign_names) // 2
        inventory_half = benign_names[:split]
        control_half = benign_names[split:]
        benign_registry = protected_names.from_names(
            inventory_half, source="half the benign set, held as a simulated inventory"
        )
        for name in benign_names:
            verdict = score_indicator(f"{ecosystem}:{name}", indicator_type="package")
            if verdict.score >= TRIAGE_THRESHOLD:
                benign_flagged += 1
        for name in control_half:
            inv = score_indicator(
                f"{ecosystem}:{name}",
                indicator_type="package",
                protected=benign_registry,
                brands=(),
            )
            if inv.score >= TRIAGE_THRESHOLD:
                benign_flagged_by_inventory += 1

    return {
        "measurement": "external_relevance_validation",
        "measurement_class": "external",
        "measurement_note": (
            "The malicious corpus was published by the OpenSSF malicious-packages project "
            "and was not authored by this repository. The AI toolchain reference list was "
            "curated here, so the LABEL is internal while the POPULATION is external."
        ),
        "ecosystem": ecosystem,
        "corpus": {
            "dataset": lock.get("dataset", "unknown"),
            "retrieval_date": lock.get("retrieval_date", ""),
            "snapshot_sha256": lock.get("snapshot_sha256", ""),
            "malicious_packages": len(malicious),
        },
        "base_rate_ai_toolchain_imitation": rate(len(ai_all), len(malicious)),
        "recall_full_label": rate(len(surfaced_all), len(ai_all)),
        "recall_held_out": rate(len(surfaced_held), len(ai_held_out)),
        "held_out_reference_names": held_out_refs,
        "reference_names_known_to_scorer": sorted(KNOWN_TO_SCORER),
        "recall_inventory_mechanism": rate(mechanism_hits, len(ai_all)),
        "inventory_coverage_sweep": sweep,
        "benign_control": {
            "names_scored": len(benign_names),
            **rate(benign_flagged, len(benign_names)),
            "inventory_branch_holdout": {
                "note": (
                    "Half the benign set is the simulated inventory; the other half is "
                    "unseen. This is the false-positive rate of the inventory branch on "
                    "real published packages it was not told about."
                ),
                **rate(benign_flagged_by_inventory, max(0, len(benign_names) - len(benign_names) // 2)),
            },
        },
        "sample_surfaced": surfaced_all[:20],
        "sample_missed_held_out": missed_held[:20],
        "not_measured": [
            "whether the scorer catches AI-toolchain imitations absent from the reference list",
            "recall against real malicious manifest CONTENT, which requires a payload corpus",
        ],
        "evaluated": date.today().isoformat(),
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ecosystem", default="npm")
    parser.add_argument("--benign-corpus", type=Path, default=None)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)

    try:
        results = evaluate(args.ecosystem, args.benign_corpus)
    except FileNotFoundError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    base = results["base_rate_ai_toolchain_imitation"]
    full = results["recall_full_label"]
    held = results["recall_held_out"]
    benign = results["benign_control"]

    print(f"ecosystem:               {results['ecosystem']}")
    print(f"malicious packages:      {results['corpus']['malicious_packages']}")
    print(
        f"AI toolchain imitations: {base['count']} "
        f"({base['rate'] * 100:.3f}%, CI [{base['wilson_ci_95'][0] * 100:.3f}%, "
        f"{base['wilson_ci_95'][1] * 100:.3f}%])"
    )
    print(f"recall, full label:      {full['count']}/{full['total']} ({full['rate'] * 100:.1f}%)  [inflated]")
    print(f"recall, held out:        {held['count']}/{held['total']} ({held['rate'] * 100:.1f}%)  [vocabulary only]")
    mech = results["recall_inventory_mechanism"]
    print(f"recall, inventory only:  {mech['count']}/{mech['total']} ({mech['rate'] * 100:.1f}%)  [vocabulary disabled]")
    print("coverage sweep (recall on imitations of covered vs uncovered names):")
    for row in results["inventory_coverage_sweep"]:
        cov = row["imitations_of_covered_names"]
        unc = row["imitations_of_uncovered_names"]
        print(
            f"  {row['inventory_coverage']:>5.0%} coverage | covered {cov['count']}/{cov['total']} "
            f"({cov['rate'] * 100:5.1f}%) | uncovered {unc['count']}/{unc['total']} ({unc['rate'] * 100:.1f}%)"
        )
    if benign["total"]:
        print(f"benign control flagged:  {benign['count']}/{benign['total']} ({benign['rate'] * 100:.2f}%)")

    if not args.no_write:
        RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if RESULTS_PATH.is_file():
            try:
                existing = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
        existing[args.ecosystem] = results
        RESULTS_PATH.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        disp = RESULTS_PATH.relative_to(ROOT) if RESULTS_PATH.is_relative_to(ROOT) else RESULTS_PATH
        print(f"\nwrote {disp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
