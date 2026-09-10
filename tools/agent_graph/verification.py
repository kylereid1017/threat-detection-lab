"""Verification harness for the capability taxonomy.

A taxonomy that has not been measured against independent labels is an opinion
with a schema. This module measures one, and it is built to be able to fail.

## What is measured

Per-capability precision and recall against a hand-labeled set, plus the same
figures broken out **by evidence tier**. That breakdown is the load-bearing
test. The taxonomy asserts that a declared dependency is stronger evidence than
an author's marketing text. If tier 3 precision is not meaningfully above tier 1
precision, the tier system is decoration and should be deleted rather than
defended.

## Where the labels come from

`labels.json` in this directory, and nowhere else. Labels are assigned by
reading a package's own documentation and source listing, never by running it
and never by consulting the taxonomy's output, which would make the measurement
circular. Each label records the basis so a reader can check it.

## What a failure here means

Low recall means the taxonomy misses capabilities that exist, which biases every
composition rate downward. That is the safer direction and is reported as a
lower bound. Low precision means the taxonomy invents capabilities, which
inflates closure rates and would make the headline finding wrong. Precision is
therefore the number to watch, and it is reported per tier so the reader can
choose a threshold rather than inherit one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from tools.agent_graph.capabilities import (
    CAPABILITY_LEGS,
    PackageCapabilities,
    Tier,
    derive_capabilities,
)

LABELS_PATH = Path(__file__).resolve().parent / "labels.json"


@dataclass
class LabelledPackage:
    """One package with independently assigned ground-truth capabilities."""

    name: str
    ecosystem: str
    capabilities: Set[str]
    basis: str
    source_url: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LabelledPackage":
        unknown = set(data.get("capabilities", [])) - set(CAPABILITY_LEGS)
        if unknown:
            raise ValueError(
                f"label for {data.get('name')} uses capabilities outside the taxonomy: "
                f"{sorted(unknown)}"
            )
        return cls(
            name=data["name"],
            ecosystem=data.get("ecosystem", "npm"),
            capabilities=set(data.get("capabilities", [])),
            basis=data.get("basis", ""),
            source_url=data.get("source_url", ""),
        )


def load_labels(path: Path = LABELS_PATH) -> List[LabelledPackage]:
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [LabelledPackage.from_dict(entry) for entry in payload.get("packages", [])]


@dataclass
class TierScore:
    tier: int
    tier_name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if not (self.precision and self.recall):
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier,
            "tier_name": self.tier_name,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def verify(
    labels: Sequence[LabelledPackage],
    records_by_name: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Score the taxonomy against labels, overall and per evidence tier."""
    tier_scores = {
        tier: TierScore(tier=int(tier), tier_name=tier.name) for tier in Tier
    }
    per_capability: Dict[str, Dict[str, int]] = {}
    misses: List[Dict[str, Any]] = []
    spurious: List[Dict[str, Any]] = []
    unresolved: List[str] = []

    for label in labels:
        record = records_by_name.get(label.name)
        if record is None:
            unresolved.append(label.name)
            continue
        derived = derive_capabilities(record)

        for tier in Tier:
            predicted = derived.capabilities(tier)
            score = tier_scores[tier]
            score.true_positives += len(predicted & label.capabilities)
            score.false_positives += len(predicted - label.capabilities)
            score.false_negatives += len(label.capabilities - predicted)

        # Capability-level detail is reported at the strongest tier only, since
        # that is the tier the published measurements use.
        predicted = derived.capabilities(Tier.DECLARED_TEXT)
        for capability in sorted(predicted | label.capabilities):
            bucket = per_capability.setdefault(
                capability, {"tp": 0, "fp": 0, "fn": 0}
            )
            if capability in predicted and capability in label.capabilities:
                bucket["tp"] += 1
            elif capability in predicted:
                bucket["fp"] += 1
                spurious.append(
                    {
                        "package": label.name,
                        "capability": capability,
                        "evidence": [
                            e.to_dict()
                            for e in derived.evidence_for(capability)
                            if e.tier >= Tier.DECLARED_TEXT
                        ],
                    }
                )
            else:
                bucket["fn"] += 1
                misses.append({"package": label.name, "capability": capability})

    def rate(bucket: Dict[str, int]) -> Dict[str, Any]:
        precision_denominator = bucket["tp"] + bucket["fp"]
        recall_denominator = bucket["tp"] + bucket["fn"]
        return {
            **bucket,
            "precision": round(bucket["tp"] / precision_denominator, 4)
            if precision_denominator
            else None,
            "recall": round(bucket["tp"] / recall_denominator, 4)
            if recall_denominator
            else None,
        }

    dependency_only = tier_scores[Tier.DECLARED_DEPENDENCY]
    all_evidence = tier_scores[Tier.DECLARED_TEXT]
    tier_system_justified = dependency_only.precision > all_evidence.precision

    return {
        "labelled_packages": len(labels),
        "scored_packages": len(labels) - len(unresolved),
        "unresolved_labels": unresolved,
        "by_tier": [tier_scores[t].to_dict() for t in sorted(Tier, reverse=True)],
        "by_capability": {c: rate(b) for c, b in sorted(per_capability.items())},
        "dependency_only_beats_all_evidence": tier_system_justified,
        "tier_justification_note": (
            "The original design assumed dependency evidence was strongest and "
            "defaulted to it. This flag is true only if restricting to dependency "
            "evidence beats admitting everything. Measured on this label set it is "
            "false: admitting the package description improved precision and recall "
            "together, because agent servers are thin wrappers whose dependency sets "
            "say nothing about what they are for. Re-measure whenever rules change, "
            "and move the default rather than defend it."
        ),
        "false_negatives": misses[:40],
        "false_positives": spurious[:40],
        "direction_note": (
            "Missed capabilities bias composition rates downward and are reported as "
            "a lower bound. Invented capabilities bias them upward and would make the "
            "headline finding wrong, so precision is the figure to watch."
        ),
    }
