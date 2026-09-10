"""Composition analysis over an installed set of agent tools.

The thesis this module exists to test: **the hazard is a property of the
installation, not of any package in it.**

A filesystem server is ordinary. A web-fetch server is ordinary. A server that
can post to an outbound endpoint is ordinary. Install all three into one agent
and the assembly can read private data, ingest text an attacker planted, and
send the result outward. No component is malicious, every component is correctly
described, and no per-package review, registry scan, or maintainer audit will
ever flag it, because there is nothing wrong with any package.

That is why this is modeled as a graph rather than a score. The interesting
questions are structural:

- Which **minimal subsets** of the installation close the chain? A closure that
  needs three packages is a different finding from one that needs two.
- Which packages are **critical**, in the sense that removing them breaks every
  closure? Those are the actionable items, and there are usually few of them.
- Is the closure **composed or single-package**? A package that closes all three
  legs alone is visible to ordinary per-package review. A composed closure is
  not, and the share of real installations in that state is the measurement this
  whole line of work is built to produce.

## On what a closure means

A closure is a capability statement, not an accusation. It says the assembly
*could* carry data out if some content it ingests turns hostile. It does not say
anyone did, that any package is malicious, or that exploitation is likely. The
distinction is load-bearing and every output here preserves it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from tools.agent_graph.capabilities import (
    CAPABILITY_LEGS,
    Leg,
    PackageCapabilities,
    Tier,
)

ALL_LEGS: Tuple[str, ...] = (
    Leg.PRIVATE_DATA,
    Leg.UNTRUSTED_INGRESS,
    Leg.EXFILTRATION,
)

#: Closure classifications, ordered by how visible the hazard is to ordinary
#: per-package review.
CLOSURE_NONE = "none"
CLOSURE_SINGLE_PACKAGE = "single_package"
CLOSURE_COMPOSED = "composed"

#: Above this many packages, enumerating every subset is wasteful. Minimal
#: closures are found by size-ascending search, and no real closure needs more
#: than three packages because there are only three legs, so the search is
#: bounded at three rather than by installation size.
MAX_CLOSURE_SIZE = 3


@dataclass
class Installation:
    """A set of agent tools configured together in one context."""

    identifier: str
    packages: List[PackageCapabilities] = field(default_factory=list)
    source: str = ""

    def package_names(self) -> List[str]:
        return [p.name for p in self.packages]


@dataclass
class CompositionResult:
    """Structural analysis of one installation."""

    identifier: str
    source: str
    package_count: int
    legs_present: Set[str] = field(default_factory=set)
    closure_type: str = CLOSURE_NONE
    minimal_closures: List[Tuple[str, ...]] = field(default_factory=list)
    critical_packages: List[str] = field(default_factory=list)
    leg_suppliers: Dict[str, List[str]] = field(default_factory=dict)
    sole_suppliers: Dict[str, str] = field(default_factory=dict)
    single_package_closers: List[str] = field(default_factory=list)
    min_tier: int = int(Tier.DECLARED_TEXT)

    @property
    def closes(self) -> bool:
        return self.closure_type != CLOSURE_NONE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "source": self.source,
            "package_count": self.package_count,
            "legs_present": sorted(self.legs_present),
            "closes_trifecta": self.closes,
            "closure_type": self.closure_type,
            "minimal_closures": [list(c) for c in self.minimal_closures],
            "smallest_closure_size": (
                min(len(c) for c in self.minimal_closures) if self.minimal_closures else None
            ),
            "critical_packages": self.critical_packages,
            "leg_suppliers": {k: sorted(v) for k, v in self.leg_suppliers.items()},
            "sole_suppliers": self.sole_suppliers,
            "single_package_closers": self.single_package_closers,
            "min_evidence_tier": self.min_tier,
            "interpretation": (
                "A closure means the assembly could carry data outward if content it "
                "ingests turns hostile. It is not a claim that any package is malicious "
                "or that exploitation occurred."
            ),
        }


def analyze(
    installation: Installation, min_tier: Tier = Tier.DECLARED_TEXT
) -> CompositionResult:
    """Find the structural closures in one installation."""
    result = CompositionResult(
        identifier=installation.identifier,
        source=installation.source,
        package_count=len(installation.packages),
        min_tier=int(min_tier),
    )

    legs_by_package: Dict[str, Set[str]] = {}
    for package in installation.packages:
        legs = package.legs(min_tier)
        if legs:
            legs_by_package[package.name] = legs
        if package.closes_trifecta_alone(min_tier):
            result.single_package_closers.append(package.name)

    for name, legs in legs_by_package.items():
        for leg in legs:
            result.leg_suppliers.setdefault(leg, []).append(name)
    result.legs_present = set(result.leg_suppliers)

    # A leg supplied by exactly one package is a single point of removal. These
    # are the actionable findings: drop that package and the chain is broken.
    for leg, suppliers in result.leg_suppliers.items():
        if len(suppliers) == 1:
            result.sole_suppliers[leg] = suppliers[0]

    if set(ALL_LEGS) - result.legs_present:
        result.closure_type = CLOSURE_NONE
        return result

    result.closure_type = (
        CLOSURE_SINGLE_PACKAGE if result.single_package_closers else CLOSURE_COMPOSED
    )
    result.minimal_closures = _minimal_closures(legs_by_package)

    if result.minimal_closures:
        # A package is critical if and only if removing it leaves no closures,
        # verified directly via a leave-one-out recheck.
        target = set(ALL_LEGS)
        critical = []
        for name in legs_by_package:
            remaining_legs: Set[str] = set().union(
                *(legs_by_package[q] for q in legs_by_package if q != name),
                set(),
            )
            if not (target <= remaining_legs):
                critical.append(name)
        result.critical_packages = sorted(critical)

    return result


def _minimal_closures(
    legs_by_package: Dict[str, Set[str]]
) -> List[Tuple[str, ...]]:
    """All inclusion-minimal package subsets covering all three legs.

    A subset is inclusion-minimal if it covers all three legs and no proper
    subset also covers all three legs. Unlike smallest-size closures, this
    preserves alternative closures of different sizes so that critical-cut
    and leave-one-out analyses see every independent path.
    """
    names = sorted(legs_by_package)
    target = set(ALL_LEGS)
    minimal: List[Tuple[str, ...]] = []
    minimal_sets: List[Set[str]] = []

    for size in range(1, MAX_CLOSURE_SIZE + 1):
        for subset in combinations(names, size):
            subset_set = set(subset)
            if any(m.issubset(subset_set) for m in minimal_sets):
                continue
            covered: Set[str] = set()
            for name in subset:
                covered |= legs_by_package[name]
            if target <= covered:
                minimal.append(subset)
                minimal_sets.append(subset_set)
    return minimal


def build_graph(
    installation: Installation, min_tier: Tier = Tier.DECLARED_TEXT
) -> Dict[str, Any]:
    """Node and edge lists for rendering one installation's capability graph."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for leg in ALL_LEGS:
        nodes.append({"id": f"leg:{leg}", "type": "leg", "label": leg})

    seen_capabilities: Set[str] = set()
    for package in installation.packages:
        capabilities = package.capabilities(min_tier)
        nodes.append(
            {
                "id": f"pkg:{package.name}",
                "type": "package",
                "label": package.name,
                "legs": sorted(package.legs(min_tier)),
                "closes_alone": package.closes_trifecta_alone(min_tier),
                "install_hooks": package.install_hooks,
                "entrypoint": package.has_executable_entrypoint,
            }
        )
        for capability in sorted(capabilities):
            if capability not in seen_capabilities:
                seen_capabilities.add(capability)
                nodes.append(
                    {
                        "id": f"cap:{capability}",
                        "type": "capability",
                        "label": capability,
                        "leg": CAPABILITY_LEGS.get(capability, ""),
                    }
                )
                edges.append(
                    {
                        "source": f"cap:{capability}",
                        "target": f"leg:{CAPABILITY_LEGS.get(capability, '')}",
                        "kind": "satisfies",
                    }
                )
            evidence = [
                e.to_dict() for e in package.evidence_for(capability) if e.tier >= min_tier
            ]
            edges.append(
                {
                    "source": f"pkg:{package.name}",
                    "target": f"cap:{capability}",
                    "kind": "provides",
                    "evidence": evidence,
                }
            )

    return {"nodes": nodes, "edges": edges}


@dataclass
class CorpusComposition:
    """Aggregate composition findings across many installations."""

    results: List[CompositionResult] = field(default_factory=list)
    min_tier: int = int(Tier.DECLARED_TEXT)

    def summary(self) -> Dict[str, Any]:
        total = len(self.results)
        if not total:
            return {"installations": 0, "note": "no installations analyzed"}

        closing = [r for r in self.results if r.closes]
        composed = [r for r in self.results if r.closure_type == CLOSURE_COMPOSED]
        single = [r for r in self.results if r.closure_type == CLOSURE_SINGLE_PACKAGE]

        leg_counts: Dict[str, int] = {leg: 0 for leg in ALL_LEGS}
        for result in self.results:
            for leg in result.legs_present:
                leg_counts[leg] += 1

        closure_sizes: Dict[int, int] = {}
        for result in composed:
            if result.minimal_closures:
                size = min(len(c) for c in result.minimal_closures)
                closure_sizes[size] = closure_sizes.get(size, 0) + 1

        critical_frequency: Dict[str, int] = {}
        for result in closing:
            for name in result.critical_packages:
                critical_frequency[name] = critical_frequency.get(name, 0) + 1

        return {
            "installations": total,
            "closing_trifecta": len(closing),
            "closure_rate": round(len(closing) / total, 4),
            "composed_closures": len(composed),
            "composed_rate": round(len(composed) / total, 4),
            "single_package_closures": len(single),
            "leg_presence_counts": leg_counts,
            "minimal_closure_size_distribution": dict(sorted(closure_sizes.items())),
            "most_frequent_critical_packages": sorted(
                critical_frequency.items(), key=lambda kv: (-kv[1], kv[0])
            )[:20],
            "min_evidence_tier": self.min_tier,
            "headline": (
                "composed_rate is the share of installations whose exfiltration chain "
                "exists only because of how packages combine. Per-package review cannot "
                "see those, which is the entire argument for measuring composition."
            ),
            "lower_bound_note": (
                "Capabilities are derived statically and are a lower bound, so the true "
                "closure rate is at least this high and cannot be lower."
            ),
        }
