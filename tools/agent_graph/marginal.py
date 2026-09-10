"""Marginal Composition Risk and Co-Installation Analysis for Agent Toolchains.

This module answers the question:
    "What is the marginal composition risk of adding server X, given what people already have?"

Rather than auditing packages in isolation ("is package X dangerous?"), which is ineffective
because almost every server is individually ordinary, this module measures the systemic
impact of packages across real installation contexts:

1. Distance-to-Closure: How many legs short of full exfiltration capability is each configuration?
2. Marginal Closure Contribution: How many open configurations flip from open to closed
   when package X is introduced?
3. Co-Installation Graph: Which packages do developers install together, what functional
   communities emerge, and what is each community's proximity to closure?
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from tools.agent_graph.capabilities import (
    CAPABILITY_LEGS,
    Leg,
    PackageCapabilities,
    Tier,
)
from tools.agent_graph.composition import (
    ALL_LEGS,
    CLOSURE_COMPOSED,
    CLOSURE_NONE,
    CLOSURE_SINGLE_PACKAGE,
    CompositionResult,
    Installation,
    analyze,
)


@dataclass
class DistanceProfile:
    """Distance-to-closure metrics for a single installation."""

    identifier: str
    package_count: int
    legs_present: Set[str]
    distance: int  # 0 = closed, 1 = 1 leg to go, 2 = 2 legs to go, 3 = 3 legs to go
    missing_legs: Set[str]
    closes: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "package_count": self.package_count,
            "legs_present": sorted(self.legs_present),
            "distance": self.distance,
            "missing_legs": sorted(self.missing_legs),
            "closes": self.closes,
        }


@dataclass
class PackageMarginalImpact:
    """Marginal closure contribution metrics for a single package."""

    package_name: str
    legs_provided: List[str]
    closes_alone: bool
    installations_lacking: int
    flips_total: int
    flip_rate_total: float
    flips_composed: int
    flip_rate_composed: float
    flips_composed_grounded: int = 0
    flip_rate_composed_grounded: float = 0.0
    flips_composed_weighted: float = 0.0
    flip_rate_composed_weighted: float = 0.0
    legs_completed: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "legs_provided": sorted(self.legs_provided),
            "closes_alone": self.closes_alone,
            "installations_lacking": self.installations_lacking,
            "flips_total": self.flips_total,
            "flip_rate_total": round(self.flip_rate_total, 4),
            "flips_composed": self.flips_composed,
            "flip_rate_composed": round(self.flip_rate_composed, 4),
            "flips_composed_grounded": self.flips_composed_grounded,
            "flip_rate_composed_grounded": round(self.flip_rate_composed_grounded, 4),
            "flips_composed_weighted": round(self.flips_composed_weighted, 4),
            "flip_rate_composed_weighted": round(self.flip_rate_composed_weighted, 4),
            "legs_completed": self.legs_completed,
        }


def compute_distance_to_closure(
    installation: Installation, min_tier: Tier = Tier.DECLARED_TEXT
) -> DistanceProfile:
    """Calculates how many legs away an installation sits from complete trifecta closure."""
    result = analyze(installation, min_tier=min_tier)
    all_target = set(ALL_LEGS)
    present = result.legs_present
    missing = all_target - present
    dist = len(missing)

    return DistanceProfile(
        identifier=installation.identifier,
        package_count=len(installation.packages),
        legs_present=present,
        distance=dist,
        missing_legs=missing,
        closes=result.closes,
    )


def compute_population_distance_distribution(
    installations: Sequence[Installation], min_tier: Tier = Tier.DECLARED_TEXT
) -> Dict[str, Any]:
    """Computes distance-to-closure distribution across the entire population of installations."""
    total = len(installations)
    if not total:
        return {
            "total_installations": 0,
            "closed_count": 0,
            "open_count": 0,
            "distance_distribution": {},
            "missing_leg_breakdown_distance_1": {},
        }

    profiles = [compute_distance_to_closure(inst, min_tier=min_tier) for inst in installations]
    closed = [p for p in profiles if p.closes]
    open_profiles = [p for p in profiles if not p.closes]

    dist_counts: Counter[int] = Counter()
    for p in open_profiles:
        dist_counts[p.distance] += 1

    missing_legs_dist1: Counter[str] = Counter()
    for p in open_profiles:
        if p.distance == 1:
            for m in p.missing_legs:
                missing_legs_dist1[m] += 1

    return {
        "total_installations": total,
        "closed_count": len(closed),
        "closed_rate": round(len(closed) / total, 4),
        "open_count": len(open_profiles),
        "open_rate": round(len(open_profiles) / total, 4),
        "distance_distribution": {
            str(d): {
                "count": dist_counts[d],
                "share_of_open": round(dist_counts[d] / len(open_profiles), 4) if open_profiles else 0.0,
                "share_of_total": round(dist_counts[d] / total, 4),
            }
            for d in sorted(dist_counts)
        },
        "missing_leg_breakdown_distance_1": {
            leg: {
                "count": missing_legs_dist1[leg],
                "share_of_distance_1": round(missing_legs_dist1[leg] / dist_counts[1], 4) if dist_counts[1] else 0.0,
            }
            for leg in ALL_LEGS
        },
    }


def compute_distance_sensitivity_band(
    installations: Sequence[Installation],
) -> Dict[str, Any]:
    """Computes distance-to-closure distributions across all three evidence tiers.

    Tier 1 (DECLARED_TEXT): admits all evidence (text + dependencies + wiring).
    Tier 2 (MANIFEST_STRUCTURE): admits structure + dependencies + wiring.
    Tier 3 (DECLARED_DEPENDENCY): admits dependencies and wiring only.
    """
    tiers = [
        ("declared_text", Tier.DECLARED_TEXT),
        ("manifest_structure", Tier.MANIFEST_STRUCTURE),
        ("declared_dependency", Tier.DECLARED_DEPENDENCY),
    ]
    band: Dict[str, Any] = {}
    for name, tier in tiers:
        band[name] = compute_population_distance_distribution(installations, min_tier=tier)
    return band


def compute_marginal_closure_contributions(
    installations: Sequence[Installation],
    package_pool: Dict[str, PackageCapabilities],
    min_tier: Tier = Tier.DECLARED_TEXT,
    population_installations: Optional[Sequence[Installation]] = None,
) -> List[PackageMarginalImpact]:
    """Simulates adding each package to every open installation lacking it.

    Measures how many installations flip from open to closed, distinguishing between
    single-package closers (which close alone) and composed catalysts.

    Also calculates co-installation affinity between candidate packages and target
    configurations to separate purely theoretical combinations from empirically grounded ones.
    """
    open_installations: List[Installation] = []
    initial_results: Dict[str, CompositionResult] = {}

    for inst in installations:
        res = analyze(inst, min_tier=min_tier)
        initial_results[inst.identifier] = res
        if not res.closes:
            open_installations.append(inst)

    # Compute empirical co-installation pair frequencies and package occurrence counts
    ref_corpus = population_installations if population_installations is not None else installations
    pair_counts: Counter[Tuple[str, str]] = Counter()
    pkg_counts: Counter[str] = Counter()
    for inst in ref_corpus:
        pkgs = sorted(set(inst.package_names()))
        for p in pkgs:
            pkg_counts[p] += 1
        for p1, p2 in combinations(pkgs, 2):
            pair_counts[(p1, p2)] += 1
            pair_counts[(p2, p1)] += 1

    results: List[PackageMarginalImpact] = []

    for pkg_name, pkg_caps in sorted(package_pool.items()):
        closes_alone = pkg_caps.closes_trifecta_alone(min_tier=min_tier)
        legs_provided = sorted(pkg_caps.legs(min_tier=min_tier))

        # Installations lacking this package
        eligible_open = [
            inst for inst in open_installations if pkg_name not in inst.package_names()
        ]
        lacking_count = len(eligible_open)

        if lacking_count == 0:
            results.append(
                PackageMarginalImpact(
                    package_name=pkg_name,
                    legs_provided=legs_provided,
                    closes_alone=closes_alone,
                    installations_lacking=0,
                    flips_total=0,
                    flip_rate_total=0.0,
                    flips_composed=0,
                    flip_rate_composed=0.0,
                    flips_composed_grounded=0,
                    flip_rate_composed_grounded=0.0,
                    flips_composed_weighted=0.0,
                    flip_rate_composed_weighted=0.0,
                    legs_completed={},
                )
            )
            continue

        flips_total = 0
        flips_composed = 0
        flips_composed_grounded = 0
        flips_composed_weighted = 0.0
        legs_completed_counter: Counter[str] = Counter()

        for inst in eligible_open:
            # Form simulated installation with package added
            simulated = Installation(
                identifier=f"{inst.identifier}+{pkg_name}",
                packages=inst.packages + [pkg_caps],
                source=inst.source,
            )
            sim_res = analyze(simulated, min_tier=min_tier)

            if sim_res.closes:
                flips_total += 1
                if sim_res.closure_type == CLOSURE_COMPOSED:
                    flips_composed += 1

                    inst_pkgs = inst.package_names()
                    # Check empirical co-occurrence with any package already in inst
                    max_co = max([pair_counts.get((pkg_name, q), 0) for q in inst_pkgs], default=0)
                    if max_co > 0:
                        flips_composed_grounded += 1

                    # Jaccard affinity weight max_{q in inst} J(pkg_name, q)
                    denom_sum = [
                        (pkg_counts[pkg_name] + pkg_counts[q] - pair_counts.get((pkg_name, q), 0))
                        for q in inst_pkgs
                    ]
                    max_j = max([
                        pair_counts.get((pkg_name, q), 0) / denom
                        for q, denom in zip(inst_pkgs, denom_sum)
                        if denom > 0
                    ], default=0.0)
                    flips_composed_weighted += max_j

                # What missing leg(s) did this package provide?
                prior_legs = initial_results[inst.identifier].legs_present
                missing_prior = set(ALL_LEGS) - prior_legs
                supplied_missing = set(legs_provided) & missing_prior
                for leg in supplied_missing:
                    legs_completed_counter[leg] += 1

        results.append(
            PackageMarginalImpact(
                package_name=pkg_name,
                legs_provided=legs_provided,
                closes_alone=closes_alone,
                installations_lacking=lacking_count,
                flips_total=flips_total,
                flip_rate_total=flips_total / lacking_count if lacking_count else 0.0,
                flips_composed=flips_composed,
                flip_rate_composed=flips_composed / lacking_count if lacking_count else 0.0,
                flips_composed_grounded=flips_composed_grounded,
                flip_rate_composed_grounded=flips_composed_grounded / lacking_count if lacking_count else 0.0,
                flips_composed_weighted=flips_composed_weighted,
                flip_rate_composed_weighted=flips_composed_weighted / lacking_count if lacking_count else 0.0,
                legs_completed=dict(legs_completed_counter),
            )
        )

    # Rank headline table primarily by composed contribution:
    # flips_composed descending, then flips_composed_grounded descending, then flips_total descending
    results.sort(
        key=lambda r: (
            -r.flips_composed,
            -r.flips_composed_grounded,
            -r.flips_total,
            r.package_name,
        )
    )
    return results


def compute_coinstallation_graph(
    installations: Sequence[Installation], min_support: int = 3
) -> Dict[str, Any]:
    """Extracts the pairwise co-installation network across installations.

    Filters to edges meeting min_support (appearing together in at least min_support configs).
    """
    pair_counts: Counter[Tuple[str, str]] = Counter()
    package_frequency: Counter[str] = Counter()

    for inst in installations:
        pkgs = sorted(set(inst.package_names()))
        for p in pkgs:
            package_frequency[p] += 1
        for p1, p2 in combinations(pkgs, 2):
            pair_counts[(p1, p2)] += 1

    edges: List[Dict[str, Any]] = []
    for (p1, p2), count in pair_counts.most_common():
        if count >= min_support:
            edges.append({
                "source": p1,
                "target": p2,
                "weight": count,
            })

    # Simple community clustering via connected components over edges meeting min_support
    adj: Dict[str, Set[str]] = defaultdict(set)
    for edge in edges:
        adj[edge["source"]].add(edge["target"])
        adj[edge["target"]].add(edge["source"])

    visited: Set[str] = set()
    communities: List[List[str]] = []
    for node in sorted(adj):
        if node not in visited:
            component: List[str] = []
            queue = [node]
            visited.add(node)
            while queue:
                curr = queue.pop(0)
                component.append(curr)
                for neighbor in adj[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            component.sort(key=lambda p: -package_frequency[p])
            communities.append(component)

    communities.sort(key=lambda c: -len(c))

    component_sizes = [len(c) for c in communities]
    singletons_count = len(package_frequency) - sum(component_sizes)

    return {
        "total_installations": len(installations),
        "total_distinct_packages": len(package_frequency),
        "total_edges": len(edges),
        "min_support": min_support,
        "component_size_distribution": component_sizes,
        "singletons_count": singletons_count,
        "top_coinstallation_pairs": [
            {"package_a": p[0], "package_b": p[1], "frequency": c}
            for p, c in pair_counts.most_common(25)
            if c >= min_support
        ],
        "communities": [
            {
                "id": f"cluster_{idx+1}",
                "size": len(comm),
                "packages": comm[:10],  # Top 10 by frequency in cluster
                "total_members": len(comm),
            }
            for idx, comm in enumerate(communities)
            if len(comm) >= 2
        ],
    }
