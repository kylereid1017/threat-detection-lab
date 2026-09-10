"""Infrastructure pivoting over collected indicators.

Pivoting is the step that turns a list into intelligence. One lookalike domain
is a data point. Four lookalike domains sharing a certificate, an address, and a
registrant pattern are a campaign, and a campaign is something a detection can
be written against.

The traversal here is deliberately conservative. Every edge names the attribute
that produced it, and shared-attribute clustering refuses to cluster on values
that are common enough to connect unrelated things. Over-pivoting is the classic
way an analyst ends up writing a rule against a shared hosting provider and
blocking a third of the internet.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set

from tools.cti.models import Cluster, Indicator, PivotEdge

#: Attributes that legitimately connect indicators belonging to one campaign.
PIVOTABLE_ATTRIBUTES = (
    "cert_sha256",
    "asn",
    "resolved_from",
    "package",
    "issuer",
    "registrable_domain",
)

#: An attribute value shared by more than this many indicators is treated as
#: infrastructure common to unrelated parties rather than as a campaign link.
#: Shared hosting, a popular certificate authority, and a large cloud ASN all
#: connect thousands of unrelated names.
MAX_CLUSTER_FANOUT = 25


@dataclass
class PivotGraph:
    """Indicators plus the relationships drawn between them."""

    nodes: Dict[str, Indicator] = field(default_factory=dict)
    edges: List[PivotEdge] = field(default_factory=list)
    clusters: List[Cluster] = field(default_factory=list)
    rejected_pivots: Dict[str, int] = field(default_factory=dict)

    def add(self, indicator: Indicator) -> None:
        existing = self.nodes.get(indicator.key)
        if existing:
            existing.merge(indicator)
        else:
            self.nodes[indicator.key] = indicator

    def add_all(self, indicators: Iterable[Indicator]) -> None:
        for indicator in indicators:
            self.add(indicator)

    def _attribute_index(self) -> Dict[str, Dict[str, List[str]]]:
        index: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        for key, indicator in self.nodes.items():
            for attribute in PIVOTABLE_ATTRIBUTES:
                value = indicator.context.get(attribute)
                if isinstance(value, str) and value.strip():
                    index[attribute][value.strip().lower()].append(key)
            # A certificate indicator connects to every name it covers.
            for name in indicator.context.get("dns_names", []) or []:
                if isinstance(name, str):
                    index["cert_sha256"][indicator.value].append(
                        f"domain:{name.lstrip('*.').lower()}"
                    )
        return index

    def build(self) -> "PivotGraph":
        """Draw edges and clusters from shared attributes."""
        self.edges.clear()
        self.clusters.clear()
        self.rejected_pivots.clear()
        index = self._attribute_index()

        for attribute, buckets in index.items():
            for value, members in buckets.items():
                members = sorted({m for m in members if m in self.nodes})
                if len(members) < 2:
                    continue
                if len(members) > MAX_CLUSTER_FANOUT:
                    self.rejected_pivots[f"{attribute}={value}"] = len(members)
                    continue
                anchor = members[0]
                for other in members[1:]:
                    self.edges.append(
                        PivotEdge(
                            source_key=anchor,
                            target_key=other,
                            relationship=f"shares_{attribute}",
                            evidence=f"{attribute}={value}",
                        )
                    )
                self.clusters.append(
                    Cluster(
                        cluster_id=f"{attribute}:{value}",
                        members=members,
                        shared_attribute=attribute,
                        shared_value=value,
                    )
                )
        self.clusters.sort(key=lambda c: (-len(c.members), c.cluster_id))
        return self

    def neighbors(self, key: str) -> Set[str]:
        found: Set[str] = set()
        for edge in self.edges:
            if edge.source_key == key:
                found.add(edge.target_key)
            elif edge.target_key == key:
                found.add(edge.source_key)
        return found

    def traverse(self, start_key: str, max_depth: int = 2) -> List[str]:
        """Breadth-first traversal from a seed, bounded by depth.

        Depth is bounded because pivot graphs expand fast and an unbounded walk
        from a seed on shared infrastructure reaches most of the graph, which
        tells an analyst nothing.
        """
        if start_key not in self.nodes:
            return []
        seen = {start_key}
        frontier = [start_key]
        order = [start_key]
        for _ in range(max_depth):
            next_frontier: List[str] = []
            for key in frontier:
                for neighbor in sorted(self.neighbors(key)):
                    if neighbor not in seen:
                        seen.add(neighbor)
                        order.append(neighbor)
                        next_frontier.append(neighbor)
            frontier = next_frontier
            if not frontier:
                break
        return order

    def to_dict(self) -> Dict[str, object]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "cluster_count": len(self.clusters),
            "clusters": [c.to_dict() for c in self.clusters],
            "edges": [e.to_dict() for e in self.edges],
            "rejected_pivots": self.rejected_pivots,
            "rejected_pivot_note": (
                "Attribute values shared by more than "
                f"{MAX_CLUSTER_FANOUT} indicators are treated as common infrastructure "
                "and are not used to link indicators."
            ),
        }
