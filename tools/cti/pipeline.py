"""Orchestration: collect, deduplicate, score, pivot, emit.

The pipeline is deterministic. Given the same snapshots it produces byte-identical
output, which is what makes it testable and what makes a published result
something a reader can reproduce rather than take on trust.

It also reports what it discarded. A collection layer that only reports what it
kept is unfalsifiable: an analyst cannot tell a quiet day from a broken parser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List

from tools.cti import emit
from tools.cti.graph import PivotGraph
from tools.cti.models import CollectionResult, Indicator
from tools.cti.relevance import (
    PRIORITY_THRESHOLD,
    TRIAGE_THRESHOLD,
    score_indicator,
)
from tools.cti.protected_names import ProtectedRegistry
from tools.cti.sources import COLLECTORS


@dataclass
class PipelineReport:
    """Everything the run produced, including what it dropped and why."""

    produced: str
    collection: List[CollectionResult] = field(default_factory=list)
    total_raw_indicators: int = 0
    unique_indicators: int = 0
    triage_queue: List[Indicator] = field(default_factory=list)
    priority_queue: List[Indicator] = field(default_factory=list)
    below_threshold: int = 0
    graph: PivotGraph = field(default_factory=PivotGraph)
    protected_summary: Dict[str, object] = field(default_factory=dict)

    def summary(self) -> Dict[str, object]:
        collected = sum(r.records_seen for r in self.collection)
        return {
            "produced": self.produced,
            "sources": [r.to_dict() for r in self.collection],
            "records_read": collected,
            "raw_indicators": self.total_raw_indicators,
            "unique_indicators": self.unique_indicators,
            "priority_indicators": len(self.priority_queue),
            "triage_indicators": len(self.triage_queue),
            "below_threshold": self.below_threshold,
            "thresholds": {
                "triage": TRIAGE_THRESHOLD,
                "priority": PRIORITY_THRESHOLD,
            },
            "reduction_ratio": (
                round(1 - (len(self.triage_queue) / self.unique_indicators), 4)
                if self.unique_indicators
                else 0.0
            ),
            "graph": self.graph.to_dict(),
            "protected_inventory": self.protected_summary,
            "interpretation": (
                "reduction_ratio is the share of unique indicators the relevance model "
                "removed from the analyst queue. It is a workload figure, not an accuracy "
                "figure: it says nothing about whether the removed indicators were "
                "irrelevant, only that the model scored them below the triage threshold."
            ),
        }


class CtiPipeline:
    """Runs collectors over local snapshots and produces operational output."""

    def __init__(
        self,
        snapshot_dir: Path,
        produced: str = "",
        protected: ProtectedRegistry | None = None,
    ) -> None:
        self.snapshot_dir = Path(snapshot_dir)
        self.produced = produced or date.today().isoformat()
        #: Optional dependency inventory. Supplying one enables the only scoring
        #: branch measured to generalize beyond the hand-written vocabulary; see
        #: docs/detections/RECALL.md.
        self.protected = protected
        #: Candidate rules drafted by the most recent `write_outputs` call.
        #: Kept on the pipeline rather than folded into the report, so that
        #: writing artifacts cannot change the report a previous run produced.
        self.last_draft_count = 0

    def collect(self) -> List[CollectionResult]:
        results: List[CollectionResult] = []
        for stem, collector_cls in sorted(COLLECTORS.items()):
            collector = collector_cls(collected=self.produced)
            results.append(collector.collect(self.snapshot_dir / f"{stem}.jsonl"))
        return results

    def run(self) -> PipelineReport:
        report = PipelineReport(produced=self.produced)
        report.collection = self.collect()

        graph = PivotGraph()
        for result in report.collection:
            report.total_raw_indicators += len(result.indicators)
            graph.add_all(result.indicators)
        report.unique_indicators = len(graph.nodes)

        for indicator in graph.nodes.values():
            verdict = score_indicator(
                indicator.value,
                indicator_type=indicator.type.value,
                context=indicator.context,
                protected=self.protected,
            )
            indicator.relevance = verdict.score
            indicator.relevance_reasons = verdict.reasons
            if verdict.is_priority:
                report.priority_queue.append(indicator)
            if verdict.is_triage_worthy:
                report.triage_queue.append(indicator)
            else:
                report.below_threshold += 1

        report.priority_queue.sort(key=lambda i: (-i.relevance, i.key))
        report.triage_queue.sort(key=lambda i: (-i.relevance, i.key))
        report.graph = graph.build()
        report.protected_summary = (
            self.protected.to_dict()
            if self.protected
            else {"source": "none supplied", "names_indexed": 0}
        )
        return report

    def write_outputs(self, report: PipelineReport, out_dir: Path) -> Dict[str, Path]:
        """Write the operational artifacts. Returns the paths written."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        written: Dict[str, Path] = {}

        summary_path = out_dir / "collection_summary.json"
        summary_path.write_text(emit.to_json(report.summary()), encoding="utf-8")
        written["summary"] = summary_path

        queue_path = out_dir / "triage_queue.json"
        queue_path.write_text(
            emit.to_json([i.to_dict() for i in report.triage_queue]), encoding="utf-8"
        )
        written["triage_queue"] = queue_path

        stix_path = out_dir / "indicators.stix.json"
        stix_path.write_text(
            emit.to_json(emit.to_stix_bundle(report.triage_queue, self.produced)),
            encoding="utf-8",
        )
        written["stix"] = stix_path

        lookup_path = out_dir / "siem_lookup.csv"
        lookup_path.write_text(emit.to_siem_lookup(report.triage_queue), encoding="utf-8")
        written["siem_lookup"] = lookup_path

        drafts_dir = out_dir / "candidate_rules"
        drafts_dir.mkdir(exist_ok=True)
        draft_count = 0
        for cluster in report.graph.clusters:
            members = [
                report.graph.nodes[key]
                for key in cluster.members
                if key in report.graph.nodes
            ]
            priority_members = [m for m in members if m.relevance >= TRIAGE_THRESHOLD]
            if not priority_members:
                continue
            draft = emit.to_candidate_sigma(
                priority_members, cluster_id=cluster.cluster_id, produced=self.produced
            )
            if not draft:
                continue
            safe = cluster.cluster_id.replace(":", "_").replace("/", "_")[:60]
            (drafts_dir / f"candidate_{safe}.yml").write_text(draft, encoding="utf-8")
            draft_count += 1
        written["candidate_rules"] = drafts_dir
        self.last_draft_count = draft_count
        return written
