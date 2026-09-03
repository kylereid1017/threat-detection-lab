"""Data models for Adversarial Swarm Intelligence Engine."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Union


@dataclass
class Variant:
    """A generated synthetic attack variant targeting a specific detection rule."""
    id: str
    target_type: str  # "yara" or "sigma"
    axis: str         # "structural", "syntax", "obfuscation", "lolbin", "encoding"
    mutation_name: str
    description: str
    payload: Union[str, Dict[str, Any]]
    cycle: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CriticVerdict:
    """Pre-flight quality, realism, and safety evaluation of a variant."""
    variant_id: str
    passed: bool
    reason: str
    safety_violations: List[str] = field(default_factory=list)
    syntax_valid: bool = True


@dataclass
class DetectionResult:
    """Outcome of running a variant against the targeted detection rule."""
    variant_id: str
    rule_name: str
    detected: bool
    matched_elements: List[str] = field(default_factory=list)
    details: str = ""


@dataclass
class BoundaryFinding:
    """Identified detection boundary or blind spot discovered by the swarm."""
    axis: str
    mutation_name: str
    detected: bool
    evasion_gap_found: bool
    root_cause: str
    policy_recommendation: str
    confidence: str = "HIGH"  # "HIGH", "MEDIUM", "LOW"
    target_rule: str = ""
    target_type: str = ""
    cycle: int = 1
    variant_id: str = ""


@dataclass
class BoundaryMap:
    """Aggregated quantitative detection boundary map and tuning recommendations."""
    target_rule: str
    target_type: str
    cycles_completed: int
    total_generated: int
    critic_approved: int
    detected_count: int
    evaded_count: int
    resilience_score: float
    findings: List[BoundaryFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Composite multi-event telemetry models (EPIC 3)
# ---------------------------------------------------------------------------


@dataclass
class TelemetryEvent:
    """A single, schema-typed Windows telemetry record.

    Models the union of event families needed for correlation analytics:
    Process Creation (Sysmon EID 1 / Security 4688), Module/Image Load
    (Sysmon EID 7), Process Access (Sysmon EID 10), File System Activity
    (Sysmon EID 11), and PowerShell Script Block (EID 4104).
    """

    event_id: int
    channel: str
    utc_time: str
    fields: Dict[str, Any] = field(default_factory=dict)
    provider: str = ""
    description: str = ""

    def epoch(self) -> float:
        """Parses ``utc_time`` (``YYYY-MM-DD HH:MM:SS[.fff]``) into epoch seconds."""
        from datetime import datetime, timezone

        text = self.utc_time.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
        raise ValueError(f"Unparseable UtcTime: {self.utc_time!r}")

    def to_record(self) -> Dict[str, Any]:
        """Flattens the event into a single SIEM-style record for query evaluation."""
        record: Dict[str, Any] = {"EventID": self.event_id, "Channel": self.channel, "UtcTime": self.utc_time}
        record.update(self.fields)
        return record

    def to_variant(self, axis: str = "correlation", mutation_name: str = "", cycle: int = 1) -> "Variant":
        """Bridges a telemetry event into a legacy single-event :class:`Variant`."""
        import uuid as _uuid

        return Variant(
            id=f"evt-{_uuid.uuid4().hex[:8]}",
            target_type="sigma",
            axis=axis,
            mutation_name=mutation_name or f"event_{self.event_id}",
            description=self.description or f"Telemetry EID {self.event_id}",
            payload=self.to_record(),
            cycle=cycle,
        )


@dataclass
class EventSequence:
    """An ordered stream of correlated telemetry events sharing a timeline."""

    sequence_id: str
    events: List[TelemetryEvent] = field(default_factory=list)
    description: str = ""

    def add(self, event: TelemetryEvent) -> "EventSequence":
        self.events.append(event)
        return self

    def to_records(self) -> List[Dict[str, Any]]:
        return [e.to_record() for e in self.events]

    def sorted_by_time(self) -> List[TelemetryEvent]:
        return sorted(self.events, key=lambda e: e.epoch())


@dataclass
class CorrelationStage:
    """One component of a temporal correlation rule."""

    name: str
    technique_id: str = ""
    rule_yaml: Optional[str] = None
    rule_path: Optional[str] = None
    event_id: Optional[int] = None


@dataclass
class CorrelationRule:
    """A multi-event correlation analytic evaluated over a bounded time window."""

    name: str
    stages: List[CorrelationStage] = field(default_factory=list)
    timespan_seconds: int = 300
    ordered: bool = True
    technique_id: str = ""
    description: str = ""


@dataclass
class MultiEventResult:
    """Outcome of evaluating a single Sigma rule across an event sequence."""

    rule_name: str
    matched: bool
    matched_event_indices: List[int] = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationResult:
    """Outcome of evaluating a temporal correlation rule across an event sequence."""

    rule_name: str
    matched: bool
    within_window: bool
    stage_matches: Dict[str, List[int]] = field(default_factory=dict)
    selected_indices: List[int] = field(default_factory=list)
    span_seconds: Optional[float] = None
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Directed-acyclic-graph state machine models (EPIC 2)
# ---------------------------------------------------------------------------


@dataclass
class NodeVisit:
    """Record of the detection engine visiting one node of the intrusion DAG."""

    node_id: str
    stage_name: str
    technique_id: str
    telemetry_kind: str
    detected: bool
    is_secondary: bool
    t_offset_seconds: float
    evasion_gap: bool = False
    detail: str = ""


@dataclass
class GraphWalkResult:
    """Aggregate result of a single walk through the detection DAG."""

    graph_name: str
    walk_id: str
    visits: List[NodeVisit] = field(default_factory=list)
    intercepted: bool = False
    interception_node: Optional[str] = None
    interception_technique: Optional[str] = None
    depth_of_defense_score: float = 0.0
    mttd_seconds: Optional[float] = None
    reached_objective: bool = False
    contained: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class StageResult:
    """Outcome of a single stage in an attack kill chain campaign."""
    stage_number: int
    stage_name: str
    tactic: str
    technique_id: str
    rule_name: str
    target_type: str
    variant: Variant
    critic_verdict: CriticVerdict
    detection_result: DetectionResult
    evasion_gap: bool


@dataclass
class CampaignResult:
    """Outcome of an end-to-end multi-stage intrusion campaign."""
    campaign_id: str
    campaign_name: str
    stages: List[StageResult] = field(default_factory=list)
    intercepted: bool = False
    interception_stage: Optional[str] = None
    interception_technique: Optional[str] = None
    completed_stages: int = 0
    total_stages: int = 5
    depth_of_defense_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
