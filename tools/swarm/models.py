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
