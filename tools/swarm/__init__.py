"""Adversarial Swarm Intelligence Engine.

Controlled multi-agent test harness for continuous detection boundary mapping
and automated rule resilience evaluation.
"""

from .config import OperatorDirective, SafetyConstraints
from .models import Variant, CriticVerdict, DetectionResult, BoundaryFinding, BoundaryMap
from .orchestrator import SwarmOrchestrator

__all__ = [
    "OperatorDirective",
    "SafetyConstraints",
    "Variant",
    "CriticVerdict",
    "DetectionResult",
    "BoundaryFinding",
    "BoundaryMap",
    "SwarmOrchestrator",
]
