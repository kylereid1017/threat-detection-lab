"""Adversarial Swarm Intelligence Engine.

Controlled multi-agent test harness for continuous detection boundary mapping
and automated rule resilience evaluation.
"""

from .adapter import SwarmAdapter
from .autonomous import AutonomousOrchestrator
from .cable_writer import CableWriter
from .config import OperatorDirective, SafetyConstraints
from .models import Variant, CriticVerdict, DetectionResult, BoundaryFinding, BoundaryMap
from .orchestrator import SwarmOrchestrator
from .prompt_engine import PromptEngine

__all__ = [
    "OperatorDirective",
    "SafetyConstraints",
    "Variant",
    "CriticVerdict",
    "DetectionResult",
    "BoundaryFinding",
    "BoundaryMap",
    "SwarmOrchestrator",
    "AutonomousOrchestrator",
    "PromptEngine",
    "SwarmAdapter",
    "CableWriter",
]
