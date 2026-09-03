"""Adversarial Swarm Intelligence Engine.

Controlled multi-agent test harness for continuous detection boundary mapping
and automated rule resilience evaluation.
"""

from .adapter import SwarmAdapter
from .autonomous import AutonomousOrchestrator
from .cable_writer import CableWriter
from .campaign import CampaignOrchestrator
from .config import OperatorDirective, SafetyConstraints
from .evaluator import MultiEventEvaluator, build_correlation_rule
from .export_layer import MitreLayerExporter, RuleCoverage
from .graph_engine import DetectionGraph, GraphEdge, GraphEngine, GraphNode
from .models import (
    Variant,
    CriticVerdict,
    DetectionResult,
    BoundaryFinding,
    BoundaryMap,
    StageResult,
    CampaignResult,
    TelemetryEvent,
    EventSequence,
    CorrelationStage,
    CorrelationRule,
    MultiEventResult,
    CorrelationResult,
    NodeVisit,
    GraphWalkResult,
)
from .orchestrator import SwarmOrchestrator
from .prompt_engine import PromptEngine
from .synthesizer import StrategicSynthesizer, StrategicReport
from .telemetry_generator import CommandLineMutator, CommandSpec, TelemetryGenerator, TelemetrySafetyError
from .validate_gate import GateReport, ZeroFalsePositiveGate

__all__ = [
    "OperatorDirective",
    "SafetyConstraints",
    "Variant",
    "CriticVerdict",
    "DetectionResult",
    "BoundaryFinding",
    "BoundaryMap",
    "StageResult",
    "CampaignResult",
    "TelemetryEvent",
    "EventSequence",
    "CorrelationStage",
    "CorrelationRule",
    "MultiEventResult",
    "CorrelationResult",
    "NodeVisit",
    "GraphWalkResult",
    "SwarmOrchestrator",
    "AutonomousOrchestrator",
    "CampaignOrchestrator",
    "PromptEngine",
    "SwarmAdapter",
    "CableWriter",
    "StrategicSynthesizer",
    "StrategicReport",
    "TelemetryGenerator",
    "CommandSpec",
    "CommandLineMutator",
    "TelemetrySafetyError",
    "MultiEventEvaluator",
    "build_correlation_rule",
    "GraphEngine",
    "DetectionGraph",
    "GraphNode",
    "GraphEdge",
    "MitreLayerExporter",
    "RuleCoverage",
    "ZeroFalsePositiveGate",
    "GateReport",
]
