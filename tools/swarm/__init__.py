"""Adversarial Swarm Intelligence Engine.

Controlled multi-agent test harness for continuous detection boundary mapping
and automated rule resilience evaluation.
"""

from .adapter import SwarmAdapter
from .autonomous import AutonomousOrchestrator
from .cable_writer import CableWriter
from .campaign import CampaignOrchestrator
from .config import OperatorDirective, SafetyConstraints
from .d3fend_mapper import D3fendMapper, D3fendReport, D3fendCountermeasure, TechniqueMapping
from .evaluator import MultiEventEvaluator, build_correlation_rule
from .export_layer import MitreLayerExporter, RuleCoverage
from .graph_engine import DetectionGraph, GraphEdge, GraphEngine, GraphNode
from .noise_floor import (
    DetectionMetricsCalculator,
    EnterpriseNoiseGenerator,
    LabelledEvent,
    NoiseFloorReport,
    RuleMetrics,
    run_benchmark,
)
from .siem_profiler import ProfilerReport, QueryProfile, SiemQueryProfiler
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
    "EnterpriseNoiseGenerator",
    "DetectionMetricsCalculator",
    "NoiseFloorReport",
    "RuleMetrics",
    "LabelledEvent",
    "run_benchmark",
    "SiemQueryProfiler",
    "QueryProfile",
    "ProfilerReport",
    "D3fendMapper",
    "D3fendReport",
    "D3fendCountermeasure",
    "TechniqueMapping",
]
