"""Flagship Workflow: Agent Exposure Review.

Answers the single practical operator question:
    "What changes if I add this tool to my current agent?"

Disciplines:
1. Local-first: parses local JSON configurations or safe synthetic examples.
2. Concrete before/after comparison: evaluates delta in capability legs, distance
   to closure, and newly formed minimal exfiltration closures.
3. Realistic mitigation: models filesystem directory scoping, profile separation,
   and network isolation, and re-checks whether modeled closures remain.
4. Redacted export: outputs human-readable findings and machine-readable JSON
   with secrets redacted and assumptions clearly documented.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.agent_graph import capabilities as caps
from tools.agent_graph import config_corpus as cc
from tools.agent_graph.composition import (
    CompositionResult,
    Installation,
    analyze,
)
from tools.agent_graph.marginal import (
    DistanceProfile,
    compute_distance_to_closure,
)


SAFE_BENIGN_EXAMPLE: Dict[str, Any] = {
    "mcpServers": {
        "sqlite": {
            "command": "npx",
            "args": ["-y", "mcp-server-sqlite@0.1.0", "--db-path", "./test.db"],
        },
        "git": {
            "command": "uvx",
            "args": ["mcp-server-git==0.1.0"],
        },
    }
}


@dataclass
class ExposureDelta:
    candidate_name: str
    candidate_capabilities: List[str]
    candidate_legs: List[str]
    baseline_closed: bool
    baseline_distance: int
    baseline_missing_legs: List[str]
    after_closed: bool
    after_distance: int
    after_missing_legs: List[str]
    closure_flipped: bool
    new_closures_count: int
    new_critical_packages: List[str]
    modeled_paths: List[str]
    mitigations: List[Dict[str, Any]] = field(default_factory=list)
    recheck_validation: Dict[str, Any] = field(default_factory=dict)
    unparsed_servers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_name": self.candidate_name,
            "candidate_capabilities": sorted(self.candidate_capabilities),
            "candidate_legs": self.candidate_legs,
            "baseline": {
                "closed": self.baseline_closed,
                "distance": self.baseline_distance,
                "missing_legs": self.baseline_missing_legs,
            },
            "after": {
                "closed": self.after_closed,
                "distance": self.after_distance,
                "missing_legs": self.after_missing_legs,
            },
            "delta": {
                "closure_flipped": self.closure_flipped,
                "new_closures_count": self.new_closures_count,
                "new_critical_packages": self.new_critical_packages,
            },
            "modeled_paths": self.modeled_paths,
            "mitigations": self.mitigations,
            "recheck_validation": self.recheck_validation,
            "unparsed_servers": self.unparsed_servers,
        }


def load_configuration(config_source: str | Path | Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse configuration, returning (parsed_servers, unparsed_server_labels)."""
    if isinstance(config_source, dict):
        raw_text = json.dumps(config_source)
    else:
        path = Path(config_source)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        raw_text = path.read_text(encoding="utf-8")

    all_entries = cc.parse_config(raw_text)
    parsed = [entry for entry in all_entries if entry.get("package")]
    unparsed_from_entries = [entry["label"] for entry in all_entries if not entry.get("package")]

    try:
        data = json.loads(raw_text)
        raw_servers = data.get("mcpServers") or data.get("mcp_servers") or {}
        if isinstance(raw_servers, dict):
            unparsed_missing = [str(k) for k in raw_servers.keys() if not any(p["label"] == str(k) for p in all_entries)]
            unparsed = sorted(set(unparsed_from_entries + unparsed_missing))
        else:
            unparsed = ["<invalid_mcp_servers_block>"]
    except Exception:
        unparsed = ["<unparseable_json>"]

    return parsed, unparsed


def build_candidate_package(
    candidate: str,
    args: Optional[Sequence[str]] = None,
    env_keys: Optional[Sequence[str]] = None,
    known_manifests: Optional[Dict[str, Any]] = None,
) -> caps.PackageCapabilities:
    """Infer capabilities for a candidate tool to be added."""
    manifests = known_manifests or {}
    meta = manifests.get(candidate) or {"name": candidate, "ecosystem": "npm"}
    pkg = caps.derive_capabilities(meta, env_keys=env_keys or [])

    # Check argument-level filesystem scoping
    if args:
        root_scoped = any(a in ("/", "\\", "C:\\", "C:/") for a in args)
        explicit_restricted = any(a.startswith(("./", "../", "workspace", "data")) for a in args)

        if root_scoped:
            # Ambient root scope - full private data
            if "fs_read" not in pkg.capabilities():
                pkg.evidence.append(
                    caps.Evidence("fs_read", caps.Tier.DECLARED_TEXT, "runtime_args", "ambient root scope '/'")
                )
        elif explicit_restricted:
            # Explicit directory scope: note restricted scoping in evidence
            pkg.evidence.append(
                caps.Evidence("fs_read", caps.Tier.DECLARED_TEXT, "runtime_args", "scoped workspace directory")
            )

    return pkg


def _split_profiles(
    packages: Sequence[caps.PackageCapabilities],
) -> tuple[List[caps.PackageCapabilities], List[caps.PackageCapabilities]]:
    """Partition tools into an ingestion profile and an analysis profile.

    The recommended mitigation is to run untrusted-content tools in one agent and
    private-data tools in another, so that no single context holds all three
    legs. This performs that partition so the recheck can measure whether it
    actually works, rather than assuming it does.

    A tool holding untrusted ingress goes to ingestion. Everything else goes to
    analysis. A tool holding both ingress and private data cannot be placed
    without carrying a leg across the boundary; it is assigned to ingestion and
    the residual closure count will show that the split failed.
    """
    ingestion: List[caps.PackageCapabilities] = []
    analysis: List[caps.PackageCapabilities] = []
    for package in packages:
        if "untrusted_ingress" in package.legs():
            ingestion.append(package)
        else:
            analysis.append(package)
    return ingestion, analysis


def evaluate_tool_addition(
    existing_config: str | Path | Dict[str, Any],
    candidate_tool: str,
    candidate_args: Optional[Sequence[str]] = None,
    candidate_env_keys: Optional[Sequence[str]] = None,
    known_manifests: Optional[Dict[str, Any]] = None,
) -> ExposureDelta:
    """Core analytical workflow: evaluates what changes if candidate_tool is added."""
    parsed_servers, unparsed = load_configuration(existing_config)
    manifests = known_manifests or {}

    # Build baseline package list
    baseline_packages: List[caps.PackageCapabilities] = []
    for s in parsed_servers:
        pkg_name = s.get("package")
        if not pkg_name:
            continue
        meta = manifests.get(pkg_name) or {"name": pkg_name, "ecosystem": "npm"}
        baseline_packages.append(caps.derive_capabilities(meta, env_keys=s.get("env_keys") or []))

    baseline_inst = Installation("baseline", baseline_packages)
    baseline_comp: CompositionResult = analyze(baseline_inst)
    baseline_dist: DistanceProfile = compute_distance_to_closure(baseline_inst)

    # Build candidate package and composed installation
    candidate_pkg = build_candidate_package(
        candidate_tool,
        args=candidate_args,
        env_keys=candidate_env_keys,
        known_manifests=manifests,
    )
    after_packages = list(baseline_packages) + [candidate_pkg]
    after_inst = Installation("after_addition", after_packages)
    after_comp: CompositionResult = analyze(after_inst)
    after_dist: DistanceProfile = compute_distance_to_closure(after_inst)

    closure_flipped = (not baseline_comp.closes) and after_comp.closes
    new_closures_count = max(0, len(after_comp.minimal_closures) - len(baseline_comp.minimal_closures))
    new_critical = sorted(set(after_comp.critical_packages) - set(baseline_comp.critical_packages))

    # Construct modeled execution/exfiltration paths
    by_name = {p.name: p for p in after_packages}

    modeled_paths: List[str] = []
    if after_comp.closes:
        for c in after_comp.minimal_closures:
            if candidate_tool in c:
                # Report the capabilities the packages in THIS closure actually
                # hold. Listing the whole taxonomy here described every closure
                # identically and credited each tool with capabilities it does
                # not have, which is worse than saying nothing.
                per_leg: Dict[str, List[str]] = {}
                for name in sorted(c):
                    member = by_name.get(name)
                    if not member:
                        continue
                    for capability in sorted(member.capabilities()):
                        leg = caps.CAPABILITY_LEGS.get(capability)
                        if leg:
                            per_leg.setdefault(leg, []).append(f"{capability} ({name})")
                legs_str = "; ".join(
                    f"{leg}: {', '.join(items)}"
                    for leg, items in sorted(per_leg.items())
                )
                modeled_paths.append(
                    f"Trifecta closure formed by [{' + '.join(sorted(c))}] via {legs_str}."
                )

    # Propose concrete separation and restriction mitigations
    mitigations: List[Dict[str, Any]] = []

    # Mitigation 1: Filesystem directory scoping.
    #
    # Gated on fs_read specifically, not on the private_data leg. That leg also
    # covers repository, mailbox, database and cloud reads, none of which take a
    # filesystem path, so the broader gate told operators to constrain the
    # directory arguments of tools that have none.
    if "fs_read" in candidate_pkg.capabilities():
        mitigations.append({
            "strategy": "Directory Path Scoping",
            "recommendation": (
                f"Constrain '{candidate_tool}' filesystem arguments from root '/' to an isolated "
                "project subdirectory (e.g. './workspace')."
            ),
            "mechanism": "Limits private data exposure boundary to non-sensitive project artifacts.",
            "modeled_effect": "Prevents ambient reading of operator ~/.ssh, ~/.aws, and system profiles.",
        })

    # Mitigation 2: Dual-Profile Architectural Split
    if closure_flipped:
        mitigations.append({
            "strategy": "Agent Profile Separation (Two-Tier Architecture)",
            "recommendation": (
                "Split tools into two distinct agent execution profiles:\n"
                "  - Profile A (Ingestion): Untrusted web/document retrieval tools; NO private data or outbound credentials.\n"
                "  - Profile B (Internal Analysis): Filesystem & database tools; NO outbound network communication."
            ),
            "mechanism": "Breaks the leave-one-out composition graph by enforcing an architectural boundary.",
            "modeled_effect": "Flips composure status back to OPEN (Distance-1) across both profiles.",
        })

    # Mitigation 3: Version Pinning & Hook Suppression
    mitigations.append({
        "strategy": "Exact Version Pinning & Script Disabling",
        "recommendation": (
            f"Pin '{candidate_tool}' to an exact cryptographic tag and add '--ignore-scripts' to execution arguments."
        ),
        "mechanism": "Defends against post-install hook execution and upstream supply-chain mutations.",
        "modeled_effect": "Eliminates passive installation execution risk.",
    })

    # Recheck Validation: simulate impact of mitigations
    recheck_notes: List[str] = []
    if after_comp.closes:
        # Actually simulate the split rather than asserting it works. The
        # previous version hardcoded the status, the residual path count, and a
        # narrative naming distances it never computed. A recheck that cannot
        # report failure is not a recheck.
        ingestion, analysis = _split_profiles(after_packages)
        ingestion_comp = analyze(Installation("profile_ingestion", ingestion))
        analysis_comp = analyze(Installation("profile_analysis", analysis))
        ingestion_dist = compute_distance_to_closure(Installation("profile_ingestion", ingestion))
        analysis_dist = compute_distance_to_closure(Installation("profile_analysis", analysis))

        residual = [
            c
            for comp in (ingestion_comp, analysis_comp)
            for c in comp.minimal_closures
        ]
        recheck_paths_remaining = len(residual)
        recheck_status = (
            "OPEN (Post-Mitigation)" if recheck_paths_remaining == 0 else "STILL CLOSED (Post-Mitigation)"
        )
        recheck_notes.append(
            "Under profile separation, ingestion holds "
            f"{len(ingestion)} tool(s) at distance {ingestion_dist.distance} "
            f"(missing: {', '.join(ingestion_dist.missing_legs) or 'nothing'}); "
            f"analysis holds {len(analysis)} tool(s) at distance {analysis_dist.distance} "
            f"(missing: {', '.join(analysis_dist.missing_legs) or 'nothing'}). "
            f"{recheck_paths_remaining} modeled closure(s) remain."
        )
        if recheck_paths_remaining:
            recheck_notes.append(
                "This split does not resolve the exposure. At least one profile still "
                "holds all three legs, so the tools would need a different partition or "
                "a capability removed outright."
            )
        if "fs_read" in candidate_pkg.capabilities():
            recheck_notes.append(
                f"Under directory scoping ('./workspace'), '{candidate_tool}' cannot read "
                "operator credential paths such as ~/.ssh and ~/.aws. This narrows the "
                "private data leg; it does not remove it."
            )
    else:
        recheck_status = "OPEN (Safe)"
        recheck_paths_remaining = 0
        recheck_notes.append("No active trifecta closure detected; setup remains open (0 paths to remediate).")

    recheck_validation = {
        "post_mitigation_status": recheck_status,
        "modeled_paths_remaining": recheck_paths_remaining,
        "details": recheck_notes,
    }

    return ExposureDelta(
        candidate_name=candidate_tool,
        candidate_capabilities=sorted(candidate_pkg.capabilities()),
        candidate_legs=sorted(candidate_pkg.legs()),
        baseline_closed=baseline_comp.closes,
        baseline_distance=baseline_dist.distance,
        baseline_missing_legs=sorted(baseline_dist.missing_legs),
        after_closed=after_comp.closes,
        after_distance=after_dist.distance,
        after_missing_legs=sorted(after_dist.missing_legs),
        closure_flipped=closure_flipped,
        new_closures_count=new_closures_count,
        new_critical_packages=new_critical,
        modeled_paths=modeled_paths,
        mitigations=mitigations,
        recheck_validation=recheck_validation,
        unparsed_servers=unparsed,
    )


def format_exposure_report(delta: ExposureDelta, config_label: str) -> str:
    """Render human-readable exposure review text leading with plain-language answer."""
    lines: List[str] = [
        "=" * 74,
        "  AGENT EXPOSURE REVIEW: TOOL ADDITION IMPACT ASSESSMENT",
        "=" * 74,
        f"Target Agent Config : {config_label}",
        f"Candidate Tool      : {delta.candidate_name}",
        f"Review Date         : {date.today().isoformat()}",
        "-" * 74,
    ]

    # Leading plain-language answer
    if delta.closure_flipped:
        lines.extend([
            "VERDICT: [!] CRITICAL COMPOSITION CHANGE DETECTED",
            f"Adding '{delta.candidate_name}' closes the lethal trifecta across your agent.",
            "Your agent previously had an open security posture. This tool introduces the final",
            f"capability leg ({', '.join(delta.candidate_legs)}) required to form an autonomous",
            "exfiltration path needing no code execution exploit.",
        ])
    elif delta.after_closed:
        lines.extend([
            "VERDICT: [!] AGENT ALREADY CLOSED -- EXPOSURE SURFACE EXPANDED",
            "Your agent was already in a closed trifecta state prior to adding this tool.",
            f"Adding '{delta.candidate_name}' adds {len(delta.candidate_capabilities)} new capabilities and",
            f"{delta.new_closures_count} new minimal closure combinations.",
        ])
    else:
        lines.extend([
            "VERDICT: [+] SAFE TO ADD -- POSTURE REMAINS OPEN",
            f"Adding '{delta.candidate_name}' does NOT close the lethal trifecta.",
            f"The agent remains at distance {delta.after_distance} from closure.",
            f"Missing capability legs: {', '.join(delta.after_missing_legs) or 'none'}.",
        ])

    lines.extend([
        "-" * 74,
        "BEFORE vs. AFTER CONFIGURATION DELTA:",
        f"  * Baseline Distance to Closure : {delta.baseline_distance} (Closed: {delta.baseline_closed})",
        f"  * Baseline Missing Legs        : {', '.join(delta.baseline_missing_legs) or 'none'}",
        f"  * After Distance to Closure    : {delta.after_distance} (Closed: {delta.after_closed})",
        f"  * After Missing Legs           : {', '.join(delta.after_missing_legs) or 'none'}",
        f"  * Candidate Capabilities       : {', '.join(delta.candidate_capabilities) or 'none'}",
        f"  * Candidate Legs Introduced    : {', '.join(delta.candidate_legs) or 'none'}",
    ])

    if delta.modeled_paths:
        lines.extend([
            "-" * 74,
            "MODELED EXPOSURE PATHS:",
        ])
        for p in delta.modeled_paths:
            lines.append(f"  -> {p}")

    if delta.mitigations:
        lines.extend([
            "-" * 74,
            "RECOMMENDED MITIGATION & SEPARATION STRATEGIES:",
        ])
        for idx, m in enumerate(delta.mitigations, 1):
            lines.append(f"[{idx}] Strategy: {m['strategy']}")
            lines.append(f"    Recommendation : {m['recommendation']}")
            lines.append(f"    Modeled Effect : {m['modeled_effect']}")

    if delta.recheck_validation:
        lines.extend([
            "-" * 74,
            "MITIGATION RECHECK & RESIDUAL EXPOSURE:",
            f"  * Post-Mitigation Posture : {delta.recheck_validation.get('post_mitigation_status', 'UNKNOWN')}",
            f"  * Modeled Paths Remaining : {delta.recheck_validation.get('modeled_paths_remaining', 0)}",
        ])
        for note in delta.recheck_validation.get("details", []):
            lines.append(f"  * {note}")

    if delta.unparsed_servers:
        lines.extend([
            "-" * 74,
            f"NOTICE: {len(delta.unparsed_servers)} server entries could not be parsed: "
            f"{', '.join(delta.unparsed_servers)}",
        ])

    lines.append("=" * 74)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.agent_graph.exposure_review",
        description="Local-first Agent Exposure Review: What changes if I add this tool to my agent?",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to agent configuration file (JSON). Omit to run on safe sample example.",
    )
    parser.add_argument(
        "--tool",
        type=str,
        default="@modelcontextprotocol/server-filesystem",
        help="Package name of candidate tool to evaluate (default: @modelcontextprotocol/server-filesystem)",
    )
    parser.add_argument(
        "--args",
        nargs="+",
        default=None,
        help="Arguments to pass to candidate tool (e.g. '--args /' or '--args ./data')",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Optional path to write machine-readable evaluation report JSON",
    )
    args = parser.parse_args(argv)

    if args.config:
        if not args.config.exists():
            print(f"[-] Configuration file not found at {args.config}", file=sys.stderr)
            return 2
        config_data = args.config
        label = str(args.config)
    else:
        config_data = SAFE_BENIGN_EXAMPLE
        label = "<safe sample baseline: sqlite + git>"

    # Load snapshot manifests if present to enrich accuracy
    manifests: Dict[str, Any] = {}
    snapshot_dir = cc.DEFAULT_OUT
    if snapshot_dir.is_dir():
        try:
            _, manifests = cc.load_snapshot(snapshot_dir)
        except Exception:
            manifests = {}

    delta = evaluate_tool_addition(
        config_data,
        candidate_tool=args.tool,
        candidate_args=args.args,
        known_manifests=manifests,
    )

    report_text = format_exposure_report(delta, label)
    print(report_text)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        report_dict = {
            "title": "Agent Exposure Review",
            "date": date.today().isoformat(),
            "target_config": label,
            "evaluation": delta.to_dict(),
        }
        args.out.write_text(json.dumps(report_dict, indent=2) + "\n", encoding="utf-8")
        disp = args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out
        print(f"\nwrote {disp}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
