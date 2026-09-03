"""CLI interface for the Adversarial Swarm Intelligence Engine."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import OperatorDirective, SafetyConstraints
from .orchestrator import SwarmOrchestrator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m tools.swarm.cli",
        description="Adversarial Swarm Intelligence: Controlled Multi-Agent Detection Boundary Testing",
    )
    parser.add_argument(
        "--target",
        choices=["yara", "sigma"],
        required=True,
        help="Target detection rule family to evaluate ('yara' or 'sigma')",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=3,
        help="Maximum closed-loop adaptation cycles to run (default: 3)",
    )
    parser.add_argument(
        "--variants-per-cycle",
        type=int,
        default=6,
        help="Maximum variants to generate per cycle (default: 6)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs" / "swarm" / "results",
        help="Directory to save boundary map JSON and campaign reports",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    directive = OperatorDirective(
        target=args.target,
        max_cycles=args.max_cycles,
        variants_per_cycle=args.variants_per_cycle,
        output_dir=args.output_dir,
    )

    print(f"[*] Initializing Adversarial Swarm for target: {args.target}")
    print(f"[*] Max cycles: {directive.max_cycles} | Max variants/cycle: {directive.variants_per_cycle}")
    print(f"[*] Safety containment: RFC 2606 reserved domains only | Local sandbox execution only")

    orchestrator = SwarmOrchestrator(directive)
    boundary_map, _ = orchestrator.run()

    print("\n[+] Swarm Run Complete!")
    print(f"    - Target Rule: {boundary_map.target_rule}")
    print(f"    - Total Generated: {boundary_map.total_generated}")
    print(f"    - Critic Approved: {boundary_map.critic_approved}")
    print(f"    - Detected: {boundary_map.detected_count}")
    print(f"    - Evaded (Gaps): {boundary_map.evaded_count}")
    print(f"    - Rule Resilience Score: {boundary_map.resilience_score * 100:.1f}%\n")

    print("[*] Boundary Findings:")
    for f in boundary_map.findings:
        status = "[+] DETECTED" if f.detected else "[!] EVASION GAP"
        print(f"    {status} {f.axis}/{f.mutation_name}")
        if f.evasion_gap_found:
            print(f"        -> Root Cause: {f.root_cause}")
            print(f"        -> Recommendation: {f.policy_recommendation}")

    print(f"\n[*] Persisted artifacts to: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
