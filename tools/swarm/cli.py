"""CLI interface for the Adversarial Swarm Intelligence Engine."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .autonomous import AutonomousOrchestrator
from .config import OperatorDirective, SafetyConstraints
from .critic import SwarmCritic
from .detectors import SigmaDetector, YaraDetector
from .orchestrator import SwarmOrchestrator
from .prompt_engine import PromptEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m tools.swarm.cli",
        description="Adversarial Swarm Intelligence: Controlled Multi-Agent Detection Boundary Testing",
    )
    parser.add_argument(
        "--target",
        choices=["yara", "sigma"],
        default="sigma",
        help="Target detection rule family to evaluate ('yara' or 'sigma', default: 'sigma')",
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
        "--autonomous",
        action="store_true",
        help="Run autonomous continuous sparring mode",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of continuous sparring iterations (default: 10)",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Custom operator threat prompt directive to test immediately",
    )
    parser.add_argument(
        "--self-heal",
        action="store_true",
        help="Enable autonomous self-healing loop to synthesize rule patches and threat intelligence cables",
    )
    parser.add_argument(
        "--campaign",
        type=str,
        default=None,
        help="Run multi-stage kill-chain intrusion campaign (e.g. 'infostealer', 'ransomware')",
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

    if args.campaign:
        from .campaign import CampaignOrchestrator
        from .cable_writer import CableWriter
        print(f"[*] Initializing Multi-Stage Kill Chain Campaign: {args.campaign.upper()}")
        print("[*] Simulating 5-stage MITRE ATT&CK intrusion lifecycle...")
        orchestrator = CampaignOrchestrator()

        if args.autonomous:
            print(f"[*] Deploying Autonomous Kill-Chain Sparring ({args.iterations} campaigns)...")
            cable_writer = CableWriter()
            authored_cables = []

            def camp_cb(idx: int, res):
                intercept_str = f"Intercepted at {res.interception_stage} ({res.interception_technique})" if res.intercepted else "UNCONTAINED BREACH"
                print(f"    [Camp {idx:02d}] {intercept_str:<45} | DoD: {res.depth_of_defense_score:.2f}")
                # Author campaign cable
                cpath = cable_writer.write_campaign_cable(res)
                authored_cables.append(cpath)

            results = orchestrator.run_autonomous_campaigns(
                iterations=args.iterations,
                campaign_name=f"{args.campaign.capitalize()}-Sparring",
                self_heal=args.self_heal,
                campaign_callback=camp_cb,
            )

            total_runs = len(results)
            intercepted_runs = sum(1 for r in results if r.intercepted)
            avg_dod = sum(r.depth_of_defense_score for r in results) / total_runs if total_runs else 0.0

            print(f"\n[+] Autonomous Kill-Chain Sparring Complete!")
            print(f"    - Campaigns Evaluated: {total_runs}")
            print(f"    - Intercepted by Layered Net: {intercepted_runs}/{total_runs} ({(intercepted_runs/total_runs)*100:.1f}%)")
            print(f"    - Average Depth-of-Defense (DoD) Score: {avg_dod:.2f}")
            print(f"    - Cables Authored & Cataloged: {len(authored_cables)} in docs/cables/INDEX.md")
            return 0

        def stage_callback(res):
            status = "[!] EVADED  " if res.evasion_gap else "[+] DETECTED"
            print(f"    [Stage {res.stage_number}: {res.stage_name:<17}] {status} | Technique: {res.technique_id} | Rule: {res.rule_name[:40]}...")

        campaign_result = orchestrator.run_campaign(
            campaign_name=f"{args.campaign.capitalize()}-Intrusion-Flow",
            campaign_id="CAMP-2026-001",
            evasion_at_stages=[2],  # Stage 2 uses pcalua LOLBin evasion to test defense-in-depth
            self_heal=args.self_heal,
            callback=stage_callback,
        )

        print("\n[+] Campaign Simulation Complete!")
        print(f"    - Total Stages Evaluated: {campaign_result.total_stages}")
        print(f"    - Intercepted by Layered Defense: {campaign_result.intercepted}")
        print(f"    - Interception Point: {campaign_result.interception_stage} ({campaign_result.interception_technique})")
        print(f"    - Depth-of-Defense Score: {campaign_result.depth_of_defense_score:.2f}")

        cable_writer = CableWriter()
        cable_path = cable_writer.write_campaign_cable(campaign_result)
        print(f"    [+] Authored Multi-Stage Intelligence Cable: {cable_path}")
        return 0

    directive = OperatorDirective(
        target=args.target,
        max_cycles=args.max_cycles,
        variants_per_cycle=args.variants_per_cycle,
        output_dir=args.output_dir,
    )

    print(f"[*] Initializing Adversarial Swarm for target: {args.target}")
    print(f"[*] Safety containment: RFC 2606 reserved domains only | Local sandbox execution only")

    # 1. Custom Single-Prompt Mode
    if args.prompt:
        print(f"[*] Executing Custom Directive: \"{args.prompt}\"")
        engine = PromptEngine()
        variant = engine.generate_from_prompt(args.prompt, target_type=args.target)
        critic = SwarmCritic(directive.safety)
        verdict = critic.evaluate(variant)

        print(f"    [Critic Gate] Passed: {verdict.passed} ({verdict.reason})")
        if not verdict.passed:
            return 1

        detector = YaraDetector() if args.target == "yara" else SigmaDetector()
        detection = detector.evaluate(variant)
        status = "[+] DETECTED" if detection.detected else "[!] EVASION GAP"
        print(f"    [Detector Verdict] {status}")
        return 0

    # 2. Autonomous Continuous Sparring Mode
    if args.autonomous:
        print(f"[*] Deploying Autonomous Continuous Sparring ({args.iterations} iterations)...")
        auto_orch = AutonomousOrchestrator(directive)

        def on_iter(item):
            status = "[+] DETECTED" if item["detected"] else ("[!] EVASION GAP" if item["critic_passed"] else "[X] CRITIC BLOCKED")
            print(f"    [Iter {item['iteration']:02d}] {status} | Axis: {item['axis']:<12} | Resilience: {item['cumulative_resilience']*100:.1f}%")
            print(f"             Prompt: \"{item['prompt']}\"")
            if item.get("healing") and item["healing"].get("healed"):
                print(f"             [+] SELF-HEALED! Synthesized patch & authored cable: {item['healing']['cable_path']}")

        summary = auto_orch.run_autonomous(iterations=args.iterations, on_iteration=on_iter, self_heal=args.self_heal)
        print("\n[+] Autonomous Sparring Complete!")
        print(f"    - Iterations Run: {summary['iterations_run']}")
        print(f"    - Critic Approved: {summary['critic_approved']}")
        print(f"    - Detected Count: {summary['detected_count']}")
        print(f"    - Final Resilience Score: {summary['final_resilience'] * 100:.1f}%")
        print(f"    - Saved history to: {args.output_dir / f'boundary_history_{args.target}.json'}")
        return 0

    # 3. Standard Closed-Loop Campaign Mode
    print(f"[*] Max cycles: {directive.max_cycles} | Max variants/cycle: {directive.variants_per_cycle}")
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
