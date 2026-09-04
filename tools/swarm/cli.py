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
        "--synthesize-trends",
        action="store_true",
        help="Synthesize all accumulated threat cables and boundary results into a strategic meta-intelligence cable",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Run the DAG correlation state machine (Epic 2) with defense-in-depth scoring",
    )
    parser.add_argument(
        "--export-layer",
        action="store_true",
        help="Export a MITRE ATT&CK Navigator coverage layer (layer.json) from all evaluated rules",
    )
    parser.add_argument(
        "--validate-gate",
        action="store_true",
        help="Run the deterministic zero-false-positive validation gate over the fixture corpus",
    )
    parser.add_argument(
        "--benchmark-snr",
        action="store_true",
        help="Benchmark signal-to-noise: precision/recall against a high-volume benign corpus",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=2500,
        help="Benign background events to generate for --benchmark-snr (default: 2500)",
    )
    parser.add_argument(
        "--attack-variants",
        type=int,
        default=14,
        help="Novel attack permutations to add to the --benchmark-snr corpus (default: 14)",
    )
    parser.add_argument(
        "--profile-siem",
        action="store_true",
        help="Profile query complexity across CrowdStrike LogScale, Splunk SPL, and Elastic Lucene",
    )
    parser.add_argument(
        "--export-d3fend",
        action="store_true",
        help="Export the dual-layer MITRE ATT&CK / D3FEND countermeasure matrix (d3fend_layer.json)",
    )
    parser.add_argument(
        "--replay-telemetry",
        action="store_true",
        help="Replay real-world telemetry (EVTX/JSONL) through Sigma rules and correlation analytics",
    )
    parser.add_argument(
        "--corpus-path",
        type=Path,
        default=None,
        help="Path to telemetry file (.evtx or .jsonl) for --replay-telemetry (default: tests/fixtures/telemetry/mordor_lsass_dump.jsonl)",
    )
    parser.add_argument(
        "--is-benign",
        action="store_true",
        help="Mark telemetry corpus as benign baseline to measure empirical false-positive rate",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=300,
        help="Correlation sliding window in seconds for --replay-telemetry (default: 300)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs" / "swarm" / "results",
        help="Directory to save boundary map JSON and campaign reports",
    )
    return parser.parse_args()


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    args = parse_args()

    if args.replay_telemetry:
        from .telemetry_replay import TelemetryReplayEngine
        engine = TelemetryReplayEngine()
        root = Path(__file__).resolve().parents[2]
        target_path = args.corpus_path or (root / "tests" / "fixtures" / "telemetry" / "mordor_lsass_dump.jsonl")
        if not target_path.is_absolute():
            target_path = root / target_path
        print(f"[*] Replaying real-world telemetry corpus: {target_path.name} ...")
        is_benign = args.is_benign or ("benign" in str(target_path).lower())
        report = engine.replay_file(target_path, is_benign=is_benign, window_seconds=args.window)
        print(report.to_markdown())
        out = args.output_dir / "telemetry_replay.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.to_json(), encoding="utf-8")
        print(f"\n[+] Wrote machine-readable ICD 203 replay report to {out}")
        return 0

    if args.benchmark_snr:
        from .noise_floor import run_benchmark
        print(f"[*] Generating {args.events} benign enterprise background events...")
        print(f"[*] Adding {args.attack_variants} novel attack permutations to the corpus...")
        report = run_benchmark(
            benign_count=args.events, attack_variants=args.attack_variants
        )
        print(report.to_markdown())
        out = args.output_dir / "noise_floor.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.to_json(), encoding="utf-8")
        print(f"\n[+] Wrote machine-readable metrics to {out}")
        return 0

    if args.profile_siem:
        from .siem_profiler import SiemQueryProfiler
        print("[*] Compiling analytics across LogScale, Splunk, and Lucene backends...")
        print("[*] Benchmarking query latencies against enterprise background corpus...")
        report = SiemQueryProfiler().benchmark_and_calibrate(corpus_size=args.events)
        print(report.to_markdown())
        out = args.output_dir / "siem_profile.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.to_json(), encoding="utf-8")
        print(f"\n[+] Wrote machine-readable profile to {out}")
        return 0

    if args.export_d3fend:
        from .d3fend_mapper import D3fendMapper
        print("[*] Building dual-layer MITRE ATT&CK / D3FEND assessment matrix...")
        mapper = D3fendMapper()
        report = mapper.build()
        print(report.to_markdown())
        path = mapper.export(out_path=args.output_dir / "d3fend_layer.json")
        print(f"\n[+] Wrote {path}")
        print(f"    - Techniques mapped: {report.mapped_count}/{len(report.mappings)}")
        print(f"    - Identifier collisions: {len(report.collisions)}")
        return 0

    if args.validate_gate:
        from .validate_gate import ZeroFalsePositiveGate
        print("[*] Running Detection-as-Code zero-false-positive validation gate...")
        report = ZeroFalsePositiveGate().run()
        print(report.to_markdown())
        return 0 if report.passed else 1

    if args.export_layer:
        from .export_layer import MitreLayerExporter
        print("[*] Exporting MITRE ATT&CK Navigator coverage layer...")
        exporter = MitreLayerExporter()
        path = exporter.export(out_path=args.output_dir / "layer.json")
        import json as _json
        layer = _json.loads(path.read_text(encoding="utf-8"))
        print(f"[+] Wrote {path}")
        print(f"    - Rules evaluated: {layer['metadata'][1]['value']}")
        print(f"    - Techniques covered: {len(layer['techniques'])}")
        return 0

    if args.graph:
        from .graph_engine import GraphEngine
        print("[*] Initializing DAG Correlation State Machine (Epic 2)...")
        engine = GraphEngine()

        def walk_cb(idx: int, res) -> None:
            outcome = (
                f"Intercepted at {res.interception_node} ({res.interception_technique})"
                if res.intercepted else "UNCONTAINED BREACH"
            )
            mttd = f"{res.mttd_seconds:.0f}s" if res.mttd_seconds is not None else "n/a"
            print(f"    [Walk {idx:02d}] {outcome:<48} | DoD: {res.depth_of_defense_score:.2f} | MTTD: {mttd}")

        results = engine.run_walks(iterations=args.iterations, walk_callback=walk_cb)
        total = len(results)
        contained = sum(1 for r in results if r.contained)
        avg_dod = sum(r.depth_of_defense_score for r in results) / total if total else 0.0
        detected_mttds = [r.mttd_seconds for r in results if r.mttd_seconds is not None]
        avg_mttd = sum(detected_mttds) / len(detected_mttds) if detected_mttds else None
        print("\n[+] Graph Correlation Walks Complete!")
        print(f"    - Walks Evaluated: {total}")
        print(f"    - Contained by Layered Net: {contained}/{total} ({(contained / total) * 100:.1f}%)")
        print(f"    - Average Depth-of-Defense (DoD): {avg_dod:.2f}")
        print(f"    - Mean Time-to-Detect (MTTD): {avg_mttd:.0f}s" if avg_mttd is not None else "    - MTTD: n/a")
        return 0

    if args.synthesize_trends:
        from .synthesizer import StrategicSynthesizer
        print("[*] Initiating Automated Strategic Threat Intelligence Synthesis...")
        synthesizer = StrategicSynthesizer()
        cable_path, stats = synthesizer.synthesize()
        print(f"\n[+] Successfully Synthesized Strategic Cable: {cable_path}")
        print(f"    - Cable Identifier: {stats['cable_id']}")
        print(f"    - Cables Ingested: {stats['cables_ingested']}")
        print(f"    - Evaluated Empirical Probes: {stats['total_evaluations']}")
        print(f"    - Baseline Resilience: {stats['resilience_rate']:.1%}")
        print(f"    - Discovered Evasion Gaps: {stats['gaps_discovered']}")
        print(f"    - Multi-Stage Campaign Containment: {stats['containment_rate']:.1%}")
        print(f"    - Average Depth-of-Defense (DoD): {stats['average_depth_of_defense']:.2f}")
        print(f"    - Discovered Clusters:")
        for k, v in stats['cluster_counts'].items():
            print(f"      * {k}: {v}")
        return 0

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
