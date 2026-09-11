"""Orchestrator: closed-loop coordination of mutation, gating, detection, and attribution."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from .analyst import SwarmAnalyst
from .config import OperatorDirective
from .craftsmen.base import BaseCraftsman
from .craftsmen.process_craftsman import ProcessCraftsman
from .craftsmen.svg_craftsman import SvgCraftsman
from .critic import SwarmCritic
from .detectors import BaseDetector, SigmaDetector, YaraDetector
from .models import BoundaryFinding, BoundaryMap, CriticVerdict, DetectionResult, Variant


class SwarmOrchestrator:
    """Coordinates the closed loop: Craftsmen -> Critic -> Detector -> Analyst -> Adapter."""

    def __init__(self, directive: OperatorDirective) -> None:
        directive.validate()
        self.directive = directive
        self.critic = SwarmCritic(safety=directive.safety)
        self.analyst = SwarmAnalyst()

        # Wire up target-specific Craftsman and Detector
        if directive.target == "yara":
            self.craftsman: BaseCraftsman = SvgCraftsman()
            self.detector: BaseDetector = YaraDetector()
        else:
            self.craftsman = ProcessCraftsman()
            self.detector = SigmaDetector()

    def run(self) -> Tuple[BoundaryMap, List[Tuple[Variant, CriticVerdict, DetectionResult]]]:
        """Executes the closed-loop adversarial testing run."""
        all_results: List[Tuple[Variant, CriticVerdict, DetectionResult]] = []
        all_findings: List[BoundaryFinding] = []
        adapter_feedback: List[str] = []

        target_rule_name = getattr(self.detector, "target_rule_name", self.directive.target)

        for cycle in range(1, self.directive.max_cycles + 1):
            # Craftsman generation (objective axes come from the directive)
            variants = self.craftsman.generate_variants(cycle=cycle, feedback=adapter_feedback)

            # Cap variants per cycle according to directive
            variants = variants[: self.directive.variants_per_cycle]

            cycle_results: List[Tuple[Variant, CriticVerdict, DetectionResult]] = []

            for variant in variants:
                # 3. Critic pre-flight gate
                verdict = self.critic.evaluate(variant)

                if verdict.passed:
                    # 4. Detector evaluation
                    detection = self.detector.evaluate(variant)
                else:
                    # Rejected by Critic (not submitted to Detector)
                    detection = DetectionResult(
                        variant_id=variant.id,
                        rule_name=target_rule_name,
                        detected=False,
                        details=f"Rejected by Critic: {verdict.reason}",
                    )

                cycle_results.append((variant, verdict, detection))

            all_results.extend(cycle_results)

            # 5. Analyst extraction
            cycle_findings = self.analyst.analyze_cycle(
                cycle_results=cycle_results,
                target_rule=target_rule_name,
                target_type=self.directive.target,
            )
            all_findings.extend(cycle_findings)

            # 6. Adapter synthesis: feedback for next cycle
            evaded_in_cycle = [f for f in cycle_findings if f.evasion_gap_found]
            adapter_feedback = [f.mutation_name for f in evaded_in_cycle]

        # Generate comprehensive boundary map
        boundary_map = self.analyst.generate_boundary_map(
            target_rule=target_rule_name,
            target_type=self.directive.target,
            cycles_completed=self.directive.max_cycles,
            all_results=all_results,
            all_findings=all_findings,
        )

        # Save artifacts
        self._save_results(boundary_map)

        return boundary_map, all_results

    def _save_results(self, boundary_map: BoundaryMap) -> None:
        """Persists the machine-readable boundary map and campaign report."""
        out_dir = Path(self.directive.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # JSON map
        json_path = out_dir / f"boundary_map_{self.directive.target}.json"
        json_path.write_text(boundary_map.to_json(), encoding="utf-8", newline="\n")

        # Markdown report
        md_path = out_dir / f"campaign_report_{self.directive.target}.md"
        md_content = self._format_markdown_report(boundary_map)
        md_path.write_text(md_content, encoding="utf-8", newline="\n")

    def _format_markdown_report(self, b_map: BoundaryMap) -> str:
        rate = b_map.detection_rate_on_approved
        rate_str = "n/a (not measured)" if rate is None else f"{rate * 100:.1f}%"
        lines = [
            f"# Detection Boundary Campaign Report - {b_map.target_rule}",
            "",
            f"**Target Type:** `{b_map.target_type}` | **Cycles Completed:** `{b_map.cycles_completed}`  ",
            f"**Total Variants Generated:** `{b_map.total_generated}` | **Critic Approved:** `{b_map.critic_approved}`  ",
            f"**Detected:** `{b_map.detected_count}` | **Evaded (Gaps Found):** `{b_map.evaded_count}`  ",
            f"**Detection Rate (Critic-approved variants):** `{rate_str}`",
            "",
            "---",
            "",
            "## Findings & Boundary Attributions",
            "",
            "| Axis | Mutation | Status | Root Cause | Recommendation |",
            "|---|---|---|---|---|",
        ]
        for f in b_map.findings:
            status = "✅ Detected" if f.detected else "🚨 Evasion Gap"
            lines.append(
                f"| {f.axis} | `{f.mutation_name}` | {status} | {f.root_cause} | {f.policy_recommendation} |"
            )
        lines.append("")
        return "\n".join(lines)
