"""Autonomous Orchestrator: Continuous closed-loop sparring against detection rules."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .analyst import SwarmAnalyst
from .config import OperatorDirective
from .critic import SwarmCritic
from .detectors import BaseDetector, SigmaDetector, YaraDetector
from .models import BoundaryFinding, CriticVerdict, DetectionResult, Variant
from .adapter import SwarmAdapter
from .prompt_engine import PromptEngine


class AutonomousOrchestrator:
    """Runs autonomous continuous sparring sessions modeling an endless wave of attack permutations."""

    def __init__(self, directive: OperatorDirective, prompt_engine: Optional[PromptEngine] = None, adapter: Optional[SwarmAdapter] = None) -> None:
        directive.validate()
        self.directive = directive
        self.prompt_engine = prompt_engine or PromptEngine()
        self.critic = SwarmCritic(safety=directive.safety)
        self.analyst = SwarmAnalyst()
        self.adapter = adapter or SwarmAdapter()

        if directive.target == "yara":
            self.detector: BaseDetector = YaraDetector()
        else:
            self.detector = SigmaDetector()

    def run_autonomous(
        self,
        iterations: int = 10,
        on_iteration: Optional[Callable[[Dict[str, Any]], None]] = None,
        self_heal: bool = False,
    ) -> Dict[str, Any]:
        """Executes N iterations of continuous threat hypothesis generation and evaluation."""
        history: List[Dict[str, Any]] = []
        approved_count = 0
        detected_count = 0
        evaded_count = 0
        all_findings: List[BoundaryFinding] = []

        target_rule_name = getattr(self.detector, "target_rule_name", self.directive.target)

        for i in range(1, iterations + 1):
            prompt, variant = self.prompt_engine.generate_novel_hypothesis(
                target_type=self.directive.target,
                index=i,
            )

            # 1. Critic pre-flight gate
            verdict = self.critic.evaluate(variant)

            # 2. Detector evaluation
            if verdict.passed:
                approved_count += 1
                detection = self.detector.evaluate(variant)
                if detection.detected:
                    detected_count += 1
                else:
                    evaded_count += 1
            else:
                detection = DetectionResult(
                    variant_id=variant.id,
                    rule_name=target_rule_name,
                    detected=False,
                    details=f"Blocked by Critic: {verdict.reason}",
                )

            # 3. Analyst attribution
            findings = self.analyst.analyze_cycle(
                cycle_results=[(variant, verdict, detection)],
                target_rule=target_rule_name,
                target_type=self.directive.target,
            )
            # 4. Adapter self-healing loop (if enabled and gap detected)
            healing_info: Optional[Dict[str, Any]] = None
            if self_heal and findings and findings[0].evasion_gap_found:
                healed, cable_path, patch_diff = self.adapter.heal_gap(
                    finding=findings[0],
                    variant=variant,
                    detector=self.detector,
                    apply_patch=True,
                )
                if healed:
                    healing_info = {
                        "healed": True,
                        "cable_path": str(cable_path) if cable_path else None,
                        "patch_diff": patch_diff,
                    }
                    # Refresh detector with patched rule
                    if self.directive.target == "sigma":
                        self.detector = SigmaDetector()
                    else:
                        self.detector = YaraDetector()

            cum_resilience = (detected_count / approved_count) if approved_count > 0 else 0.0

            item: Dict[str, Any] = {
                "iteration": i,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "prompt": prompt,
                "variant_id": variant.id,
                "mutation_name": variant.mutation_name,
                "axis": variant.axis,
                "critic_passed": verdict.passed,
                "critic_reason": verdict.reason,
                "detected": detection.detected,
                "evasion_gap": (findings[0].evasion_gap_found if findings else False),
                "healing": healing_info,
                "cumulative_resilience": round(cum_resilience, 3),
            }
            history.append(item)

            if on_iteration:
                on_iteration(item)

        final_resilience = (detected_count / approved_count) if approved_count > 0 else 0.0

        summary = {
            "target_type": self.directive.target,
            "target_rule": target_rule_name,
            "iterations_run": iterations,
            "total_generated": iterations,
            "critic_approved": approved_count,
            "detected_count": detected_count,
            "evaded_count": evaded_count,
            "final_resilience": round(final_resilience, 3),
            "history": history,
        }

        self._persist_history(summary)
        return summary

    def _persist_history(self, summary: Dict[str, Any]) -> None:
        """Saves time-series boundary history artifact to disk."""
        out_dir = Path(self.directive.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        hist_path = out_dir / f"boundary_history_{self.directive.target}.json"
        hist_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
