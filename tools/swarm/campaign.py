"""Campaign Orchestrator: Autonomous Multi-Stage Kill Chain Simulator & Defense-in-Depth Engine."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List, Optional

from .adapter import SwarmAdapter
from .critic import SwarmCritic
from .detectors import SigmaDetector, YaraDetector
from .models import CampaignResult, StageResult
from .prompt_engine import PromptEngine

ROOT = Path(__file__).resolve().parents[2]


class CampaignOrchestrator:
    """Simulates realistic, multi-stage cyber intrusion campaigns across the MITRE ATT&CK matrix."""

    STAGE_RULES = {
        1: {
            "name": "Initial Access",
            "type": "yara",
            "rule_file": ROOT / "rules" / "yara" / "suspicious_active_content_svg.yar",
            "rule_name": "Suspicious_Active_Content_SVG_Attachment",
            "tactic": "Initial Access",
            "technique_id": "T1566.001",
        },
        2: {
            "name": "Execution",
            "type": "sigma",
            "rule_file": ROOT / "rules" / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml",
            "rule_name": "Suspicious Process Spawning From Explorer Run Prompt (ClickFix Pattern)",
            "tactic": "Execution",
            "technique_id": "T1204.002",
        },
        3: {
            "name": "Defense Evasion",
            "type": "sigma",
            "rule_file": ROOT / "rules" / "sigma" / "proc_creation_win_defense_evasion_tampering.yml",
            "rule_name": "Suspicious Event Log Clearing or Security Software Tampering",
            "tactic": "Defense Evasion",
            "technique_id": "T1070.001",
        },
        4: {
            "name": "Credential Access",
            "type": "sigma",
            "rule_file": ROOT / "rules" / "sigma" / "proc_creation_win_rundll32_lsass_dump.yml",
            "rule_name": "LSASS Process Memory Dump via Rundll32 Comsvcs.dll",
            "tactic": "Credential Access",
            "technique_id": "T1003.001",
        },
        5: {
            "name": "Persistence",
            "type": "sigma",
            "rule_file": ROOT / "rules" / "sigma" / "proc_creation_win_schtasks_persistence.yml",
            "rule_name": "Suspicious Scheduled Task Creation Spawning Shell or Script Engine",
            "tactic": "Persistence",
            "technique_id": "T1053.005",
        },
    }

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or ROOT
        self.prompt_engine = PromptEngine()
        self.critic = SwarmCritic()
        self.adapter = SwarmAdapter(repo_root=self.repo_root)

        # Detectors pool
        self._init_detectors()

    def _init_detectors(self) -> None:
        self.detectors = {
            1: YaraDetector(rule_path=self.STAGE_RULES[1]["rule_file"]),
            2: SigmaDetector(rule_path=self.STAGE_RULES[2]["rule_file"]),
            3: SigmaDetector(rule_path=self.STAGE_RULES[3]["rule_file"]),
            4: SigmaDetector(rule_path=self.STAGE_RULES[4]["rule_file"]),
            5: SigmaDetector(rule_path=self.STAGE_RULES[5]["rule_file"]),
        }

    def run_campaign(
        self,
        campaign_name: str = "Stealer-Lure-Intrusion",
        campaign_id: str = "CAMP-2026-001",
        evasion_at_stages: Optional[List[int]] = None,
        self_heal: bool = False,
        callback: Optional[Callable[[StageResult], None]] = None,
    ) -> CampaignResult:
        """Executes a 5-stage intrusion campaign evaluating defense-in-depth coverage."""
        evasion_at = evasion_at_stages or []
        stages_results: List[StageResult] = []
        intercepted = False
        first_intercept_stage: Optional[str] = None
        first_intercept_tech: Optional[str] = None
        completed_stages = 0

        dod_weights = {1: 1.0, 2: 0.8, 3: 0.6, 4: 0.4, 5: 0.2}
        dod_score = 0.0

        for stage_num in range(1, 6):
            cfg = self.STAGE_RULES[stage_num]
            is_evasive = stage_num in evasion_at
            st_name, tactic, tech_id, variant = self.prompt_engine.generate_stage_variant(
                stage=stage_num, cycle=1, evasive=is_evasive
            )

            # Pre-flight Critic gate
            critic_verdict = self.critic.evaluate(variant)
            if not critic_verdict.passed:
                continue

            # In-memory detector
            detector = self.detectors[stage_num]
            det_result = detector.evaluate(variant)
            is_gap = not det_result.detected

            stage_res = StageResult(
                stage_number=stage_num,
                stage_name=st_name,
                tactic=tactic,
                technique_id=tech_id,
                rule_name=cfg["rule_name"],
                target_type=cfg["type"],
                variant=variant,
                critic_verdict=critic_verdict,
                detection_result=det_result,
                evasion_gap=is_gap,
            )
            stages_results.append(stage_res)

            if det_result.detected and not intercepted:
                intercepted = True
                first_intercept_stage = st_name
                first_intercept_tech = tech_id
                dod_score = dod_weights[stage_num]

            if not is_gap:
                completed_stages += 1

            # Autonomous self-healing loop
            if is_gap and self_heal:
                from .models import BoundaryFinding
                finding = BoundaryFinding(
                    target_rule=cfg["rule_name"],
                    target_type=cfg["type"],
                    mutation_name=variant.mutation_name,
                    axis=variant.axis,
                    detected=False,
                    evasion_gap_found=True,
                    root_cause=f"Variant bypassed rule {cfg['rule_name']}",
                    policy_recommendation=f"Tune detection {cfg['rule_name']}",
                    confidence="HIGH",
                    cycle=1,
                    variant_id=variant.id,
                )
                success, cable_path, diff = self.adapter.heal_gap(
                    finding, variant, detector=detector, apply_patch=False
                )

            if callback:
                callback(stage_res)

        return CampaignResult(
            campaign_id=campaign_id,
            campaign_name=campaign_name,
            stages=stages_results,
            intercepted=intercepted,
            interception_stage=first_intercept_stage,
            interception_technique=first_intercept_tech,
            completed_stages=completed_stages,
            total_stages=5,
            depth_of_defense_score=dod_score,
        )

    def run_autonomous_campaigns(
        self,
        iterations: int = 5,
        campaign_name: str = "Autonomous-Kill-Chain-Sparring",
        self_heal: bool = False,
        stage_callback: Optional[Callable[[int, StageResult], None]] = None,
        campaign_callback: Optional[Callable[[int, CampaignResult], None]] = None,
    ) -> List[CampaignResult]:
        """Runs continuous simulated multi-stage intrusion campaigns with varying adversary evasion tactics."""
        results: List[CampaignResult] = []

        evasion_profiles = [
            [],
            [1],
            [2],
            [1, 2],
            [2, 3],
            [1, 2, 4],
            [2, 5],
            [1, 3],
        ]

        for i in range(1, iterations + 1):
            profile = evasion_profiles[(i - 1) % len(evasion_profiles)]
            camp_id = f"CAMP-2026-{i:03d}"

            def wrapped_stage_cb(stage_res: StageResult) -> None:
                if stage_callback:
                    stage_callback(i, stage_res)

            res = self.run_campaign(
                campaign_name=f"{campaign_name}-Run{i}",
                campaign_id=camp_id,
                evasion_at_stages=profile,
                self_heal=self_heal,
                callback=wrapped_stage_cb,
            )
            results.append(res)
            if campaign_callback:
                campaign_callback(i, res)

        return results
