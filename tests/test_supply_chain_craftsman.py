"""Unit tests for SupplyChainCraftsman: DPRK Contagious Interview tradecraft generator."""

import json
import unittest
from pathlib import Path

from tools.swarm.craftsmen.supply_chain_craftsman import SupplyChainCraftsman
from tools.swarm.critic import SwarmCritic
from tools.swarm.detectors import SigmaDetector, YaraDetector

ROOT = Path(__file__).resolve().parents[1]


class SupplyChainCraftsmanTests(unittest.TestCase):
    def setUp(self):
        self.craftsman = SupplyChainCraftsman()
        self.critic = SwarmCritic()
        self.yara_detector = YaraDetector(rule_path=ROOT / "rules" / "yara" / "developer_malicious_package_hooks.yar")
        self.sigma_detector = SigmaDetector(rule_path=ROOT / "rules" / "sigma" / "proc_creation_macos_dev_credential_theft.yml")

    def test_cycle_1_package_hook_variants_pass_critic(self):
        variants = self.craftsman.generate_variants(cycle=1)
        self.assertGreaterEqual(len(variants), 3)
        for var in variants:
            self.assertEqual(var.target_type, "yara")
            verdict = self.critic.evaluate(var)
            self.assertTrue(verdict.passed, f"Variant {var.mutation_name} failed critic: {verdict.reason}")
            # Ensure detections fire on package hooks
            det_res = self.yara_detector.evaluate(var)
            self.assertTrue(det_res.detected, f"YARA failed to detect {var.mutation_name}")

    def test_cycle_2_workstation_credential_variants_pass_critic(self):
        variants = self.craftsman.generate_variants(cycle=2)
        self.assertGreaterEqual(len(variants), 4)
        for var in variants:
            self.assertEqual(var.target_type, "sigma")
            verdict = self.critic.evaluate(var)
            self.assertTrue(verdict.passed, f"Variant {var.mutation_name} failed critic: {verdict.reason}")

        # The credential harvesting variants should trigger the macOS credential Sigma rule
        aws_scrape = next(v for v in variants if v.mutation_name == "proc_macos_node_scrape_aws_creds")
        det = self.sigma_detector.evaluate(aws_scrape)
        self.assertTrue(det.detected, f"Sigma failed to detect {aws_scrape.mutation_name}")

        ssh_scrape = next(v for v in variants if v.mutation_name == "proc_macos_python_read_ssh_keys")
        det = self.sigma_detector.evaluate(ssh_scrape)
        self.assertTrue(det.detected, f"Sigma failed to detect {ssh_scrape.mutation_name}")

    def test_cycle_3_advanced_obfuscation_and_cloud_recon(self):
        variants = self.craftsman.generate_variants(cycle=3)
        self.assertGreaterEqual(len(variants), 3)
        for var in variants:
            verdict = self.critic.evaluate(var)
            self.assertTrue(verdict.passed, f"Variant {var.mutation_name} failed critic: {verdict.reason}")


if __name__ == "__main__":
    unittest.main()
