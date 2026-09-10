"""Unit tests for CloudClusterCraftsman: Frontier AI Compute Cluster & Weight Defense."""

import unittest
from pathlib import Path

from tools.swarm.craftsmen.cloud_cluster_craftsman import CloudClusterCraftsman
from tools.swarm.critic import SwarmCritic
from tools.swarm.detectors import SigmaDetector

ROOT = Path(__file__).resolve().parents[1]


class CloudClusterCraftsmanTests(unittest.TestCase):
    def setUp(self):
        self.craftsman = CloudClusterCraftsman()
        self.critic = SwarmCritic()
        self.sigma_detector = SigmaDetector(rule_path=ROOT / "rules" / "sigma" / "proc_creation_cloud_imds_checkpoint_exfiltration.yml")

    def test_cycle_1_container_escape_variants(self):
        variants = self.craftsman.generate_variants(cycle=1)
        self.assertGreaterEqual(len(variants), 3)
        for var in variants:
            self.assertEqual(var.target_type, "sigma")
            verdict = self.critic.evaluate(var)
            self.assertTrue(verdict.passed, f"Variant {var.mutation_name} failed critic: {verdict.reason}")
            det = self.sigma_detector.evaluate(var)
            self.assertTrue(det.detected, f"Rule failed to detect container escape {var.mutation_name}")

    def test_cycle_2_imds_token_and_role_theft(self):
        variants = self.craftsman.generate_variants(cycle=2)
        self.assertGreaterEqual(len(variants), 3)
        for var in variants:
            verdict = self.critic.evaluate(var)
            self.assertTrue(verdict.passed, f"Variant {var.mutation_name} failed critic: {verdict.reason}")
        # Test IMDSv2 token retrieval
        token_req = next(v for v in variants if v.mutation_name == "proc_imdsv2_session_token_request")
        det = self.sigma_detector.evaluate(token_req)
        self.assertTrue(det.detected, f"Rule failed to detect IMDSv2 token request: {det.details}")

    def test_cycle_3_model_checkpoint_and_weight_exfiltration(self):
        variants = self.craftsman.generate_variants(cycle=3)
        self.assertGreaterEqual(len(variants), 3)
        for var in variants:
            verdict = self.critic.evaluate(var)
            self.assertTrue(verdict.passed, f"Variant {var.mutation_name} failed critic: {verdict.reason}")
        # Test S3 multipart weight exfiltration
        weight_exfil = next(v for v in variants if v.mutation_name == "proc_aws_s3_multipart_weight_exfil")
        det = self.sigma_detector.evaluate(weight_exfil)
        self.assertTrue(det.detected, f"Rule failed to detect model weight exfiltration: {det.details}")


if __name__ == "__main__":
    unittest.main()
