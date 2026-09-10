"""Unit tests for Multi-Campaign DAG State Machine & GraphEngine."""

import unittest
from pathlib import Path

from tools.swarm.graph_engine import GraphEngine

ROOT = Path(__file__).resolve().parents[1]


class MultiCampaignGraphEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = GraphEngine(repo_root=ROOT)

    def test_campaign_registry_contains_all_three_campaigns(self):
        self.assertIn("clickfix", self.engine.CAMPAIGN_REGISTRY)
        self.assertIn("contagious_interview", self.engine.CAMPAIGN_REGISTRY)
        self.assertIn("frontier_ai_cluster", self.engine.CAMPAIGN_REGISTRY)

    def test_all_campaign_graphs_are_valid_and_acyclic(self):
        for key in self.engine.CAMPAIGN_REGISTRY:
            graph = self.engine.build_graph_by_key(key)
            self.assertIsNotNone(graph)
            # validate_acyclic raises ValueError if any cycle exists
            graph.validate_acyclic()
            self.assertGreaterEqual(len(graph.nodes), 5)
            self.assertGreaterEqual(len(graph.edges), 4)
            self.assertEqual(len(graph.primary_order), 5)
            self.assertTrue(graph.start)
            self.assertTrue(graph.objective)
            self.assertTrue(graph.threat_actor)

    def test_graph_serialization_to_workbench_dict(self):
        for key in self.engine.CAMPAIGN_REGISTRY:
            graph = self.engine.build_graph_by_key(key)
            wb_dict = graph.to_workbench_dict()
            self.assertIn("nodes", wb_dict)
            self.assertIn("edges", wb_dict)
            self.assertIn("primary_order", wb_dict)
            self.assertIn("secondary_of", wb_dict)
            self.assertIn("threat_actor", wb_dict)
            self.assertIn("diamond_model", wb_dict)

            # Check that nodes have UI coordinates
            for nid, node_info in wb_dict["nodes"].items():
                self.assertIn("x", node_info)
                self.assertIn("y", node_info)
                self.assertIn("label", node_info)
                self.assertIn("tech", node_info)

    def test_walk_clickfix_campaign(self):
        graph = self.engine.build_clickfix_graph()
        res = self.engine.walk(graph=graph, evasion_at=["execution"])
        self.assertTrue(res.intercepted)
        self.assertGreater(res.depth_of_defense_score, 0.0)
        self.assertIsNotNone(res.mttd_seconds)

    def test_walk_contagious_interview_campaign(self):
        graph = self.engine.build_contagious_interview_graph()
        # Test clean run (no evasions)
        res_clean = self.engine.walk(graph=graph, evasion_at=[])
        self.assertTrue(res_clean.intercepted)
        self.assertEqual(res_clean.interception_node, "supply_ingress")

        # Test evasive run on supply ingress and workstation exec
        res_evasive = self.engine.walk(graph=graph, evasion_at=["supply_ingress", "workstation_exec"])
        self.assertTrue(res_evasive.intercepted)
        # Compensating secondary control or subsequent stage intercepts
        self.assertGreater(res_evasive.depth_of_defense_score, 0.0)

    def test_walk_frontier_ai_cluster_campaign(self):
        graph = self.engine.build_frontier_ai_cluster_graph()
        # Test run with container escape evasion
        res = self.engine.walk(graph=graph, evasion_at=["container_escape"])
        self.assertTrue(res.intercepted)
        self.assertGreater(res.depth_of_defense_score, 0.0)

    def test_run_walks_rotates_profiles(self):
        for key in self.engine.CAMPAIGN_REGISTRY:
            graph = self.engine.build_graph_by_key(key)
            results = self.engine.run_walks(iterations=4, graph=graph)
            self.assertEqual(len(results), 4)
            for r in results:
                self.assertIsNotNone(r.depth_of_defense_score)

    def test_run_walks_profile_offset_rotates_evasion(self):
        """Successive single-walk offsets must exercise different evasion profiles."""
        graph = self.engine.build_default_graph()
        outcomes = set()
        for offset in range(6):
            result = self.engine.run_walks(iterations=1, graph=graph, profile_offset=offset)[0]
            outcomes.add(result.interception_node if result.intercepted else "UNCONTAINED")
        self.assertGreater(
            len(outcomes), 1, f"All single-walk offsets produced the same outcome: {outcomes}"
        )

    def test_always_miss_detectors_cannot_claim_interception(self):
        from unittest.mock import MagicMock
        from tools.swarm.models import DetectionResult, CorrelationResult

        always_miss_detector = MagicMock()
        always_miss_detector.evaluate.return_value = DetectionResult("test", "test", detected=False, details="miss")

        self.engine._yara = always_miss_detector
        self.engine._yara_package = always_miss_detector
        for k in self.engine._sigma:
            self.engine._sigma[k] = always_miss_detector

        always_miss_correlator = MagicMock()
        always_miss_correlator.evaluate_correlation.return_value = CorrelationResult(
            rule_name="miss", matched=False, within_window=False, stage_matches={}, selected_indices=[]
        )
        self.engine.correlator = always_miss_correlator

        for key in self.engine.CAMPAIGN_REGISTRY:
            graph = self.engine.build_graph_by_key(key)
            res = self.engine.walk(graph=graph, evasion_at=list(graph.primary_order))
            self.assertFalse(res.intercepted, f"Campaign {key} falsely reported interception when all detectors miss")
            self.assertEqual(res.depth_of_defense_score, 0.0)


if __name__ == "__main__":
    unittest.main()

