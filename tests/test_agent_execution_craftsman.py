"""Tests for AgentExecutionCraftsman and the AI Agent Execution Tier campaign graph."""

import unittest

from tools.swarm.craftsmen import AgentExecutionCraftsman
from tools.swarm.critic import SwarmCritic
from tools.swarm.graph_engine import GraphEngine


class AgentExecutionCraftsmanTests(unittest.TestCase):
    """Verifies that AgentExecutionCraftsman generates valid adversarial mutations."""

    def setUp(self):
        self.craftsman = AgentExecutionCraftsman()
        self.critic = SwarmCritic()

    def test_generate_variants_cycle_1_runners(self):
        variants = self.craftsman.generate_variants(cycle=1)
        self.assertGreaterEqual(len(variants), 5)
        names = [v.mutation_name for v in variants]
        self.assertIn("proc_agent_claude_npx_unpinned", names)
        self.assertIn("proc_agent_cursor_uvx_yes", names)
        self.assertIn("proc_agent_bunx_unpinned", names)
        self.assertIn("proc_agent_deno_dynamic_eval", names)

        for v in variants:
            self.assertEqual(v.target_type, "sigma")
            self.assertIn("CommandLine", v.payload)
            verdict = self.critic.evaluate(v)
            self.assertTrue(verdict.passed, f"Critic failed on {v.mutation_name}: {verdict.reason}")

    def test_generate_variants_cycle_2_alien_runtime(self):
        variants = self.craftsman.generate_variants(cycle=2)
        self.assertGreaterEqual(len(variants), 5)
        names = [v.mutation_name for v in variants]
        self.assertIn("proc_bun_temp_execution", names)
        self.assertIn("proc_bun_site_packages", names)
        self.assertIn("proc_bun_tmp_linux", names)
        self.assertIn("proc_bun_programdata_evasion", names)

        for v in variants:
            self.assertEqual(v.target_type, "sigma")
            verdict = self.critic.evaluate(v)
            self.assertTrue(verdict.passed, f"Critic failed on {v.mutation_name}: {verdict.reason}")

    def test_generate_variants_cycle_3_correlation(self):
        variants = self.craftsman.generate_variants(cycle=3)
        self.assertGreaterEqual(len(variants), 3)
        names = [v.mutation_name for v in variants]
        self.assertIn("corr_unpinned_then_aws_creds", names)
        self.assertIn("corr_unpinned_then_ssh_keys", names)
        self.assertIn("corr_delayed_evasion", names)

        for v in variants:
            self.assertEqual(v.target_type, "sigma")
            self.assertIn("stage_1", v.payload)
            self.assertIn("stage_2", v.payload)
            self.assertIn("delta_seconds", v.payload)


class AgentExecutionCampaignGraphTests(unittest.TestCase):
    """Verifies that the Agent Execution Tier campaign graph walks and scores correctly."""

    def setUp(self):
        self.engine = GraphEngine()

    def test_build_agent_execution_graph_structure(self):
        graph = self.engine.build_graph_by_key("agent_execution_infostealer")
        self.assertEqual(graph.campaign_id, "CAMP-AGENT-004")
        self.assertEqual(graph.start, "agent_ingress")
        self.assertEqual(graph.objective, "agent_exfil")
        self.assertEqual(len(graph.primary_order), 5)
        self.assertIn("agent_config_audit", graph.nodes)
        self.assertIn("agent_correlation", graph.nodes)
        graph.validate_acyclic()

    def test_walk_agent_execution_graph_uncontained_and_intercepted(self):
        graph = self.engine.build_graph_by_key("agent_execution_infostealer")
        # Baseline walk with no evasions: should be intercepted early
        result_baseline = self.engine.walk(graph=graph, evasion_at=[])
        self.assertTrue(result_baseline.intercepted)
        self.assertGreater(result_baseline.depth_of_defense_score, 0.0)

        # Walk with primary evasions on depth 1 & 2: secondary compensating controls should fire
        result_evasive = self.engine.walk(
            graph=graph,
            evasion_at=["agent_unpinned_exec", "agent_alien_runtime"],
        )
        self.assertTrue(result_evasive.intercepted)
        self.assertGreater(result_evasive.depth_of_defense_score, 0.0)
