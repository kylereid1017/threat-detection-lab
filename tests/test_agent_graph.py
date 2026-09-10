"""Tests for capability derivation and composition analysis.

The composition claim is the load-bearing one: that a chain can close across
packages none of which closes it alone. Most of these tests exist to pin that
distinction, because if `composed` and `single_package` ever blur, the headline
measurement stops meaning anything.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.agent_graph.capabilities import (
    CAPABILITY_LEGS,
    Leg,
    Tier,
    capabilities_from_wiring,
    derive_capabilities,
    taxonomy_summary,
)
from tools.agent_graph.composition import (
    CLOSURE_COMPOSED,
    CLOSURE_NONE,
    CLOSURE_SINGLE_PACKAGE,
    CorpusComposition,
    Installation,
    analyze,
    build_graph,
)
from tools.agent_graph.config_corpus import extract_package, parse_config
from tools.agent_graph.verification import load_labels

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "docs" / "detections" / "evaluation-agent-composition.json"
VERIFICATION = ROOT / "docs" / "detections" / "evaluation-capability-taxonomy.json"


def pkg(name, deps=None, description="", env=None, scripts=None):
    record = {
        "name": name,
        "ecosystem": "npm",
        "description": description,
        "keywords": [],
        "manifest": {
            "dependencies": {d: "1" for d in (deps or [])},
            "scripts": {s: "x" for s in (scripts or [])},
            "bin": {},
        },
    }
    return derive_capabilities(record, env_keys=env or [])


class TaxonomyStructureTests(unittest.TestCase):
    def test_every_capability_maps_to_a_leg(self):
        legs = {Leg.PRIVATE_DATA, Leg.UNTRUSTED_INGRESS, Leg.EXFILTRATION}
        for capability, leg in CAPABILITY_LEGS.items():
            with self.subTest(capability=capability):
                self.assertIn(leg, legs)

    def test_all_three_legs_are_represented(self):
        self.assertEqual(len(set(CAPABILITY_LEGS.values())), 3)

    def test_summary_credits_the_framing_and_states_the_bound(self):
        summary = taxonomy_summary()
        self.assertIn("Willison", summary["framing_credit"])
        self.assertIn("lower bound", summary["lower_bound_note"])


class DerivationTests(unittest.TestCase):
    def test_dependency_evidence_is_exact_not_substring(self):
        """Substring matching on dependency names caused most earlier false positives."""
        matched = pkg("x", deps=["pg"])
        unmatched = pkg("y", deps=["pg-connection-string-parser"])
        self.assertIn("database_read", matched.capabilities())
        self.assertNotIn(
            "database_read",
            {
                e.capability
                for e in unmatched.evidence
                if e.source == "dependency"
            },
        )

    def test_wiring_evidence_recovers_what_dependencies_miss(self):
        """Thin wrappers reach services with the built-in client and declare nothing."""
        bare = pkg("srv", deps=["@modelcontextprotocol/sdk"])
        wired = pkg("srv", deps=["@modelcontextprotocol/sdk"], env=["SLACK_BOT_TOKEN"])
        self.assertEqual(bare.legs(), set())
        self.assertEqual(len(wired.legs()), 3)

    def test_wiring_names_the_variable_that_produced_it(self):
        found = capabilities_from_wiring(["GITHUB_PERSONAL_ACCESS_TOKEN"])
        self.assertTrue(found)
        self.assertTrue(all(term == "GITHUB_PERSONAL_ACCESS_TOKEN" for _, term in found))

    def test_unknown_env_var_grants_nothing(self):
        self.assertEqual(capabilities_from_wiring(["MY_APP_SETTING"]), [])

    def test_package_name_counts_as_declared_text(self):
        """Packages with no registry manifest must still score, or rates understate."""
        derived = pkg("mcp-server-filesystem-helper")
        self.assertIn("fs_read", derived.capabilities())

    def test_evidence_is_attributable(self):
        derived = pkg("x", deps=["puppeteer"])
        evidence = derived.evidence_for("browser_automation")
        self.assertTrue(evidence)
        self.assertEqual(evidence[0].source, "dependency")
        self.assertEqual(evidence[0].detail, "puppeteer")

    def test_min_tier_filters_evidence(self):
        derived = pkg("github tool", deps=["pg"], description="github repository access")
        self.assertIn("repo_read", derived.capabilities(Tier.DECLARED_TEXT))
        self.assertNotIn("repo_read", derived.capabilities(Tier.DECLARED_DEPENDENCY))


class CompositionTests(unittest.TestCase):
    def _install(self, packages):
        return Installation(identifier="test", packages=packages)

    def test_composed_closure_is_distinguished_from_single_package(self):
        """The entire thesis lives in this distinction."""
        composed = analyze(
            self._install(
                [
                    pkg("reader", deps=["glob"]),
                    pkg("ingest", deps=["cheerio"]),
                    pkg("sender", deps=["nodemailer"]),
                ]
            )
        )
        self.assertEqual(composed.closure_type, CLOSURE_COMPOSED)
        self.assertEqual(composed.single_package_closers, [])

        solo = analyze(self._install([pkg("all-in-one", deps=["puppeteer", "glob"])]))
        self.assertEqual(solo.closure_type, CLOSURE_SINGLE_PACKAGE)

    def test_two_legs_is_not_a_closure(self):
        result = analyze(
            self._install([pkg("reader", deps=["glob"]), pkg("ingest", deps=["cheerio"])])
        )
        self.assertEqual(result.closure_type, CLOSURE_NONE)
        self.assertFalse(result.closes)

    def test_minimal_closures_are_minimal(self):
        result = analyze(
            self._install(
                [
                    pkg("a", deps=["glob"]),
                    pkg("b", deps=["cheerio"]),
                    pkg("c", deps=["nodemailer"]),
                    pkg("d", deps=["glob"]),
                ]
            )
        )
        self.assertTrue(result.minimal_closures)
        self.assertTrue(all(len(c) == 3 for c in result.minimal_closures))

    def test_critical_packages_appear_in_every_closure(self):
        result = analyze(
            self._install(
                [
                    pkg("only_ingest", deps=["cheerio"]),
                    pkg("reader_a", deps=["glob"]),
                    pkg("reader_b", deps=["glob"]),
                    pkg("sender", deps=["nodemailer"]),
                ]
            )
        )
        self.assertIn("only_ingest", result.critical_packages)
        self.assertNotIn("reader_a", result.critical_packages)

    def test_sole_supplier_is_identified(self):
        result = analyze(
            self._install(
                [
                    pkg("a", deps=["glob"]),
                    pkg("b", deps=["cheerio"]),
                    pkg("c", deps=["nodemailer"]),
                ]
            )
        )
        self.assertEqual(len(result.sole_suppliers), 3)

    def test_empty_installation_is_safe(self):
        result = analyze(self._install([]))
        self.assertEqual(result.closure_type, CLOSURE_NONE)
        self.assertEqual(result.minimal_closures, [])

    def test_result_disclaims_accusation(self):
        result = analyze(self._install([pkg("a", deps=["puppeteer", "glob"])]))
        self.assertIn("not a claim that any package is malicious", result.to_dict()["interpretation"])

    def test_graph_edges_reference_existing_nodes(self):
        installation = self._install(
            [pkg("a", deps=["glob"]), pkg("b", deps=["nodemailer"])]
        )
        graph = build_graph(installation)
        ids = {n["id"] for n in graph["nodes"]}
        for edge in graph["edges"]:
            with self.subTest(edge=edge):
                self.assertIn(edge["source"], ids)
                self.assertIn(edge["target"], ids)

    def test_corpus_summary_separates_composed_from_total(self):
        results = [
            analyze(self._install([pkg("solo", deps=["puppeteer", "glob"])])),
            analyze(
                self._install(
                    [
                        pkg("a", deps=["glob"]),
                        pkg("b", deps=["cheerio"]),
                        pkg("c", deps=["nodemailer"]),
                    ]
                )
            ),
            analyze(self._install([pkg("quiet", deps=[])])),
        ]
        summary = CorpusComposition(results=results).summary()
        self.assertEqual(summary["installations"], 3)
        self.assertEqual(summary["closing_trifecta"], 2)
        self.assertEqual(summary["composed_closures"], 1)
        self.assertEqual(summary["single_package_closures"], 1)


class ConfigParsingTests(unittest.TestCase):
    def test_runner_arguments_resolve_to_the_package(self):
        self.assertEqual(
            extract_package("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]),
            "@modelcontextprotocol/server-filesystem",
        )
        self.assertEqual(extract_package("uvx", ["mcp-server-git"]), "mcp-server-git")

    def test_version_pins_are_stripped(self):
        self.assertEqual(extract_package("npx", ["-y", "pkg@1.2.3"]), "pkg")
        self.assertEqual(extract_package("npx", ["-y", "@scope/pkg@1.2.3"]), "@scope/pkg")

    def test_non_runner_commands_resolve_to_nothing(self):
        self.assertIsNone(extract_package("node", ["dist/index.js"]))

    def test_malformed_command_types_do_not_raise(self):
        """Configurations in the wild are hand-written and unvalidated."""
        self.assertIsNone(extract_package(["npx"], None))
        self.assertIsNone(extract_package(None, "not-a-list"))
        self.assertIsNone(extract_package(42, []))

    def test_env_keys_are_captured_for_wiring_evidence(self):
        entries = parse_config(
            json.dumps(
                {
                    "mcpServers": {
                        "gh": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-github"],
                            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "x"},
                        }
                    }
                }
            )
        )
        self.assertEqual(entries[0]["env_keys"], ["GITHUB_PERSONAL_ACCESS_TOKEN"])

    def test_non_config_json_yields_nothing(self):
        self.assertEqual(parse_config('{"name": "not a config"}'), [])
        self.assertEqual(parse_config("not json at all"), [])


class LabelSetTests(unittest.TestCase):
    def test_labels_load_and_use_known_capabilities(self):
        labels = load_labels()
        self.assertGreaterEqual(len(labels), 20)
        for label in labels:
            with self.subTest(package=label.name):
                self.assertLessEqual(label.capabilities, set(CAPABILITY_LEGS))
                self.assertTrue(label.basis, "every label must record its basis")
                self.assertTrue(label.source_url)

    def test_negative_control_is_present(self):
        """A label with no capabilities catches a taxonomy that invents them."""
        labels = load_labels()
        self.assertTrue(
            any(not label.capabilities for label in labels),
            "the label set needs at least one package with no capabilities",
        )


class PublishedMeasurementTests(unittest.TestCase):
    def test_composition_results_are_declared_external(self):
        if not RESULTS.is_file():
            self.skipTest("composition analysis has not been run in this checkout")
        data = json.loads(RESULTS.read_text(encoding="utf-8"))
        self.assertEqual(data["measurement_class"], "external")
        self.assertIn("lower_bound_note", data["summary"])

    def test_taxonomy_verification_is_published_with_its_failures(self):
        if not VERIFICATION.is_file():
            self.skipTest("taxonomy verification has not been run in this checkout")
        data = json.loads(VERIFICATION.read_text(encoding="utf-8"))
        self.assertIn("by_tier", data)
        self.assertIn("false_positives", data)
        self.assertIn("false_negatives", data)
        self.assertFalse(
            data["dependency_only_beats_all_evidence"],
            "if this flips, the default evidence tier should move with it",
        )


from tools.agent_graph.marginal import (
    compute_coinstallation_graph,
    compute_distance_sensitivity_band,
    compute_distance_to_closure,
    compute_marginal_closure_contributions,
    compute_population_distance_distribution,
)


class MarginalRiskTests(unittest.TestCase):
    """Tests for marginal composition risk, distance-to-closure, and co-installation."""

    def test_distance_to_closure(self):
        # 3 legs -> distance 0
        p_all = pkg("p_all", deps=["pg", "puppeteer"])
        inst_closed = Installation("closed", [p_all])
        prof_closed = compute_distance_to_closure(inst_closed)
        self.assertEqual(prof_closed.distance, 0)
        self.assertTrue(prof_closed.closes)
        self.assertEqual(prof_closed.missing_legs, set())

        # 2 legs -> distance 1 (missing untrusted_ingress)
        p_priv_exfil = pkg("p_priv_exfil", deps=["pg", "nodemailer"])
        inst_dist1 = Installation("dist1", [p_priv_exfil])
        prof_dist1 = compute_distance_to_closure(inst_dist1)
        self.assertEqual(prof_dist1.distance, 1)
        self.assertFalse(prof_dist1.closes)
        self.assertIn(Leg.UNTRUSTED_INGRESS, prof_dist1.missing_legs)

        # 1 leg -> distance 2
        p_priv = pkg("p_priv", deps=["pg"])
        inst_dist2 = Installation("dist2", [p_priv])
        prof_dist2 = compute_distance_to_closure(inst_dist2)
        self.assertEqual(prof_dist2.distance, 2)
        self.assertFalse(prof_dist2.closes)

        # 0 legs -> distance 3
        p_none = pkg("p_none")
        inst_dist3 = Installation("dist3", [p_none])
        prof_dist3 = compute_distance_to_closure(inst_dist3)
        self.assertEqual(prof_dist3.distance, 3)
        self.assertFalse(prof_dist3.closes)

    def test_population_distance_distribution(self):
        p_all = pkg("p_all", deps=["pg", "puppeteer"])
        p_priv_exfil = pkg("p_priv_exfil", deps=["pg", "nodemailer"])
        p_priv = pkg("p_priv", deps=["pg"])
        p_none = pkg("p_none")

        installations = [
            Installation("c1", [p_all]),
            Installation("c2", [p_priv_exfil]),
            Installation("c3", [p_priv]),
            Installation("c4", [p_none]),
        ]

        summary = compute_population_distance_distribution(installations)
        self.assertEqual(summary["total_installations"], 4)
        self.assertEqual(summary["closed_count"], 1)
        self.assertEqual(summary["open_count"], 3)
        self.assertEqual(summary["distance_distribution"]["1"]["count"], 1)
        self.assertEqual(summary["distance_distribution"]["2"]["count"], 1)
        self.assertEqual(summary["distance_distribution"]["3"]["count"], 1)
        self.assertEqual(summary["missing_leg_breakdown_distance_1"][Leg.UNTRUSTED_INGRESS]["count"], 1)

    def test_marginal_closure_contributions(self):
        # Open installation sitting at distance 1 (missing untrusted_ingress)
        p_priv_exfil = pkg("p_priv_exfil", deps=["pg", "nodemailer"])
        inst_open = Installation("inst1", [p_priv_exfil])

        # Candidate 1: provides untrusted_ingress -> should flip inst_open via composition
        p_ingress = pkg("p_ingress", deps=["cheerio"])

        # Candidate 2: provides private_data -> already present, no flip
        p_priv = pkg("p_priv", deps=["pg"])

        # Candidate 3: single-package closer -> flips inst_open as single-package closer
        p_all = pkg("p_all", deps=["pg", "puppeteer"])

        pool = {
            "p_ingress": p_ingress,
            "p_priv": p_priv,
            "p_all": p_all,
        }

        impacts = compute_marginal_closure_contributions([inst_open], pool)
        impact_by_name = {i.package_name: i for i in impacts}

        # p_ingress should cause 1 composed flip
        self.assertEqual(impact_by_name["p_ingress"].flips_total, 1)
        self.assertEqual(impact_by_name["p_ingress"].flips_composed, 1)
        self.assertFalse(impact_by_name["p_ingress"].closes_alone)

        # p_priv should cause 0 flips
        self.assertEqual(impact_by_name["p_priv"].flips_total, 0)

        # p_all causes 1 flip, but 0 composed flips (because it closes alone)
        self.assertEqual(impact_by_name["p_all"].flips_total, 1)
        self.assertEqual(impact_by_name["p_all"].flips_composed, 0)
        self.assertTrue(impact_by_name["p_all"].closes_alone)

    def test_coinstallation_graph(self):
        pA = pkg("pA")
        pB = pkg("pB")
        pC = pkg("pC")
        pD = pkg("pD")
        pE = pkg("pE")

        insts = [
            Installation("i1", [pA, pB, pC]),
            Installation("i2", [pA, pB]),
            Installation("i3", [pD, pE]),
            Installation("i4", [pD, pE]),
        ]

        graph = compute_coinstallation_graph(insts, min_support=2)
        self.assertEqual(graph["total_installations"], 4)
        top_pairs = {(p["package_a"], p["package_b"]): p["frequency"] for p in graph["top_coinstallation_pairs"]}
        self.assertEqual(top_pairs.get(("pA", "pB")), 2)
        self.assertEqual(top_pairs.get(("pD", "pE")), 2)
        self.assertNotIn(("pA", "pC"), top_pairs)  # Only appeared once, below min_support=2

        # Verify community clustering
        self.assertGreaterEqual(len(graph["communities"]), 2)
        self.assertIn("component_size_distribution", graph)
        self.assertIn("singletons_count", graph)

    def test_distance_sensitivity_band(self):
        p_all = pkg("p_all", deps=["pg", "puppeteer"])
        p_priv_exfil = pkg("p_priv_exfil", deps=["pg", "nodemailer"])
        p_priv = pkg("p_priv", deps=["pg"])
        p_none = pkg("p_none")

        installations = [
            Installation("c1", [p_all]),
            Installation("c2", [p_priv_exfil]),
            Installation("c3", [p_priv]),
            Installation("c4", [p_none]),
        ]

        band = compute_distance_sensitivity_band(installations)
        self.assertIn("declared_text", band)
        self.assertIn("manifest_structure", band)
        self.assertIn("declared_dependency", band)
        # All tiers analyze the 4 installations
        for tier_name in ["declared_text", "manifest_structure", "declared_dependency"]:
            self.assertEqual(band[tier_name]["total_installations"], 4)
            self.assertIn("distance_distribution", band[tier_name])

    def test_marginal_closure_ranking_prioritizes_composed(self):
        # Open installation sitting at distance 1
        p_priv_exfil = pkg("p_priv_exfil", deps=["pg", "nodemailer"])
        inst_open = Installation("inst1", [p_priv_exfil])

        # Candidate 1: composed closer (provides untrusted_ingress)
        p_ingress = pkg("p_ingress", deps=["cheerio"])
        # Candidate 2: solo closer (provides all 3 legs alone)
        p_all = pkg("p_all", deps=["pg", "puppeteer"])

        pool = {
            "p_ingress": p_ingress,
            "p_all": p_all,
        }

        # Candidate 1 should rank ahead of Candidate 2 because p_ingress causes composed closure
        impacts = compute_marginal_closure_contributions([inst_open], pool)
        self.assertEqual(impacts[0].package_name, "p_ingress")
        self.assertEqual(impacts[0].flips_composed, 1)
        self.assertEqual(impacts[1].package_name, "p_all")
        self.assertEqual(impacts[1].flips_composed, 0)
        self.assertEqual(impacts[1].flips_total, 1)

    def test_marginal_closure_coinstallation_affinity(self):
        p_priv_exfil = pkg("p_priv_exfil", deps=["pg", "nodemailer"])
        inst_open = Installation("inst1", [p_priv_exfil])

        # Candidate A has prior co-installation with p_priv_exfil in population
        p_cand_a = pkg("p_cand_a", deps=["cheerio"])
        # Candidate B has NO prior co-installation in population
        p_cand_b = pkg("p_cand_b", deps=["cheerio"])

        # Reference population showing p_cand_a co-installed with p_priv_exfil
        pop = [
            Installation("pop1", [p_priv_exfil, p_cand_a]),
            Installation("pop2", [p_priv_exfil, p_cand_a]),
            inst_open,
        ]

        pool = {
            "p_cand_a": p_cand_a,
            "p_cand_b": p_cand_b,
        }

        impacts = compute_marginal_closure_contributions(
            [inst_open], pool, population_installations=pop
        )
        impact_by_name = {i.package_name: i for i in impacts}

        # Both have 1 unweighted composed flip
        self.assertEqual(impact_by_name["p_cand_a"].flips_composed, 1)
        self.assertEqual(impact_by_name["p_cand_b"].flips_composed, 1)

        # But p_cand_a is empirically grounded, while p_cand_b is ungrounded
        self.assertEqual(impact_by_name["p_cand_a"].flips_composed_grounded, 1)
        self.assertGreater(impact_by_name["p_cand_a"].flips_composed_weighted, 0.0)

        self.assertEqual(impact_by_name["p_cand_b"].flips_composed_grounded, 0)
        self.assertEqual(impact_by_name["p_cand_b"].flips_composed_weighted, 0.0)


if __name__ == "__main__":
    unittest.main()

