"""Unit tests for tools.agent_graph.export_artifact."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.agent_graph import export_artifact


class ExportArtifactTests(unittest.TestCase):
    def test_build_installations_and_taxonomy_payload(self):
        installations, payload_servers, manifests = export_artifact.build_installations()
        self.assertGreater(len(installations), 0)
        self.assertGreater(len(payload_servers), 0)
        self.assertGreater(len(manifests), 0)

        tax = export_artifact.taxonomy_payload(manifests)
        self.assertIn("capability_legs", tax)
        self.assertIn("scope_rules", tax)
        self.assertIn("text_rules", tax)
        self.assertIn("wiring_rules", tax)
        self.assertIn("packages", tax)

    def test_main_runs_and_emits_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_html = tmp_path / "composition.html"
            out_json = tmp_path / "composition.json"

            with patch.object(export_artifact, "DEFAULT_OUT", out_html), \
                 patch.object(export_artifact, "RESULTS", out_json):
                ret = export_artifact.main()
                self.assertEqual(ret, 0)
                self.assertTrue(out_html.exists())
                self.assertTrue(out_json.exists())

                html_content = out_html.read_text(encoding="utf-8")
                self.assertIn("<!DOCTYPE html>", html_content)
                self.assertIn("Agent Capability Composition", html_content)
                # Confirm escaping of <, >, & in embedded JSON payload
                self.assertNotIn("<<", html_content)

                json_data = json.loads(out_json.read_text(encoding="utf-8"))
                self.assertEqual(json_data["measurement"], "agent_capability_composition")
                self.assertIn("summary", json_data)
                self.assertIn("installations", json_data)


if __name__ == "__main__":
    unittest.main()
