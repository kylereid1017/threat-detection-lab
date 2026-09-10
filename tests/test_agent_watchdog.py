"""Unit tests for AI Agent Registry Watchdog & Triage Stream."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tools.agent_watchdog import (
    AgentRegistryWatchdog,
    WatchdogAlert,
    main,
)
from tools.cti.protected_names import ProtectedRegistry


class AgentRegistryWatchdogTests(unittest.TestCase):
    """Verifies that AgentRegistryWatchdog accurately triages agent ecosystem packages."""

    def setUp(self):
        self.watchdog = AgentRegistryWatchdog()

    def test_confirmed_malicious_detection(self):
        alert = self.watchdog.evaluate_package({
            "name": "groq-mcp",
            "ecosystem": "pypi",
            "version": "1.4.3",
        })
        self.assertEqual(alert.risk_score, 100)
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.action, "QUARANTINE_IMMEDIATELY")
        self.assertTrue(any("MAL-2026-5321" in r for r in alert.reasons))

    def test_compound_and_typosquat_scoring(self):
        # Compound brand embedding
        alert = self.watchdog.evaluate_package({
            "name": "modelcontextprotocol-evals",
            "ecosystem": "npm",
            "version": "0.1.0",
        })
        self.assertIsNotNone(alert.imitated_package)
        self.assertGreaterEqual(alert.risk_score, 40)
        self.assertTrue(any("Compound imitation" in r for r in alert.reasons))

    def test_privilege_manifest_scoring(self):
        # Benign name but excessive manifest privileges
        alert = self.watchdog.evaluate_package({
            "name": "utility-helper-service",
            "ecosystem": "npm",
            "version": "1.0.0",
            "bin": {"svc": "./cli.js"},
            "scripts": {"postinstall": "node compile.js"},
            "dependencies": {"axios": "^1.0.0", "execa": "^5.0.0"},
            "maintainers": ["single_dev"],
            "has_oidc": False,
        })
        # Score breakdown: bin (+20) + postinstall (+25) + egress (+10) + proc (+15) + single maintainer (+5) + no oidc (+5) = 80
        self.assertEqual(alert.risk_score, 80)
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.action, "QUARANTINE_IMMEDIATELY")
        self.assertTrue(any("bin" in r for r in alert.reasons))
        self.assertTrue(any("postinstall" in r for r in alert.reasons))
        self.assertTrue(any("axios" in r for r in alert.reasons))
        self.assertTrue(any("execa" in r for r in alert.reasons))

    def test_benign_package_low_score(self):
        alert = self.watchdog.evaluate_package({
            "name": "standard-formatter",
            "ecosystem": "npm",
            "version": "2.0.0",
            "maintainers": ["alice", "bob"],
            "has_oidc": True,
        })
        self.assertEqual(alert.risk_score, 0)
        self.assertEqual(alert.severity, "LOW")
        self.assertEqual(alert.action, "ALLOW")
        self.assertEqual(len(alert.reasons), 0)

    def test_scan_stream_min_score_filter(self):
        stream = [
            {"name": "standard-formatter", "maintainers": ["a", "b"], "has_oidc": True},
            {"name": "groq-mcp"},
            {"name": "fastmcp-extension", "bin": {"ext": "main.py"}},
        ]
        # At min_score=50, should only return groq-mcp (100) and fastmcp-extension (compound 40 + bin 20 = 60)
        alerts = self.watchdog.scan_stream(stream, min_score=50)
        self.assertEqual(len(alerts), 2)
        names = [a.package_name for a in alerts]
        self.assertIn("groq-mcp", names)
        self.assertIn("fastmcp-extension", names)

    def test_cli_feed_and_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            feed_file = Path(tmpdir) / "feed.jsonl"
            out_file = Path(tmpdir) / "alerts.jsonl"

            records = [
                {"name": "groq-mcp", "ecosystem": "pypi", "version": "0.1.0"},
                {"name": "benign-logger", "maintainers": ["u1", "u2"], "has_oidc": True},
            ]
            with open(feed_file, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main([
                    "--feed", str(feed_file),
                    "--output", str(out_file),
                    "--min-score", "50",
                    "--format", "json",
                ])

            self.assertEqual(code, 0)
            self.assertTrue(out_file.exists())
            written_alerts = [json.loads(line) for line in out_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(written_alerts), 1)
            self.assertEqual(written_alerts[0]["package_name"], "groq-mcp")
            self.assertEqual(written_alerts[0]["risk_score"], 100)

    def test_cli_missing_feed_error(self):
        code = main(["--feed", "non_existent_feed_file_12345.jsonl"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
