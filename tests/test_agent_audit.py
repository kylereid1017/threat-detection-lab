"""Unit tests for the AI Agent Execution Layer Security Auditor (mcp-audit)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.agent_audit import (
    AuditFinding,
    audit_config_data,
    generate_sample_config,
    load_malicious_index,
    DEFAULT_PROTECTED_CATALOG,
)


class TestAgentAudit(unittest.TestCase):
    def setUp(self):
        self.malicious_index = {
            "groq-mcp": "MAL-2026-5321",
            "@browserbasehq/mcp": "MAL-2025-191195",
            "openai-mcp": "MAL-2026-9999",
        }

    def test_safe_server_zero_findings(self):
        conf = {
            "mcpServers": {
                "safe-local-node": {
                    "command": "node",
                    "args": ["/opt/mcp/dist/index.js", "./project-data"],
                    "env": {"DEBUG": "false"}
                }
            }
        }
        findings, summary = audit_config_data(conf, DEFAULT_PROTECTED_CATALOG, self.malicious_index)
        self.assertEqual(len(findings), 0)
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["total_servers"], 1)

    def test_unpinned_dynamic_execution_detected(self):
        conf = {
            "mcpServers": {
                "unpinned-server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"]
                }
            }
        }
        findings, summary = audit_config_data(conf, DEFAULT_PROTECTED_CATALOG, self.malicious_index)
        categories = [f.category for f in findings]
        self.assertIn("dynamic_execution", categories)
        self.assertIn("supply_chain_unpinned", categories)
        self.assertIn("passive_lifecycle_hooks", categories)

    def test_compound_typosquat_detected(self):
        conf = {
            "mcpServers": {
                "sneaky-sdk": {
                    "command": "npx",
                    "args": ["-y", "--ignore-scripts", "@shady-actor/modelcontextprotocol-sdk@1.0.0"]
                }
            }
        }
        findings, summary = audit_config_data(conf, DEFAULT_PROTECTED_CATALOG, self.malicious_index)
        imitation_findings = [f for f in findings if f.category == "imitation_lure"]
        self.assertEqual(len(imitation_findings), 1)
        self.assertEqual(imitation_findings[0].metadata["imitated"], "modelcontextprotocol")
        self.assertEqual(imitation_findings[0].metadata["kind"], "compound")

    def test_openssf_malicious_hit_detected(self):
        conf = {
            "mcpServers": {
                "trojan-tool": {
                    "command": "npx",
                    "args": ["-y", "--ignore-scripts", "@browserbasehq/mcp@0.1.0"]
                }
            }
        }
        findings, summary = audit_config_data(conf, DEFAULT_PROTECTED_CATALOG, self.malicious_index)
        mal_findings = [f for f in findings if f.category == "confirmed_malicious"]
        self.assertEqual(len(mal_findings), 1)
        self.assertEqual(mal_findings[0].severity, "CRITICAL")
        self.assertEqual(mal_findings[0].metadata["advisory"], "MAL-2025-191195")

    def test_plaintext_credentials_and_broad_fs(self):
        conf = {
            "mcpServers": {
                "db-server": {
                    "command": "node",
                    "args": ["index.js", "/"],
                    "env": {
                        "DATABASE_URL": "postgresql://postgres:secretP@ssw0rd@127.0.0.1:5432/main",
                        "ANTHROPIC_API_KEY": "sk-ant-live-token-123456789"
                    }
                }
            }
        }
        findings, summary = audit_config_data(conf, DEFAULT_PROTECTED_CATALOG, self.malicious_index)
        categories = [f.category for f in findings]
        self.assertIn("credential_exposure", categories)
        self.assertIn("plaintext_secret", categories)
        self.assertIn("overprivileged_filesystem", categories)

    def test_sample_config_audit(self):
        sample = generate_sample_config()
        findings, summary = audit_config_data(sample, DEFAULT_PROTECTED_CATALOG, self.malicious_index)
        self.assertGreaterEqual(summary["total_servers"], 5)
        self.assertGreater(summary["total_findings"], 5)

    def test_find_default_config_paths(self):
        from tools.agent_audit import find_default_config_paths
        paths = find_default_config_paths()
        self.assertIsInstance(paths, list)

    def test_load_malicious_index(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            f_npm = p / "npm.jsonl"
            f_pypi = p / "pypi.jsonl"
            f_npm.write_text('{"name": "mal-pkg", "advisory": "MAL-123"}\n{"invalid":\n', encoding="utf-8")
            f_pypi.write_text('{"name": "py-mal", "advisory": "MAL-456"}\n', encoding="utf-8")

            idx = load_malicious_index(f_npm, f_pypi)
            self.assertEqual(idx.get("mal-pkg"), "MAL-123")
            self.assertEqual(idx.get("py-mal"), "MAL-456")

            # Missing files handle gracefully
            idx_empty = load_malicious_index(p / "missing1", p / "missing2")
            self.assertEqual(len(idx_empty), 0)

    def test_format_report_text(self):
        from tools.agent_audit import format_report_text, AuditFinding
        # Unsupported schema
        text_unsupported = format_report_text([], {"status": "unsupported_schema", "total_servers": 0}, "bad.json")
        self.assertIn("Audit incomplete", text_unsupported)

        # Zero findings
        text_clean = format_report_text([], {"total_servers": 1, "total_findings": 0}, "clean.json")
        self.assertIn("follows hardening baseline", text_clean)

        # With findings
        f = AuditFinding(
            server_name="srv",
            severity="HIGH",
            category="dynamic_execution",
            title="Unpinned Exec",
            description="detail",
            remediation="pin exact version",
        )
        text_findings = format_report_text([f], {"total_servers": 1, "total_findings": 1, "high_count": 1}, "conf.json")
        self.assertIn("Unpinned Exec", text_findings)

    def test_main_cli(self):
        from tools.agent_audit import main
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            out_file = p / "audit_out.json"
            cfg_file = p / "test_cfg.json"
            cfg_file.write_text(json.dumps(generate_sample_config()), encoding="utf-8")

            # Main with sample audit and out
            with patch("sys.argv", ["mcp-audit", "--sample-audit", "--out", str(out_file)]):
                main()
                self.assertTrue(out_file.exists())

            # Main with specific config
            with patch("sys.argv", ["mcp-audit", "--config", str(cfg_file)]):
                main()


if __name__ == "__main__":
    unittest.main()
