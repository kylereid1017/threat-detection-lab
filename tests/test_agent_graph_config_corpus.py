"""Unit tests for tools.agent_graph.config_corpus."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.agent_graph import config_corpus as cc


class ConfigCorpusTests(unittest.TestCase):
    def test_extract_package_various_runners(self):
        # npx
        self.assertEqual(
            cc.extract_package("npx", ["-y", "@modelcontextprotocol/server-filesystem"]),
            "@modelcontextprotocol/server-filesystem",
        )
        self.assertEqual(
            cc.extract_package("npx", ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"]),
            "@modelcontextprotocol/server-filesystem",
        )
        self.assertEqual(
            cc.extract_package("npx.cmd", ["demo-pkg@^2.0.0"]),
            "demo-pkg",
        )
        # uvx / uv / pipx
        self.assertEqual(
            cc.extract_package("uvx", ["mcp-server-git==0.1.0"]),
            "mcp-server-git",
        )
        self.assertEqual(
            cc.extract_package("uvx", ["--from", "git-mcp==1.0", "run"]),
            "git-mcp",
        )
        self.assertEqual(
            cc.extract_package("pipx", ["run", "--spec", "my-tool==1.2", "my-tool"]),
            "my-tool",
        )
        self.assertEqual(
            cc.extract_package("bunx", ["-y", "bun-mcp"]),
            "bun-mcp",
        )
        self.assertEqual(
            cc.extract_package("pnpm", ["dlx", "pnpm-tool"]),
            "pnpm-tool",
        )
        # Non-runner commands
        self.assertIsNone(cc.extract_package("python", ["script.py"]))
        self.assertIsNone(cc.extract_package("", []))
        self.assertIsNone(cc.extract_package(["invalid"], None))

    def test_parse_config(self):
        valid = {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {"DEBUG": "true", "KEY": "val"}
                },
                "remote": {
                    "command": "node",
                    "url": "https://example.com/sse"
                }
            }
        }
        entries = cc.parse_config(json.dumps(valid))
        self.assertEqual(len(entries), 2)
        fs_entry = next(e for e in entries if e["label"] == "fs")
        self.assertEqual(fs_entry["package"], "@modelcontextprotocol/server-filesystem")
        self.assertTrue(fs_entry["has_env"])
        self.assertEqual(fs_entry["env_keys"], ["DEBUG", "KEY"])
        self.assertEqual(fs_entry["transport"], "stdio")

        rem_entry = next(e for e in entries if e["label"] == "remote")
        self.assertEqual(rem_entry["transport"], "remote")

        # Fallback to mcp_servers
        fallback = {"mcp_servers": {"local": {"command": "npx", "args": ["demo"]}}}
        self.assertEqual(len(cc.parse_config(json.dumps(fallback))), 1)

        # Unparseable or invalid schema
        self.assertEqual(cc.parse_config("not json"), [])
        self.assertEqual(cc.parse_config(json.dumps({"mcpServers": "not a dict"})), [])

    def test_config_record_and_deduplicate(self):
        r1 = cc.ConfigRecord(
            repo="org/repo1",
            path="claude.json",
            servers=[{"package": "pkg-a"}, {"package": "pkg-b"}]
        )
        r2 = cc.ConfigRecord(
            repo="org/repo2",
            path="mcp.json",
            servers=[{"package": "pkg-b"}, {"package": "pkg-a"}]
        )
        r3 = cc.ConfigRecord(
            repo="org/repo3",
            path="other.json",
            servers=[{"package": "pkg-c"}]
        )
        self.assertEqual(r1.packages, ["pkg-a", "pkg-b"])
        self.assertEqual(r1.fingerprint, r2.fingerprint)
        d = r1.to_dict()
        self.assertEqual(d["repo"], "org/repo1")

        deduped, dups = cc.deduplicate([r1, r2, r3])
        self.assertEqual(len(deduped), 2)
        self.assertEqual(dups, 1)

    def test_collect_configs(self):
        locations = [
            {"repo": "r1", "path": "ok.json"},
            {"repo": "r2", "path": "bad.json"},
            {"repo": "r3", "path": "empty.json"},
            {"repo": "r4", "path": "unreadable.json"},
        ]

        def mock_fetch(repo, path, timeout=20):
            if repo == "r1":
                return json.dumps({"mcpServers": {"s": {"command": "npx", "args": ["p1"]}}})
            if repo == "r2":
                return "not json at all"
            if repo == "r3":
                return json.dumps({})
            return None

        with patch.object(cc, "fetch_raw", side_effect=mock_fetch):
            records, stats = cc.collect_configs(locations, workers=2)
            self.assertEqual(len(records), 1)
            self.assertEqual(stats["fetched"], 3)
            self.assertEqual(stats["unreadable"], 1)
            self.assertEqual(stats["no_servers"], 2)

    def test_fetch_npm_manifest_and_fetch_manifests(self):
        import urllib.error
        meta_data = {
            "name": "demo-pkg",
            "description": "Demo MCP Server",
            "keywords": ["mcp"],
            "dependencies": {"express": "4"},
            "bin": {"demo": "dist/index.js"},
            "scripts": {"build": "tsc"},
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(meta_data).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch("json.load", return_value=meta_data):
                manifest = cc.fetch_npm_manifest("demo-pkg")
                self.assertIsNotNone(manifest)
                self.assertEqual(manifest["name"], "demo-pkg")
                self.assertEqual(manifest["ecosystem"], "npm")
                self.assertIn("dependencies", manifest["manifest"])

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("network error")):
            self.assertIsNone(cc.fetch_npm_manifest("fail-pkg"))

        # fetch_manifests batch
        with patch.object(cc, "fetch_npm_manifest", side_effect=lambda name, timeout=20: meta_data if name == "ok" else None):
            resolved, missing = cc.fetch_manifests(["ok", "fail"], workers=2)
            self.assertIn("ok", resolved)
            self.assertIn("fail", missing)

    def test_load_snapshot(self):
        # Test loading the existing snapshot in the repository
        records, manifests = cc.load_snapshot(cc.DEFAULT_OUT)
        self.assertGreater(len(records), 0)
        self.assertGreater(len(manifests), 0)


if __name__ == "__main__":
    unittest.main()
