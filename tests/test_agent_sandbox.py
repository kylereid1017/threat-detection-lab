"""Unit tests for AI Agent Sandbox & Host Confinement."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.agent_sandbox import (
    SandboxPolicy,
    generate_linux_bwrap_command,
    generate_macos_seatbelt_profile,
    generate_windows_sandbox_command,
    prepare_sandboxed_launch,
)


class SandboxPolicyTests(unittest.TestCase):
    """Verifies that SandboxPolicy enforces fine-grained path and network boundaries."""

    def test_path_access_allowed_and_denied(self):
        policy = SandboxPolicy(
            name="test-server",
            fs_read_roots=["/home/user/project", "C:\\Users\\user\\project"],
            fs_write_roots=["/home/user/project/out", "C:\\Users\\user\\project\\out"],
        )

        # Allowed read
        self.assertTrue(policy.is_path_allowed("/home/user/project/data.json", mode="read"))
        # Denied write to read-only root
        self.assertFalse(policy.is_path_allowed("/home/user/project/data.json", mode="write"))
        # Allowed write to write root
        self.assertTrue(policy.is_path_allowed("/home/user/project/out/result.csv", mode="write"))
        # Denied completely outside root
        self.assertFalse(policy.is_path_allowed("/etc/shadow", mode="read"))
        self.assertFalse(policy.is_path_allowed("C:\\Windows\\System32\\cmd.exe", mode="read"))

    def test_credential_paths_strictly_denied_even_if_under_root(self):
        policy = SandboxPolicy(
            name="test-server",
            fs_read_roots=["/home/user", "C:\\Users\\user"],
            deny_credential_paths=True,
        )

        # High-value credentials must always return False
        self.assertFalse(policy.is_path_allowed("/home/user/.aws/credentials"))
        self.assertFalse(policy.is_path_allowed("/home/user/.ssh/id_rsa"))
        self.assertFalse(policy.is_path_allowed("C:\\Users\\user\\.aws\\credentials"))
        self.assertFalse(policy.is_path_allowed("C:\\Users\\user\\project\\.env"))
        self.assertFalse(policy.is_path_allowed("/home/user/Library/Application Support/Google/Chrome/Default/Cookies"))

    def test_network_host_enforcement(self):
        # Network disabled
        policy_no_net = SandboxPolicy(name="offline", net_enabled=False)
        self.assertFalse(policy_no_net.is_host_allowed("api.github.com"))
        self.assertFalse(policy_no_net.is_host_allowed("example.invalid"))

        # Network enabled with specific whitelist
        policy_net = SandboxPolicy(
            name="online",
            net_enabled=True,
            net_allowed_hosts=["api.anthropic.com", "huggingface.co"],
        )
        self.assertTrue(policy_net.is_host_allowed("api.anthropic.com"))
        self.assertTrue(policy_net.is_host_allowed("huggingface.co"))
        self.assertTrue(policy_net.is_host_allowed("sub.huggingface.co"))
        self.assertFalse(policy_net.is_host_allowed("evil-exfil.stage.invalid"))

    def test_environment_sanitization(self):
        policy = SandboxPolicy(
            name="clean-env",
            env_passthrough=["PATH", "LANG", "CUSTOM_VAR"],
        )
        dirty_env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
            "CUSTOM_VAR": "safe_value",
            "ANTHROPIC_API_KEY": "sk-ant-secret123",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "GITHUB_TOKEN": "ghp_secret_token",
        }
        sanitized = policy.sanitize_env(dirty_env)
        self.assertIn("PATH", sanitized)
        self.assertIn("LANG", sanitized)
        self.assertIn("CUSTOM_VAR", sanitized)
        self.assertNotIn("ANTHROPIC_API_KEY", sanitized)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", sanitized)
        self.assertNotIn("GITHUB_TOKEN", sanitized)

    def test_load_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_file = Path(tmp) / "mcp-manifest.json"
            manifest_data = {
                "name": "sqlite-mcp-server",
                "capabilities": {
                    "fs_read_roots": ["/data/db"],
                    "fs_write_roots": ["/data/db/wal"],
                    "allow_child_processes": False,
                    "net_enabled": False,
                }
            }
            manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

            policy = SandboxPolicy.from_manifest(manifest_file)
            self.assertEqual(policy.name, "sqlite-mcp-server")
            self.assertEqual(policy.fs_read_roots, [str(Path("/data/db"))])
            self.assertFalse(policy.allow_child_processes)
            self.assertFalse(policy.net_enabled)


class SandboxLauncherTests(unittest.TestCase):
    """Verifies that Sandbox Launcher generates proper OS-native isolation plans."""

    def setUp(self):
        self.policy = SandboxPolicy(
            name="audit-test-server",
            fs_read_roots=["/tmp/test_project"],
            fs_write_roots=["/tmp/test_project/out"],
            allow_child_processes=False,
            net_enabled=False,
        )

    def test_generate_linux_bwrap_plan(self):
        plan = generate_linux_bwrap_command(self.policy, ["node", "server.js"])
        self.assertEqual(plan.isolation_driver, "linux_bwrap")
        self.assertIn("bwrap", plan.command[0])
        self.assertIn("--unshare-all", plan.command)
        self.assertIn("--tmpfs", plan.command)
        self.assertIn("/tmp", plan.command)
        self.assertIn("--clearenv", plan.command)
        self.assertIn("server.js", plan.command)

    def test_generate_macos_seatbelt_plan(self):
        plan = generate_macos_seatbelt_profile(self.policy, ["node", "server.js"])
        self.assertEqual(plan.isolation_driver, "macos_seatbelt")
        self.assertEqual(plan.command[0], "sandbox-exec")
        self.assertEqual(plan.command[1], "-p")
        self.assertIsNotNone(plan.seatbelt_profile)
        self.assertIn("(deny default)", plan.seatbelt_profile)
        self.assertIn("(deny process-fork)", plan.seatbelt_profile)
        self.assertIn("(deny network*)", plan.seatbelt_profile)
        self.assertIn(".aws", plan.seatbelt_profile)
        self.assertIn(".ssh", plan.seatbelt_profile)

    def test_generate_windows_advisory_plan(self):
        plan = generate_windows_sandbox_command(self.policy, ["node.exe", "server.js"])
        self.assertEqual(plan.isolation_driver, "windows_advisory_env")
        # Direct execution without dangerous powershell wrapper
        self.assertEqual(plan.command, ["node.exe", "server.js"])
        self.assertIn("TEMP", plan.env)
        self.assertIn("AgentSandbox", plan.env["TEMP"])
        # Explicit warning that OS boundaries are not enforced on Windows
        self.assertTrue(any("NOT enforced" in s for s in plan.confinement_summary))

    def test_prepare_sandboxed_launch_dispatcher(self):
        plan_linux = prepare_sandboxed_launch(self.policy, ["python", "app.py"], platform_override="linux")
        self.assertEqual(plan_linux.isolation_driver, "linux_bwrap")
        self.assertEqual(plan_linux.plan_type, "Policy / Launch-Plan Prototype")

        plan_mac = prepare_sandboxed_launch(self.policy, ["python", "app.py"], platform_override="darwin")
        self.assertEqual(plan_mac.isolation_driver, "macos_seatbelt")

        plan_win = prepare_sandboxed_launch(self.policy, ["python", "app.py"], platform_override="windows")
        self.assertEqual(plan_win.isolation_driver, "windows_advisory_env")

    def test_bwrap_host_filtering_fails_closed(self):
        policy_with_hosts = SandboxPolicy(
            name="host-filter-test",
            net_enabled=True,
            net_allowed_hosts=["api.example.com"],
        )
        with self.assertRaises(ValueError) as ctx:
            generate_linux_bwrap_command(policy_with_hosts, ["node", "index.js"])
        self.assertIn("unsupported", str(ctx.exception).lower())


