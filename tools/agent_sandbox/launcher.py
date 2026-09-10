"""Cross-Platform Sandbox Launcher for AI Agent Tool Confinement.

Translates high-level SandboxPolicy declarations into OS-native isolation primitives:
1. Linux: Bubblewrap (bwrap) unshared namespaces and filesystem mounts.
2. macOS: Apple Sandbox Seatbelt (sandbox-exec) policy definitions.
3. Windows: Advisory temporary directory redirection and environment sanitization.
   NOTE: OS-level kernel confinement (namespaces/Seatbelt equivalent) is not supported
   on Windows without container virtualization (AppContainer / Windows Sandbox).
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .policy import SandboxPolicy


@dataclass
class SandboxedExecutionPlan:
    """Concrete OS-level execution plan with isolation wrappers applied."""

    command: List[str]
    env: Dict[str, str]
    isolation_driver: str  # "linux_bwrap" | "macos_seatbelt" | "windows_advisory_env" | "passthrough"
    confinement_summary: List[str]
    rationale: str
    plan_type: str = "Policy / Launch-Plan Prototype"
    seatbelt_profile: Optional[str] = None



def generate_linux_bwrap_command(
    policy: SandboxPolicy, raw_command: Sequence[str]
) -> SandboxedExecutionPlan:
    """Constructs a Bubblewrap (bwrap) isolation command for Linux."""
    bwrap_cmd: List[str] = [
        "bwrap",
        "--die-with-parent",
        "--new-session",
    ]

    summary: List[str] = []

    # 1. Namespaces
    if not policy.net_enabled:
        bwrap_cmd.append("--unshare-all")
        summary.append("Network completely disabled (unshared network namespace)")
    else:
        if policy.net_allowed_hosts and "*" not in policy.net_allowed_hosts:
            raise ValueError(
                f"Host-level network filtering ({policy.net_allowed_hosts}) is unsupported "
                "by native Bubblewrap without an external proxy driver. "
                "Execution plan fails closed to prevent unrestricted network egress."
            )
        bwrap_cmd.extend(["--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts"])
        summary.append("Network enabled (unrestricted egress; per-host filtering requires external proxy)")

    # 2. Standard system read-only mounts
    for sys_dir in ["/usr", "/lib", "/lib64", "/bin", "/etc/ssl", "/etc/ca-certificates"]:
        if os.path.exists(sys_dir):
            bwrap_cmd.extend(["--ro-bind", sys_dir, sys_dir])

    if policy.net_enabled and os.path.exists("/etc/resolv.conf"):
        bwrap_cmd.extend(["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"])

    # 3. Isolated tmpfs (neutralizes /tmp malware staging like alien Bun)
    bwrap_cmd.extend(["--tmpfs", "/tmp"])
    summary.append("Isolated in-memory /tmp tmpfs (neutralizes persistent disk staging)")

    # 4. User-allowed read roots
    for r in policy.fs_read_roots:
        if os.path.exists(r):
            bwrap_cmd.extend(["--ro-bind", r, r])
            summary.append(f"Read-only mount: {r}")

    # 5. User-allowed write roots
    for w in policy.fs_write_roots:
        if os.path.exists(w):
            bwrap_cmd.extend(["--bind", w, w])
            summary.append(f"Read-write mount: {w}")

    # 6. Environment
    bwrap_cmd.append("--clearenv")
    sanitized_env = policy.sanitize_env()
    for k, v in sanitized_env.items():
        bwrap_cmd.extend(["--setenv", k, v])

    bwrap_cmd.extend(["--", *raw_command])

    return SandboxedExecutionPlan(
        command=bwrap_cmd,
        env=sanitized_env,
        isolation_driver="linux_bwrap",
        confinement_summary=summary,
        rationale="Bubblewrap namespaces isolate root filesystem, enforce read-only bindings, and prevent alien runtimes from escaping.",
    )


def generate_macos_seatbelt_profile(
    policy: SandboxPolicy, raw_command: Sequence[str]
) -> SandboxedExecutionPlan:
    """Generates Apple Sandbox Seatbelt profile text and sandbox-exec command."""
    summary: List[str] = []
    lines: List[str] = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec (literal \"/bin/sh\"))",
        "(allow file-read-data (subpath \"/usr/lib\"))",
        "(allow file-read-data (subpath \"/System/Library\"))",
    ]

    # Process execution
    if not policy.allow_child_processes:
        lines.append("(deny process-fork)")
        summary.append("Child process forking prohibited (deny process-fork)")

    # Network
    if policy.net_enabled:
        lines.append("(allow network-outbound)")
        summary.append("Outbound network permitted")
    else:
        lines.append("(deny network*)")
        summary.append("Network completely denied")

    # Credential blacklists
    if policy.deny_credential_paths:
        home = os.path.expanduser("~")
        lines.append(f"(deny file* (subpath \"{home}/.aws\"))")
        lines.append(f"(deny file* (subpath \"{home}/.ssh\"))")
        lines.append(f"(deny file* (subpath \"{home}/Library/Application Support/Google/Chrome\"))")
        summary.append("Explicit denial on ~/.aws, ~/.ssh, and Chrome Cookies")

    # Allowed read paths
    for r in policy.fs_read_roots:
        lines.append(f"(allow file-read* (subpath \"{r}\"))")
        summary.append(f"Allowed read: {r}")

    # Allowed write paths
    for w in policy.fs_write_roots:
        lines.append(f"(allow file-write* (subpath \"{w}\"))")
        summary.append(f"Allowed write: {w}")

    seatbelt_text = "\n".join(lines)
    sanitized_env = policy.sanitize_env()

    command = ["sandbox-exec", "-p", seatbelt_text, *raw_command]

    return SandboxedExecutionPlan(
        command=command,
        env=sanitized_env,
        isolation_driver="macos_seatbelt",
        confinement_summary=summary,
        rationale="macOS Seatbelt profile drops ambient credential reads and enforces path confinement.",
        seatbelt_profile=seatbelt_text,
    )


def generate_windows_sandbox_command(
    policy: SandboxPolicy, raw_command: Sequence[str]
) -> SandboxedExecutionPlan:
    """Generates Windows launch plan using advisory environment sanitization and isolated temp.

    NOTE: This does NOT enforce OS-level process or filesystem confinement. On Windows,
    kernel-level isolation requires AppContainer or container virtualization.
    """
    summary: List[str] = []
    sanitized_env = policy.sanitize_env()

    # On Windows, redirect %TEMP% and %TMP% to an isolated tool sandbox directory
    # so dropped executables (like bun.exe in MAL-2026-5318) cannot access user temp.
    sandbox_tmp = os.path.normpath(os.path.join(os.environ.get("LOCALAPPDATA", "C:\\Temp"), "AgentSandbox", policy.name))
    sanitized_env["TEMP"] = sandbox_tmp
    sanitized_env["TMP"] = sandbox_tmp
    summary.append(f"Redirected %TEMP% and %TMP% to isolated sandbox tree: {sandbox_tmp}")

    # Strip ambient credential environment variables
    for cred_key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "ANTHROPIC_API_KEY"]:
        sanitized_env.pop(cred_key, None)
    summary.append("Sanitized ambient environment: stripped cloud keys, AWS tokens, and PATs")

    # Explicit warning of no OS confinement
    summary.append("WARNING: OS-level process and filesystem boundaries are NOT enforced on Windows without container virtualization.")

    return SandboxedExecutionPlan(
        command=list(raw_command),
        env=sanitized_env,
        isolation_driver="windows_advisory_env",
        confinement_summary=summary,
        rationale="Windows advisory isolation: redirected temporary directory and stripped credential variables. OS kernel confinement is not active.",
    )



def prepare_sandboxed_launch(
    policy: SandboxPolicy,
    raw_command: Sequence[str],
    platform_override: Optional[str] = None,
) -> SandboxedExecutionPlan:
    """Prepares a platform-native sandboxed execution plan for an agent tool."""
    target_platform = (platform_override or platform.system()).lower()

    if "linux" in target_platform:
        return generate_linux_bwrap_command(policy, raw_command)
    elif "darwin" in target_platform or "mac" in target_platform:
        return generate_macos_seatbelt_profile(policy, raw_command)
    elif "win" in target_platform:
        return generate_windows_sandbox_command(policy, raw_command)

    # Fallback to sanitized passthrough
    return SandboxedExecutionPlan(
        command=list(raw_command),
        env=policy.sanitize_env(),
        isolation_driver="passthrough",
        confinement_summary=["Environment sanitized only (unsupported OS for native sandbox)"],
        rationale="Fallback mode: environment keys stripped, but OS native sandbox not available.",
    )
