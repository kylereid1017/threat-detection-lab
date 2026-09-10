"""AI Agent Sandbox & Host Confinement Package.

Provides capability policy definitions and OS-native isolation drivers
(Linux Bubblewrap, macOS Seatbelt, Windows Restricted Tokens/Job Objects)
to confine Model Context Protocol (MCP) servers and prevent privilege escalation.
"""

from .launcher import (
    SandboxedExecutionPlan,
    generate_linux_bwrap_command,
    generate_macos_seatbelt_profile,
    generate_windows_sandbox_command,
    prepare_sandboxed_launch,
)
from .policy import SandboxPolicy

__all__ = [
    "SandboxPolicy",
    "SandboxedExecutionPlan",
    "prepare_sandboxed_launch",
    "generate_linux_bwrap_command",
    "generate_macos_seatbelt_profile",
    "generate_windows_sandbox_command",
]
