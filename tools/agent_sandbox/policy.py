"""Sandbox Policy Definition for AI Agent Host Confinement.

Implements the specification defined in docs/upstream/MCP_TELEMETRY_AND_CAPABILITY_SPECIFICATION.md:
- Declares read/write filesystem boundaries.
- Controls child process spawning permissions.
- Defines outbound network destinations.
- Explicitly blacklists developer credential vaults (~/.aws, ~/.ssh, browser state).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


DEFAULT_DENIED_CREDENTIAL_PATTERNS = [
    ".aws",
    ".ssh",
    ".gnupg",
    ".config/gcloud",
    ".azure",
    "AppData/Local/Google/Chrome",
    "Application Support/Google/Chrome",
    "AppData/Roaming/Mozilla/Firefox",
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
]


@dataclass
class SandboxPolicy:
    """Security capability contract defining isolation boundaries for an agent tool."""

    name: str
    fs_read_roots: List[str] = field(default_factory=list)
    fs_write_roots: List[str] = field(default_factory=list)
    allow_child_processes: bool = False
    net_enabled: bool = False
    net_allowed_hosts: List[str] = field(default_factory=list)
    env_passthrough: List[str] = field(default_factory=lambda: ["PATH", "LANG", "NODE_ENV"])
    deny_credential_paths: bool = True
    denied_path_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_DENIED_CREDENTIAL_PATTERNS))

    def __post_init__(self) -> None:
        # Normalize paths
        self.fs_read_roots = [os.path.normpath(p) for p in self.fs_read_roots]
        self.fs_write_roots = [os.path.normpath(p) for p in self.fs_write_roots]

    def is_path_allowed(self, target_path: str | Path, mode: str = "read") -> bool:
        """Verifies if *target_path* is permissible under policy rules."""
        norm_target = os.path.normpath(str(target_path))
        target_lower = norm_target.lower().replace("\\", "/")

        # 1. Deny high-value credential locations
        if self.deny_credential_paths:
            for pattern in self.denied_path_patterns:
                if pattern.lower() in target_lower:
                    return False

        # 2. Check roots
        roots = self.fs_write_roots if mode == "write" else (self.fs_read_roots + self.fs_write_roots)
        if not roots:
            return False

        for root in roots:
            try:
                common = os.path.commonpath([norm_target, root])
                if common == root:
                    return True
            except ValueError:
                # Different drives on Windows (e.g. C: vs D:)
                continue

        return False

    def is_host_allowed(self, host: str) -> bool:
        """Checks if outbound network host is allowed."""
        if not self.net_enabled:
            return False
        if "*" in self.net_allowed_hosts:
            return True
        host_lower = host.lower().strip()
        for allowed in self.net_allowed_hosts:
            allowed_lower = allowed.lower().strip()
            if host_lower == allowed_lower or host_lower.endswith("." + allowed_lower):
                return True
        return False

    def sanitize_env(self, source_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Filters environment variables, stripping unapproved keys and plaintext secrets."""
        source = source_env if source_env is not None else dict(os.environ)
        sanitized: Dict[str, str] = {}
        disallowed_substrings = ["KEY", "SECRET", "TOKEN", "AUTH", "PASS", "CRED"]

        for k, v in source.items():
            k_upper = k.upper()
            if k in self.env_passthrough or k_upper in [p.upper() for p in self.env_passthrough]:
                # Check for sensitive key names
                if any(sub in k_upper for sub in disallowed_substrings) and k_upper not in ["PATH", "LANG"]:
                    continue
                sanitized[k] = v

        return sanitized

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fs_read_roots": self.fs_read_roots,
            "fs_write_roots": self.fs_write_roots,
            "allow_child_processes": self.allow_child_processes,
            "net_enabled": self.net_enabled,
            "net_allowed_hosts": self.net_allowed_hosts,
            "env_passthrough": self.env_passthrough,
            "deny_credential_paths": self.deny_credential_paths,
            "denied_path_patterns": self.denied_path_patterns,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SandboxPolicy:
        return cls(
            name=data.get("name", "unnamed-tool"),
            fs_read_roots=data.get("fs_read_roots", []),
            fs_write_roots=data.get("fs_write_roots", []),
            allow_child_processes=data.get("allow_child_processes", False),
            net_enabled=data.get("net_enabled", False),
            net_allowed_hosts=data.get("net_allowed_hosts", []),
            env_passthrough=data.get("env_passthrough", ["PATH", "LANG", "NODE_ENV"]),
            deny_credential_paths=data.get("deny_credential_paths", True),
            denied_path_patterns=data.get("denied_path_patterns", list(DEFAULT_DENIED_CREDENTIAL_PATTERNS)),
        )

    @classmethod
    def from_manifest(cls, manifest_path: Path | str) -> SandboxPolicy:
        """Loads capability declarations from an mcp-manifest.json or package.json."""
        path = Path(manifest_path)
        content = json.loads(path.read_text(encoding="utf-8"))

        capabilities = content.get("capabilities", {})
        if not capabilities and "mcp" in content:
            capabilities = content["mcp"].get("capabilities", {})

        return cls(
            name=content.get("name", path.stem),
            fs_read_roots=capabilities.get("fs_read_roots", []),
            fs_write_roots=capabilities.get("fs_write_roots", []),
            allow_child_processes=capabilities.get("allow_child_processes", False),
            net_enabled=capabilities.get("net_enabled", False),
            net_allowed_hosts=capabilities.get("net_allowed_hosts", []),
        )
