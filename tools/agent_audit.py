"""AI Agent Execution Layer Security Auditor (mcp-audit).

A defensive security tool that audits AI agent configurations (e.g. Claude Desktop,
Cursor, or autonomous agent tool manifests) to detect supply chain risks, unpinned
dynamic package execution, dangerous install hooks, exposed credentials, and
imitation lures targeting the Model Context Protocol (MCP) ecosystem.

Disciplines:
- NEVER downloads, unpacks, or executes package payloads. Inspects configuration
  files, manifests, and registry metadata only.
- Detects unpinned dynamic execution (`npx -y`, `uvx`) that pulls latest untrusted code.
- Evaluates configured packages against the CTI Protected Registry for typosquats.
- Cross-references packages against OpenSSF confirmed-malicious advisories.
- Flags exposed plaintext secrets and high-risk ambient filesystem mounts.

Usage:
    python tools/agent_audit.py --config path/to/claude_desktop_config.json
    python tools/agent_audit.py --sample-audit
    python tools/agent_audit.py --config config.json --out audit-results.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.cti.protected_names import ProtectedRegistry, normalize_package  # noqa: E402

DEFAULT_MALICIOUS_NPM = ROOT / "corpus" / "malicious" / "npm_malicious_packages.jsonl"
DEFAULT_MALICIOUS_PYPI = ROOT / "corpus" / "malicious" / "pypi_malicious_packages.jsonl"

# Standard authoritative tooling for the protected registry
DEFAULT_PROTECTED_CATALOG = [
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-sentry",
    "modelcontextprotocol",
    "mcp",
    "fastmcp",
    "langchain",
    "langchain-core",
    "langgraph",
    "anthropic",
    "openai",
    "groq",
    "llamaindex",
]

# Sensitive keys or patterns in environment configurations
SECRET_KEY_PATTERNS = [
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"api_?key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
]

# URI patterns with embedded credentials (e.g. postgres://user:pass@host/db)
EMBEDDED_CRED_URI = re.compile(r":\/\/[^:]+:[^@]+@")

# Dynamic package runner executables
DYNAMIC_RUNNERS = {"npx", "npx.cmd", "uvx", "uvx.exe", "pipx", "bunx"}

SECRET_ARG_PATTERNS = [
    re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]*://[^:]+:)([^@]+)(@)"),
    re.compile(r"(api[_-]?key|secret|token|password|auth|credential|conn[_-]?str)=([^\s]+)", re.IGNORECASE),
    re.compile(r"(bearer\s+)([a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    re.compile(r"\b(sk-[a-zA-Z0-9_\-]{16,}|ghp_[a-zA-Z0-9]{20,}|glpat-[a-zA-Z0-9_\-]{20,})\b"),
]


def redact_secret_str(s: str) -> str:
    """Redacts secrets and connection strings from display strings and metadata."""
    res = str(s)
    if "://" in res and "@" in res:
        res = re.sub(r"://([^:]+):([^@]+)@", r"://\1:[REDACTED]@", res)
    for p in SECRET_ARG_PATTERNS:
        res = p.sub(r"\1=[REDACTED]", res)
    return res


def redact_secrets_in_args(args: Sequence[str]) -> List[str]:
    """Redacts credential tokens and connection strings in command arguments."""
    return [redact_secret_str(a) for a in args]


def _is_exact_version_pin(v: str) -> bool:
    """True only if version is an exact version pin, not a range or dist-tag."""
    if not v:
        return False
    v = v.strip()
    if any(c in v for c in ("^", "~", "*", ">", "<", "x", "X", " ")):
        return False
    if v.lower() in ("latest", "next", "beta", "alpha", "rc", "canary", "dev", "nightly"):
        return False
    return bool(re.match(r"^[0-9]+(\.[0-9]+)*([+-][a-zA-Z0-9.]+)?$", v))


@dataclass
class AuditFinding:
    server_name: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str
    title: str
    description: str
    remediation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_name": self.server_name,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


def find_default_config_paths() -> List[Path]:
    """Return standard locations where agent configs live across operating systems."""
    candidates = []

    # Windows
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
        candidates.append(Path(appdata) / "Cursor" / "mcp.json")

    # macOS / Linux
    home = Path.home()
    candidates.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")
    candidates.append(home / ".cursor" / "mcp.json")
    candidates.append(Path.cwd() / "claude_desktop_config.json")
    candidates.append(Path.cwd() / "mcp_servers.json")

    return [p for p in candidates if p.exists() and p.is_file()]


def load_malicious_index(npm_path: Path, pypi_path: Path) -> Dict[str, str]:
    """Load OpenSSF malicious packages into a normalized lookup map."""
    mal_map: Dict[str, str] = {}
    for p in (npm_path, pypi_path):
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        name = data.get("name", "").strip().lower()
                        adv = data.get("advisory", "MAL-KNOWN")
                        if name:
                            mal_map[name] = adv
                    except json.JSONDecodeError:
                        continue
    return mal_map


def audit_server_entry(
    server_name: str,
    server_conf: Dict[str, Any],
    protected_registry: ProtectedRegistry,
    malicious_index: Dict[str, str],
) -> List[AuditFinding]:
    """Audit a single configured MCP server entry."""
    findings: List[AuditFinding] = []

    command = str(server_conf.get("command", "")).strip()
    args = [str(a) for a in server_conf.get("args", [])]
    env = server_conf.get("env", {}) if isinstance(server_conf.get("env"), dict) else {}

    base_cmd = Path(command).name.lower()

    # -----------------------------------------------------------------------
    # 1. Unpinned Dynamic Execution & Runner Checks
    # -----------------------------------------------------------------------
    if base_cmd in DYNAMIC_RUNNERS:
        is_npx = "npx" in base_cmd
        is_uvx = "uvx" in base_cmd

        # Check for unprompted auto-confirm flags (-y, --yes)
        has_auto_confirm = any(a in ("-y", "--yes") for a in args)

        # Identify package target in args
        pkg_arg = None
        for a in args:
            if not a.startswith("-") and not a.endswith(".js") and not a.endswith(".py"):
                pkg_arg = a
                break

        if has_auto_confirm:
            findings.append(AuditFinding(
                server_name=server_name,
                severity="HIGH",
                category="dynamic_execution",
                title="Unpinned Dynamic Execution Flag (-y/--yes)",
                description=(
                    f"Server '{server_name}' invokes '{base_cmd}' with '{args[0] if args else ''}', "
                    "bypassing interactive confirmation and package verification."
                ),
                remediation=(
                    "Install the tool package locally with a lockfile, or remove dynamic flags "
                    "and pin an exact cryptographic integrity hash."
                ),
                metadata={"command": redact_secret_str(command), "args": redact_secrets_in_args(args)},
            ))

        if pkg_arg:
            # Check version pinning in package argument
            is_pinned = False
            if is_npx:
                scope_offset = 1 if pkg_arg.startswith("@") else 0
                if "@" in pkg_arg[scope_offset:]:
                    version_part = pkg_arg[scope_offset:].rsplit("@", 1)[1]
                    if _is_exact_version_pin(version_part):
                        is_pinned = True
            elif is_uvx:
                if "==" in pkg_arg:
                    v = pkg_arg.split("==", 1)[1]
                    if _is_exact_version_pin(v):
                        is_pinned = True
                elif "--from" in args:
                    idx = args.index("--from")
                    if idx + 1 < len(args):
                        from_target = args[idx + 1]
                        if "==" in from_target:
                            v = from_target.split("==", 1)[1]
                            if _is_exact_version_pin(v):
                                is_pinned = True

            if not is_pinned:
                findings.append(AuditFinding(
                    server_name=server_name,
                    severity="CRITICAL",
                    category="supply_chain_unpinned",
                    title="Floating Package Version Target",
                    description=(
                        f"Server '{server_name}' executes '{pkg_arg}' without an exact version pin. "
                        "A newly published upstream version or compromised release will execute automatically."
                    ),
                    remediation=f"Pin package to an exact tested version, e.g. '{pkg_arg}@<version>' or '{pkg_arg}==<version>'.",
                    metadata={"target_package": pkg_arg},
                ))

            # ---------------------------------------------------------------
            # 2. Lifecycle Script Execution
            # ---------------------------------------------------------------
            if is_npx and not any(a == "--ignore-scripts" for a in args):
                findings.append(AuditFinding(
                    server_name=server_name,
                    severity="MEDIUM",
                    category="passive_lifecycle_hooks",
                    title="Install Scripts Allowed (--ignore-scripts Missing)",
                    description=(
                        f"Server '{server_name}' resolves packages via npm without '--ignore-scripts'. "
                        "Our population study established that 26.0% of agent packages declare install hooks, "
                        "enabling arbitrary code execution during package setup."
                    ),
                    remediation="Add '--ignore-scripts' to the args array in configuration.",
                    metadata={"args": redact_secrets_in_args(args)},
                ))

            # ---------------------------------------------------------------
            # 3. Protected Name / Typosquat / Compound Lure Inspection
            # ---------------------------------------------------------------
            clean_pkg = re.split(r"[=><~]", pkg_arg)[0]
            if clean_pkg.startswith("@"):
                parts = clean_pkg.split("@")
                clean_pkg = "@" + parts[1] if len(parts) >= 2 else clean_pkg
            elif "@" in clean_pkg:
                clean_pkg = clean_pkg.split("@", 1)[0]

            imitation = protected_registry.nearest(clean_pkg)
            if imitation:
                findings.append(AuditFinding(
                    server_name=server_name,
                    severity="HIGH" if imitation.kind == "compound" else "CRITICAL",
                    category="imitation_lure",
                    title=f"Potential Typosquat or Compound Lure ({imitation.kind})",
                    description=(
                        f"Package '{clean_pkg}' closely imitates authoritative package '{imitation.name}' "
                        f"(kind: {imitation.kind}, edit distance: {imitation.distance}). "
                        "95.2% of agent ecosystem imitations are compound lures exploiting modular names."
                    ),
                    remediation=f"Verify if the intention was to use official '{imitation.name}' instead of '{clean_pkg}'.",
                    metadata={"imitated": imitation.name, "kind": imitation.kind, "distance": imitation.distance},
                ))

            # ---------------------------------------------------------------
            # 4. OpenSSF Malicious Dataset Cross-Reference
            # ---------------------------------------------------------------
            lowered_pkg = clean_pkg.lower()
            if lowered_pkg in malicious_index:
                adv = malicious_index[lowered_pkg]
                expected_eco = "npm" if is_npx else ("pypi" if is_uvx else None)
                known_ecos = {
                    "@browserbasehq/mcp": "npm",
                    "@postman/postman-mcp-server": "npm",
                    "openai-mcp": "npm",
                    "groq-mcp": "pypi",
                    "mcp-runcommand-server": "pypi",
                    "mcp-runcommand-server2": "pypi",
                }
                adv_eco = known_ecos.get(lowered_pkg)
                if adv_eco and expected_eco and adv_eco != expected_eco:
                    findings.append(AuditFinding(
                        server_name=server_name,
                        severity="MEDIUM",
                        category="advisory_ecosystem_mismatch",
                        title="Advisory Name Match in Different Ecosystem",
                        description=(
                            f"Package '{clean_pkg}' matches advisory '{adv}' in the {adv_eco.upper()} registry, "
                            f"but is executed via {expected_eco.upper()} runner. Present malice unverified."
                        ),
                        remediation="Verify package provenance and author identity.",
                        metadata={"package": clean_pkg, "advisory": adv, "ecosystem": expected_eco},
                    ))
                else:
                    findings.append(AuditFinding(
                        server_name=server_name,
                        severity="CRITICAL",
                        category="confirmed_malicious",
                        title="Package Listed in OpenSSF Malicious Advisories",
                        description=(
                            f"Package '{clean_pkg}' matches OpenSSF advisory '{adv}'. "
                            "This identity is confirmed malicious or was compromised post-publication."
                        ),
                        remediation="Immediately remove this server from configuration and rotate all host credentials.",
                        metadata={"package": clean_pkg, "advisory": adv},
                    ))

    # -----------------------------------------------------------------------
    # 5. Dangerous Ambient Environment & Credential Exposure
    # -----------------------------------------------------------------------
    for k, v in env.items():
        v_str = str(v)
        # Check for embedded connection URIs with plaintext passwords
        if EMBEDDED_CRED_URI.search(v_str):
            findings.append(AuditFinding(
                server_name=server_name,
                severity="HIGH",
                category="credential_exposure",
                title="Plaintext Credentials in Connection String",
                description=(
                    f"Environment variable '{k}' contains an embedded username/password URI in plaintext. "
                    "Child processes inherit this configuration directly."
                ),
                remediation="Store secrets in OS keychain or load credentials dynamically via secret manager.",
                metadata={"variable": k},
            ))
        elif any(p.search(k) for p in SECRET_KEY_PATTERNS) and len(v_str) >= 8:
            findings.append(AuditFinding(
                server_name=server_name,
                severity="MEDIUM",
                category="plaintext_secret",
                title="Plaintext Secret Stored in Agent Config",
                description=(
                    f"Environment variable '{k}' in server '{server_name}' appears to store a sensitive token or key in plaintext."
                ),
                remediation="Avoid storing static tokens directly in JSON config files.",
                metadata={"variable": k},
            ))

    # Check for root/home path mounting in arguments
    for a in args:
        is_broad_root = a in ("/", "C:\\", "C:/", "~") or a.startswith("/root")
        is_home_dir = bool(re.match(r"^(?:[a-zA-Z]:[\\/]|/)(?:Users|home)[\\/][^\\/]+[\\/]?$", a, re.IGNORECASE))
        if is_broad_root or is_home_dir:
            findings.append(AuditFinding(
                server_name=server_name,
                severity="HIGH",
                category="overprivileged_filesystem",
                title="Overly Broad Root Filesystem Scope",
                description=(
                    f"Server '{server_name}' is granted ambient access to '{a}'. "
                    "This exposes entire system directories and developer profiles to agent tools."
                ),
                remediation="Scope filesystem access strictly to specific project workspace subdirectories.",
                metadata={"path_arg": redact_secret_str(a)},
            ))

    return findings


def audit_config_data(
    config_data: Dict[str, Any],
    protected_names: List[str],
    malicious_index: Dict[str, str],
) -> Tuple[List[AuditFinding], Dict[str, Any]]:
    """Audit parsed agent configuration dictionary."""
    protected_registry = ProtectedRegistry(names=set(protected_names), source="agent-audit-registry")
    has_recognized_schema = any(k in config_data for k in ("mcpServers", "servers", "mcp_servers"))
    servers = config_data.get("mcpServers") or config_data.get("servers") or config_data.get("mcp_servers")

    if not has_recognized_schema or not isinstance(servers, dict):
        return [], {
            "total_servers": 0,
            "status": "unsupported_schema",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }

    all_findings: List[AuditFinding] = []
    for s_name, s_conf in servers.items():
        if isinstance(s_conf, dict):
            findings = audit_server_entry(s_name, s_conf, protected_registry, malicious_index)
            all_findings.extend(findings)

    summary = {
        "total_servers": len(servers),
        "total_findings": len(all_findings),
        "critical_count": sum(1 for f in all_findings if f.severity == "CRITICAL"),
        "high_count": sum(1 for f in all_findings if f.severity == "HIGH"),
        "medium_count": sum(1 for f in all_findings if f.severity == "MEDIUM"),
        "low_count": sum(1 for f in all_findings if f.severity == "LOW"),
    }

    return all_findings, summary


def generate_sample_config() -> Dict[str, Any]:
    """Generate a realistic test agent configuration containing both benign and insecure patterns."""
    return {
        "mcpServers": {
            "filesystem-safe": {
                "command": "node",
                "args": ["/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "./data"]
            },
            "unpinned-postgres": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://admin:superSecret123@localhost/prod_db"]
            },
            "sqlite-unpinned-hookable": {
                "command": "npx",
                "args": ["-y", "mcp-server-sqlite", "test.db"]
            },
            "compound-lure-server": {
                "command": "npx",
                "args": ["-y", "@untrusted-scope/modelcontextprotocol-sdk"]
            },
            "malicious-lead-server": {
                "command": "python",
                "args": ["-m", "groq-mcp"]
            },
            "broad-fs-server": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/"]
            }
        }
    }


def format_report_text(findings: List[AuditFinding], summary: Dict[str, Any], config_path_label: str) -> str:
    """Format human-readable CLI report."""
    lines = [
        "=" * 72,
        "  AI AGENT EXECUTION LAYER SECURITY AUDIT (mcp-audit)",
        f"  Target Configuration: {config_path_label}",
        f"  Audit Date: {date.today()}",
        "=" * 72,
        f"Total Servers Audited: {summary.get('total_servers', 0)}",
        f"Findings: {summary.get('total_findings', 0)} "
        f"(CRITICAL: {summary.get('critical_count', 0)}, "
        f"HIGH: {summary.get('high_count', 0)}, "
        f"MEDIUM: {summary.get('medium_count', 0)})",
        "-" * 72,
    ]

    if summary.get("status") in ("unsupported_schema", "invalid_servers_block") or summary.get("total_servers", 0) == 0:
        lines.append("[-] Configuration unsupported or contains zero parsed server declarations.")
        lines.append("    Audit incomplete: no assertions made about hardening baseline.")
        lines.append("=" * 72)
        return "\n".join(lines)

    if not findings:
        lines.append("[+] Zero security findings detected. Agent configuration follows hardening baseline.")
        lines.append("=" * 72)
        return "\n".join(lines)

    for i, f in enumerate(findings, 1):
        lines.extend([
            f"[{i}] [{f.severity}] [{f.server_name}] {f.title}",
            f"    Category:    {f.category}",
            f"    Detail:      {f.description}",
            f"    Remediation: {f.remediation}",
            ""
        ])

    lines.append("=" * 72)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit AI agent configurations (Claude Desktop, Cursor) for execution layer supply-chain risks."
    )
    parser.add_argument("--config", type=Path, help="Path to agent JSON configuration file")
    parser.add_argument("--sample-audit", action="store_true", help="Run audit against synthetic agent configuration")
    parser.add_argument("--out", type=Path, help="Write machine-readable JSON results to output path")
    parser.add_argument("--malicious-npm", type=Path, default=DEFAULT_MALICIOUS_NPM)
    parser.add_argument("--malicious-pypi", type=Path, default=DEFAULT_MALICIOUS_PYPI)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    config_path = args.config
    is_sample = args.sample_audit

    if is_sample:
        config_data = generate_sample_config()
        config_label = "<synthetic sample configuration>"
    elif config_path:
        if not config_path.exists():
            print(f"[-] Error: Configuration file not found at {config_path}")
            sys.exit(1)
        try:
            config_data = json.loads(config_path.read_text(encoding="utf-8"))
            config_label = str(config_path)
        except Exception as exc:
            print(f"[-] Error parsing JSON configuration: {exc}")
            sys.exit(1)
    else:
        found_paths = find_default_config_paths()
        if found_paths:
            config_path = found_paths[0]
            print(f"[*] Discovered agent configuration at: {config_path}")
            config_data = json.loads(config_path.read_text(encoding="utf-8"))
            config_label = str(config_path)
        else:
            print("[*] No standard agent configuration discovered on system.")
            print("[*] Executing audit on synthetic sample configuration to demonstrate security baseline...\n")
            config_data = generate_sample_config()
            config_label = "<synthetic sample configuration>"

    malicious_map = load_malicious_index(args.malicious_npm, args.malicious_pypi)
    findings, summary = audit_config_data(config_data, DEFAULT_PROTECTED_CATALOG, malicious_map)

    report_text = format_report_text(findings, summary, config_label)
    print(report_text)

    if args.out:
        out_report = {
            "title": "AI Agent Execution Layer Security Audit",
            "date": str(date.today()),
            "config_source": config_label,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(out_report, indent=2) + "\n", encoding="utf-8")
        print(f"[+] Machine-readable audit report emitted to: {args.out}")


if __name__ == "__main__":
    main()
