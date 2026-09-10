"""Real-Time Agent Package Registry Watchdog & Triage Stream.

Monitors and evaluates newly published npm and PyPI packages in the Model Context
Protocol (MCP) and AI agent ecosystem. Automatically scores each package for:
1. Compound and homoglyph typosquats of protected namespaces (@modelcontextprotocol, anthropic, langchain).
2. Manifest privilege abuse (CLI executable 'bin' declarations, preinstall/postinstall hooks).
3. Maintainer account fragility (single maintainer, unverified publisher, missing OIDC).
4. Direct cross-reference against OpenSSF confirmed-malicious package feeds.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from tools.cti.protected_names import ProtectedRegistry

DEFAULT_PROTECTED_NAMES = {
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-git",
    "modelcontextprotocol",
    "mcp",
    "fastmcp",
    "anthropic",
    "claude-code",
    "openai",
    "langchain",
    "langchain-core",
    "llamaindex",
    "chromadb",
    "tiktoken",
    "groq",
}

# Known confirmed-malicious exemplars (offline hash-checked database)
KNOWN_MALICIOUS_AGENT_PACKAGES = {
    "@browserbasehq/mcp": "MAL-2025-191195",
    "@postman/postman-mcp-server": "MAL-2025-190909",
    "openai-mcp": "MAL-2026-5320",
    "groq-mcp": "MAL-2026-5321",
    "mcp-runcommand-server": "MAL-2026-5322",
    "mcp-runcommand-server2": "MAL-2026-5323",
}


@dataclass
class WatchdogAlert:
    """Triage alert emitted by the real-time agent watchdog."""

    package_name: str
    ecosystem: str
    version: str
    risk_score: int
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    action: str    # "QUARANTINE_IMMEDIATELY" | "AUDIT_REQUIRED" | "MONITOR" | "ALLOW"
    reasons: List[str] = field(default_factory=list)
    imitated_package: Optional[str] = None
    imitation_kind: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "action": self.action,
            "reasons": self.reasons,
            "imitated_package": self.imitated_package,
            "imitation_kind": self.imitation_kind,
            "timestamp": self.timestamp,
        }


class AgentRegistryWatchdog:
    """Evaluator that triages incoming package publications against agent threat models."""

    def __init__(
        self,
        protected_registry: Optional[ProtectedRegistry] = None,
        malicious_lookup: Optional[Dict[str, str]] = None,
    ) -> None:
        self.registry = protected_registry or ProtectedRegistry(
            names=set(DEFAULT_PROTECTED_NAMES), source="agent-watchdog-defaults"
        )
        self.malicious_lookup = malicious_lookup or dict(KNOWN_MALICIOUS_AGENT_PACKAGES)

    def evaluate_package(self, record: Dict[str, Any]) -> WatchdogAlert:
        """Evaluates a single package publication record and produces a WatchdogAlert."""
        name = record.get("name", "unknown")
        raw_ecosystem = record.get("ecosystem")
        version = record.get("version", "0.0.0")

        reasons: List[str] = []
        score = 0
        imitated_name: Optional[str] = None
        imitation_kind: Optional[str] = None

        # 1. Check confirmed malicious corpus
        lowered_name = name.lower()
        if lowered_name in self.malicious_lookup:
            adv = self.malicious_lookup[lowered_name]
            expected_ecosystem = {
                "@browserbasehq/mcp": "npm",
                "@postman/postman-mcp-server": "npm",
                "openai-mcp": "npm",
                "groq-mcp": "pypi",
                "mcp-runcommand-server": "pypi",
                "mcp-runcommand-server2": "pypi",
            }.get(lowered_name)

            ecosystem = raw_ecosystem.lower() if raw_ecosystem else (expected_ecosystem or "npm")

            if raw_ecosystem and expected_ecosystem and expected_ecosystem != raw_ecosystem.lower():
                score += 20
                reasons.append(
                    f"Historical advisory match in {expected_ecosystem.upper()} catalog ({adv}); "
                    f"ecosystem mismatch ({raw_ecosystem.lower()}) means malicious applicability is unverified."
                )
            else:
                score = 100
                reasons.append(f"Confirmed malicious package match in OpenSSF catalog ({adv}).")
                return WatchdogAlert(
                    package_name=name,
                    ecosystem=ecosystem,
                    version=version,
                    risk_score=score,
                    severity="CRITICAL",
                    action="QUARANTINE_IMMEDIATELY",
                    reasons=reasons,
                    imitated_package=None,
                    imitation_kind=None,
                )
        else:
            ecosystem = raw_ecosystem.lower() if raw_ecosystem else "npm"

        # 2. Typosquat / imitation check via ProtectedRegistry
        imitation = self.registry.nearest(name)
        if imitation:
            imitated_name = imitation.name
            imitation_kind = imitation.kind
            if imitation.kind == "misspelling":
                score += 45
                reasons.append(f"Keyboard typosquat / misspelling of protected dependency '{imitation.name}' (edit distance {imitation.distance}).")
            elif imitation.kind == "compound":
                score += 40
                reasons.append(f"Compound imitation embedding protected brand '{imitation.name}' in modular name.")
            elif imitation.kind == "substitution":
                score += 50
                reasons.append(f"Homoglyph character substitution of protected name '{imitation.name}'.")

        # 3. Privilege Manifest Checks (support both flat and nested acquisition manifest)
        manifest = record.get("manifest") if isinstance(record.get("manifest"), dict) else record

        # CLI Entrypoint ('bin')
        has_bin = bool(manifest.get("bin") or record.get("bin"))
        if has_bin:
            score += 20
            reasons.append("Declares executable CLI entrypoint ('bin') designed for dynamic runner execution.")

        # Lifecycle Scripts
        scripts = manifest.get("scripts") or record.get("scripts") or {}
        hooks = [h for h in ["preinstall", "postinstall", "prepare"] if h in scripts]
        if hooks:
            score += 25
            reasons.append(f"Declares automatic install lifecycle scripts: {', '.join(hooks)}.")

        # 4. Sensitive Dependencies / Egress
        deps = manifest.get("dependencies") or record.get("dependencies") or {}
        if isinstance(deps, list):
            deps_dict = {d: True for d in deps}
        elif isinstance(deps, dict):
            deps_dict = deps
        else:
            deps_dict = {}

        egress_libs = [l for l in ["axios", "node-fetch", "got", "urllib", "requests"] if l in deps_dict]
        if egress_libs:
            score += 10
            reasons.append(f"Direct outbound network egress libraries declared: {', '.join(egress_libs)}.")

        proc_libs = [l for l in ["execa", "cross-spawn", "subprocess"] if l in deps_dict]
        if proc_libs:
            score += 15
            reasons.append(f"Child process spawning libraries declared: {', '.join(proc_libs)}.")

        # 5. Maintainer Fragility
        maintainers = manifest.get("maintainers") or record.get("maintainers", [])
        if maintainers and len(maintainers) == 1:
            score += 5
            reasons.append("Single-maintainer concentration: elevated account takeover risk.")

        has_oidc = record.get("has_oidc") if "has_oidc" in record else manifest.get("has_oidc")
        if has_oidc is False:
            score += 5
            reasons.append("Missing cryptographic OIDC release provenance.")

        # Cap score at 100
        score = min(score, 100)

        # Determine Severity and Recommended Action
        if score >= 80:
            severity = "CRITICAL"
            action = "QUARANTINE_IMMEDIATELY"
        elif score >= 50:
            severity = "HIGH"
            action = "AUDIT_REQUIRED"
        elif score >= 25:
            severity = "MEDIUM"
            action = "MONITOR"
        else:
            severity = "LOW"
            action = "ALLOW"

        return WatchdogAlert(
            package_name=name,
            ecosystem=ecosystem,
            version=version,
            risk_score=score,
            severity=severity,
            action=action,
            reasons=reasons,
            imitated_package=imitated_name,
            imitation_kind=imitation_kind,
        )

    def scan_stream(self, records: Iterable[Dict[str, Any]], min_score: int = 0) -> List[WatchdogAlert]:
        """Processes an iterable stream of package records."""
        alerts: List[WatchdogAlert] = []
        for rec in records:
            alert = self.evaluate_package(rec)
            if alert.risk_score >= min_score:
                alerts.append(alert)
        return alerts


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="AI Agent Registry Watchdog & Triage Stream")
    parser.add_argument("--feed", type=str, help="JSONL file of package records to evaluate")
    parser.add_argument("--output", type=str, help="Path to write alerts in JSONL format")
    parser.add_argument("--min-score", type=int, default=25, help="Minimum risk score to report (default 25)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output display format")

    args = parser.parse_args(argv)
    watchdog = AgentRegistryWatchdog()

    records: List[Dict[str, Any]] = []
    if args.feed:
        feed_path = Path(args.feed)
        if not feed_path.exists():
            print(f"Error: feed file not found: {feed_path}", file=sys.stderr)
            return 1
        for line in feed_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    else:
        # Default built-in demonstration stream
        records = [
            {
                "name": "groq-mcp",
                "ecosystem": "pypi",
                "version": "1.4.3",
            },
            {
                "name": "@hacker/modelcontextprotocol-tools",
                "ecosystem": "npm",
                "version": "0.1.0",
                "bin": {"mcp-tools": "./bin.js"},
                "scripts": {"postinstall": "node setup.js"},
                "dependencies": {"axios": "^1.2.0"},
                "maintainers": ["attacker"],
                "has_oidc": False,
            },
            {
                "name": "fastmcp-helpers",
                "ecosystem": "pypi",
                "version": "0.0.1",
                "bin": {"fastmcp-tool": "main.py"},
            },
            {
                "name": "lodash",
                "ecosystem": "npm",
                "version": "4.17.21",
                "maintainers": ["jdalton", "mathias"],
                "has_oidc": True,
            },
        ]

    alerts = watchdog.scan_stream(records, min_score=args.min_score)

    if args.output:
        out_path = Path(args.output)
        with open(out_path, "w", encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(a.to_dict()) + "\n")
        print(f"Wrote {len(alerts)} alerts to {out_path}")

    if args.format == "json":
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        print(f"\n{'='*70}")
        print(f"AI AGENT REGISTRY WATCHDOG: TRIAGE RESULTS ({len(alerts)} alerts)")
        print(f"{'='*70}")
        for a in alerts:
            color = "\033[91m" if a.severity in ("CRITICAL", "HIGH") else "\033[93m"
            reset = "\033[0m"
            print(f"\n[{a.severity}] {a.package_name} (v{a.version}) - Risk Score: {a.risk_score}/100")
            print(f"Action: {a.action}")
            if a.imitated_package:
                print(f"Imitates: {a.imitated_package} ({a.imitation_kind})")
            print("Reasons:")
            for r in a.reasons:
                print(f"  - {r}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
