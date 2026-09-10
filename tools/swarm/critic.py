"""Agent 3 — The Critic: Pre-flight realism, syntax, and safety validation gate."""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import List

from .config import SafetyConstraints
from .models import CriticVerdict, Variant


class SwarmCritic:
    """Evaluates variants against safety constraints and syntax standards before detector execution."""

    def __init__(self, safety: SafetyConstraints | None = None) -> None:
        self.safety = safety or SafetyConstraints()

    def evaluate(self, variant: Variant) -> CriticVerdict:
        """Runs syntax validation and safety boundary checks on a candidate variant."""
        violations: List[str] = []
        syntax_valid = True

        # 1. Syntax Validation
        if variant.target_type == "yara":
            if not isinstance(variant.payload, str):
                return CriticVerdict(
                    variant_id=variant.id,
                    passed=False,
                    reason="Payload must be a string for YARA target",
                    syntax_valid=False
                )
            trimmed = variant.payload.strip()
            if trimmed.startswith("<"):
                try:
                    ET.fromstring(variant.payload)
                except ET.ParseError as exc:
                    syntax_valid = False
                    violations.append(f"Invalid XML/SVG syntax: {exc}")
            elif trimmed.startswith("{") or trimmed.startswith("["):
                import json
                try:
                    json.loads(variant.payload)
                except Exception as exc:
                    syntax_valid = False
                    violations.append(f"Invalid JSON syntax: {exc}")
        elif variant.target_type == "sigma":
            if not isinstance(variant.payload, dict):
                return CriticVerdict(
                    variant_id=variant.id,
                    passed=False,
                    reason="Payload must be a dictionary for Sigma target",
                    syntax_valid=False
                )
            is_process = {"ParentImage", "Image", "CommandLine"}.issubset(variant.payload.keys())
            is_cloud = {"eventSource", "eventName"}.issubset(variant.payload.keys())
            if not (is_process or is_cloud):
                syntax_valid = False
                violations.append("Missing required telemetry keys: requires either {ParentImage, Image, CommandLine} or {eventSource, eventName}")

        # 2. Safety Gate: Domain & URL containment
        payload_text = variant.payload if isinstance(variant.payload, str) else str(variant.payload)
        safety_issues = self._check_safety_boundaries(payload_text)
        violations.extend(safety_issues)

        passed = syntax_valid and len(violations) == 0
        reason = "Passed all pre-flight syntax and safety checks" if passed else "; ".join(violations)

        return CriticVerdict(
            variant_id=variant.id,
            passed=passed,
            reason=reason,
            safety_violations=violations,
            syntax_valid=syntax_valid
        )

    def _check_safety_boundaries(self, text: str) -> List[str]:
        """Ensures that all URLs and network targets adhere strictly to safe reserved ranges."""
        issues: List[str] = []

        # Find all URLs
        urls = re.findall(r'https?://[^\s"\'<>`)]+', text, re.IGNORECASE)
        for url in urls:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            # Allow standard XML/W3C namespace schema identifiers and link-local metadata
            if (
                hostname.lower() in ("www.w3.org", "w3.org", "localhost", "127.0.0.1", "::1")
                or hostname.startswith("169.254.")
            ):
                continue
            if not any(hostname.lower().endswith(tld) for tld in self.safety.allowed_tlds):
                issues.append(
                    f"Forbidden destination '{hostname}': must end with an approved TLD ({self.safety.allowed_tlds})"
                )

        # Check for raw routable public IP addresses (allow localhost and 169.254. link-local metadata)
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        for ip in ip_matches:
            if not (ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("169.254.")):
                issues.append(f"Routable IPv4 address '{ip}' detected. Live IPs are forbidden in sandbox.")

        # Check for raw routable IPv6 literals (loopback, unspecified and link-local allowed)
        for token in re.findall(r"[0-9A-Fa-f:]{2,}", text):
            if token.count(":") < 2:
                continue
            try:
                address = ipaddress.ip_address(token)
            except ValueError:
                continue
            if not isinstance(address, ipaddress.IPv6Address):
                continue
            if address.is_loopback or address.is_unspecified or address.is_link_local:
                continue
            issues.append(f"Routable IPv6 address '{token}' detected. Live IPs are forbidden in sandbox.")

        return issues
