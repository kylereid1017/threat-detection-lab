"""Critic role: pre-flight realism, syntax, and safety validation gate."""

from __future__ import annotations

import base64
import ipaddress
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import List

from .config import SafetyConstraints
from .models import CriticVerdict, Variant

#: Suffixes that identify a file rather than a network host, so a UNC-shaped string ending in
#: one is a Windows path, not a destination. Restricted to unambiguous file extensions: a
#: suffix that is also a real TLD (.com, .sh, .py) must never be listed here, or every host
#: under that TLD would be silently skipped.
FILE_LIKE_SUFFIXES = (
    ".exe", ".cmd", ".bat", ".scr", ".dll", ".sys", ".msi", ".ps1", ".psm1", ".vbs",
    ".js", ".mjs", ".cjs", ".jar", ".bin",
)

#: The declared destination policy, in one place, so the enforcement and the artifact wording
#: cannot drift apart. Anything outside these ranges is rejected.
PERMITTED_ADDRESS_RANGES = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",        # RFC 1122 loopback
        "0.0.0.0/32",         # unspecified
        "169.254.0.0/16",     # RFC 3927 link-local (incl. cloud metadata)
        "10.0.0.0/8",         # RFC 1918 private
        "172.16.0.0/12",      # RFC 1918 private
        "192.168.0.0/16",     # RFC 1918 private
        "192.0.2.0/24",       # RFC 5737 documentation
        "198.51.100.0/24",    # RFC 5737 documentation
        "203.0.113.0/24",     # RFC 5737 documentation
        "::1/128",            # IPv6 loopback
        "::/128",             # IPv6 unspecified
        "fe80::/10",          # IPv6 link-local
        "fc00::/7",           # RFC 4193 unique local
        "2001:db8::/32",      # RFC 3849 documentation
    )
)


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
        """Checks every destination form the Critic understands against the declared policy.

        Policy: reserved domain names (RFC 2606/6761) and non-routable or documentation address
        ranges (RFC 1122, RFC 1918, RFC 3927, RFC 5737). Checked forms: explicit URLs, defanged
        URLs, UNC paths, and destinations recovered from base64 blobs. Forms the Critic does not
        parse - a bare hostname with no scheme, for instance, which is indistinguishable from a
        filename - are listed as gaps in docs/swarm/architecture.md rather than assumed safe.
        """
        issues: List[str] = []

        for url in re.findall(r'https?://[^\s"\'<>`)]+', text, re.IGNORECASE):
            issues.extend(self._check_destination(urlparse(url).hostname or "", url))

        # Defanged / obfuscated schemes: hxxp://, h**p://, and bracketed dots.
        for raw in re.findall(r"h(?:xx|\*\*|tt)p(?:s)?://[^\s\"'<>`)]+", text, re.IGNORECASE):
            normalised = (
                raw.replace("hxxp", "http").replace("h**p", "http")
                .replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
            )
            issues.extend(self._check_destination(urlparse(normalised).hostname or "", raw))

        # UNC paths: \\host\share\... A local Windows path stored with escaped separators
        # (C:\\Users\\...\\Claude.exe) is the common case in telemetry payloads, so a UNC is
        # only recognised when the leading separator starts a value (not a continuation of a
        # path) and the host is a dotted name that is not a file name.
        for match in re.finditer(r'(?<![\\\w.])\\\\([A-Za-z0-9][A-Za-z0-9._-]*)(\\[^\s"\'<>`|]+)+', text):
            host = match.group(1)
            if "." not in host or host.lower().endswith(FILE_LIKE_SUFFIXES):
                continue
            issues.extend(self._check_destination(host, f"UNC {match.group(0)}"))

        # Base64 blobs: recover any destination the encoding was hiding.
        for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
            decoded = self._try_base64(blob)
            if not decoded:
                continue
            for hidden in re.findall(r'https?://[^\s"\'<>`)]+', decoded, re.IGNORECASE):
                issues.extend(self._check_destination(urlparse(hidden).hostname or "", f"base64-encoded {hidden}"))

        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
            if not self._ip_permitted(ip):
                issues.append(
                    f"Non-reserved IPv4 address '{ip}' detected. Permitted: loopback, link-local, "
                    f"RFC 1918 private, and RFC 5737 documentation ranges."
                )

        for token in re.findall(r"[0-9A-Fa-f:]{2,}", text):
            if token.count(":") < 2:
                continue
            try:
                address = ipaddress.ip_address(token)
            except ValueError:
                continue
            if not isinstance(address, ipaddress.IPv6Address):
                continue
            if not self._ip_permitted(str(address)):
                issues.append(f"Non-reserved IPv6 address '{token}' detected. Permitted: loopback, link-local, ULA, and documentation ranges.")

        return issues

    def _check_destination(self, host: str, raw: str) -> List[str]:
        """Applies the declared policy to one host; returns the violations, if any."""
        host = (host or "").lower()
        if not host:
            return []
        # W3C namespace identifiers appear inside inert SVG fixtures and are not destinations.
        if host in ("www.w3.org", "w3.org", "xmlns.w3.org"):
            return []
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return [] if any(host.endswith(tld) for tld in self.safety.allowed_tlds) else [
                f"Forbidden destination '{host}' (from {raw!r}): must end with an approved TLD ({self.safety.allowed_tlds})"
            ]
        return [] if self._ip_permitted(host) else [f"Non-reserved address '{host}' (from {raw!r}) detected in a destination."]

    @staticmethod
    def _ip_permitted(token: str) -> bool:
        """True only for loopback, unspecified, link-local, private, and documentation ranges."""
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            return False
        return any(address in network for network in PERMITTED_ADDRESS_RANGES)

    @staticmethod
    def _try_base64(blob: str) -> str:
        """Best-effort decode of a candidate blob; '' when it is not valid base64."""
        try:
            padded = blob + "=" * (-len(blob) % 4)
            decoded = base64.b64decode(padded, validate=True)
        except Exception:  # noqa: BLE001 - a non-base64 candidate is simply not decoded
            return ""
        return decoded.decode("utf-8", errors="ignore")
