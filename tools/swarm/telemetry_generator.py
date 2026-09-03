"""EPIC 1 — Synthetic Telemetry Generator (schema boundary testing).

A flexible, schema-driven replacement for procedural text templates. Produces
diverse, strictly inert Windows telemetry fixtures (Sysmon Event ID 1 and
Security Event ID 4688) and programmatic command-line permutations used to probe
the syntactic resilience boundary of detection analytics.

Safety invariants (non-negotiable):
    * Every generated record is validated against RFC 2606 / RFC 5737 reserved
      documentation endpoints before it is returned to any analyzer.
    * No live network egress, no binary payloads, no routable destinations.
"""

from __future__ import annotations

import ipaddress
import random
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import EventSequence, TelemetryEvent

# Reserved, non-routable documentation endpoints (RFC 2606 + RFC 5737 + loopback).
ALLOWED_TLDS: Tuple[str, ...] = (".invalid", ".test", ".example", ".localhost")
ALLOWED_TEST_NETS: Tuple[str, ...] = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
ALLOWED_HOSTNAMES: Tuple[str, ...] = ("www.w3.org", "w3.org", "localhost")

# Canonical Sysmon/Security channel identifiers.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

_URL_RE = re.compile(r"https?://[^\s\"'<>`)]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class TelemetrySafetyError(ValueError):
    """Raised when a generated record would breach sandbox containment guarantees."""


def assert_safe_text(text: str) -> None:
    """Validates that *text* references only reserved documentation endpoints.

    Raises:
        TelemetrySafetyError: if a routable host or IP address is present.
    """
    for url in _URL_RE.findall(text):
        host = _extract_host(url)
        if host in ALLOWED_HOSTNAMES:
            continue
        if _is_test_ip(host):
            continue
        if not any(host.endswith(tld) for tld in ALLOWED_TLDS):
            raise TelemetrySafetyError(
                f"Forbidden destination host '{host}': telemetry must target RFC 2606 reserved domains "
                f"({', '.join(ALLOWED_TLDS)}) or RFC 5737 test-nets."
            )
    for ip in _IPV4_RE.findall(text):
        if not (_is_test_ip(ip) or ip.startswith("127.") or ip == "0.0.0.0"):
            raise TelemetrySafetyError(
                f"Routable IPv4 address '{ip}' detected. Only loopback and RFC 5737 test-nets are permitted."
            )


def _extract_host(url: str) -> str:
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "").lower()


def _is_test_ip(candidate: str) -> bool:
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net) for net in ALLOWED_TEST_NETS)


@dataclass
class CommandSpec:
    """Declarative description of a process invocation to be rendered and mutated."""

    binary: str
    image_path: str
    args: List[str] = field(default_factory=list)
    parent_image: str = "C:\\Windows\\explorer.exe"
    parent_command_line: str = "C:\\Windows\\explorer.exe"
    user: str = "VICTIM-PC\\analyst"
    integrity_level: str = "Medium"

    def render(self, args: Optional[List[str]] = None) -> str:
        """Renders the command line as ``binary arg1 arg2 ...``."""
        parts = [self.binary, *(args if args is not None else self.args)]
        return " ".join(p for p in parts if p != "").strip()


class CommandLineMutator:
    """Generates deterministic command-line permutations along syntactic axes.

    The mutation axes (argument reordering, integer switch aliasing, whitespace
    padding, and wrapper-host injection) are exactly the low-cost variations an
    adversary applies to defeat brittle literal-string analytics.
    """

    #: Wrapper hosts that re-parent a payload away from a monitored parent/child edge.
    WRAPPERS: Dict[str, Tuple[str, str]] = {
        "wt": ("C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.19\\wt.exe", "wt.exe"),
        "conhost": ("C:\\Windows\\System32\\conhost.exe", "conhost.exe"),
        "cmd": ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
    }

    #: PowerShell ``-WindowStyle`` aliases that are semantically equivalent to ``hidden``.
    WINDOW_ALIASES: Tuple[str, ...] = ("-w hidden", "-w 1", "-w h", "-windowstyle hidden", "-windowstyle 1")

    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)

    def reorder_args(self, spec: CommandSpec) -> Tuple[str, str]:
        """Deterministically shuffles switch/value pairs while preserving semantics."""
        pairs = self._tokenize_pairs(spec.args)
        order = list(range(len(pairs)))
        self.rng.shuffle(order)
        reordered: List[str] = []
        for idx in order:
            reordered.extend(pairs[idx])
        return "arg_reorder", spec.render(reordered)

    def integer_switch(self, spec: CommandSpec) -> Tuple[str, str]:
        """Substitutes a literal ``-w hidden`` for its integer alias ``-w 1``."""
        rendered = spec.render()
        mutated = re.sub(r"-w\s+hidden", "-w 1", rendered, flags=re.IGNORECASE)
        mutated = re.sub(r"-windowstyle\s+hidden", "-windowstyle 1", mutated, flags=re.IGNORECASE)
        return "integer_switch", mutated

    def whitespace(self, spec: CommandSpec) -> Tuple[str, str]:
        """Injects redundant whitespace (double spaces, tab) between tokens."""
        rendered = spec.render()
        mutated = rendered.replace(" ", "  ", 1)
        if " -" in mutated:
            mutated = mutated.replace(" -", " \t-", 1)
        return "whitespace_pad", mutated

    def wrapper(self, spec: CommandSpec, wrapper: str = "wt") -> Tuple[str, str, str, str]:
        """Wraps the invocation in a terminal/host process to re-parent execution.

        Returns:
            (mutation_name, wrapped_command_line, wrapper_image_path, wrapper_binary)
        """
        if wrapper not in self.WRAPPERS:
            raise ValueError(f"Unknown wrapper '{wrapper}'. Choose from {sorted(self.WRAPPERS)}.")
        image_path, binary = self.WRAPPERS[wrapper]
        inner = spec.render()
        if wrapper == "cmd":
            wrapped = f"cmd.exe /c {inner}"
        else:
            wrapped = f"{binary} {inner}"
        return f"wrapper_{wrapper}", wrapped, image_path, binary

    def mutate_all(self, spec: CommandSpec) -> List[Tuple[str, str]]:
        """Returns every syntactic command-line permutation for *spec*."""
        mutations: List[Tuple[str, str]] = [("baseline", spec.render())]
        mutations.append(self.reorder_args(spec))
        mutations.append(self.integer_switch(spec))
        mutations.append(self.whitespace(spec))
        wname, wcmd, _, _ = self.wrapper(spec, "wt")
        mutations.append((wname, wcmd))
        # De-duplicate while preserving order.
        seen: set[str] = set()
        unique: List[Tuple[str, str]] = []
        for name, cmd in mutations:
            if cmd not in seen:
                seen.add(cmd)
                unique.append((name, cmd))
        return unique

    @staticmethod
    def _tokenize_pairs(args: List[str]) -> List[List[str]]:
        """Groups an argument vector into ``[switch, value]`` pairs for safe reordering."""
        pairs: List[List[str]] = []
        i = 0
        while i < len(args):
            token = args[i]
            if token.startswith("-") and i + 1 < len(args) and not args[i + 1].startswith("-"):
                pairs.append([token, args[i + 1]])
                i += 2
            else:
                pairs.append([token])
                i += 1
        return pairs


class TelemetryGenerator:
    """Schema-driven builder for inert, validated Windows telemetry fixtures.

    Args:
        seed: Seed driving deterministic command-line mutation ordering.
        offline_mock: When ``True``, all mutation axes collapse to the canonical
            baseline rendering, yielding a stable offline fixture set with no
            pseudo-random variation. Useful for reproducible CI snapshots.
        base_time: ISO-like base timestamp (``YYYY-MM-DD HH:MM:SS``) anchoring the
            generated timeline. Successive events advance by ``dwell_seconds``.
        dwell_seconds: Seconds between successive events on a generated timeline.
    """

    def __init__(
        self,
        seed: int = 1337,
        offline_mock: bool = False,
        base_time: str = "2026-09-03 14:00:00",
        dwell_seconds: int = 5,
    ) -> None:
        self.mutator = CommandLineMutator(seed=seed)
        self.offline_mock = offline_mock
        self.base_time = base_time
        self.dwell_seconds = dwell_seconds
        self._tick = 0

    # -- timeline helpers -------------------------------------------------

    def _timestamp(self, offset_index: Optional[int] = None) -> str:
        from datetime import datetime, timedelta, timezone

        idx = self._tick if offset_index is None else offset_index
        base = datetime.strptime(self.base_time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        stamp = base + timedelta(seconds=idx * self.dwell_seconds)
        if offset_index is None:
            self._tick += 1
        return stamp.strftime("%Y-%m-%d %H:%M:%S.000")

    def reset_timeline(self) -> None:
        self._tick = 0

    # -- event builders ---------------------------------------------------

    def process_creation(
        self,
        image_path: str,
        command_line: str,
        parent_image: str = "C:\\Windows\\explorer.exe",
        user: str = "VICTIM-PC\\analyst",
        utc_time: Optional[str] = None,
        integrity_level: str = "Medium",
        as_4688: bool = False,
    ) -> TelemetryEvent:
        """Builds a Process Creation event (Sysmon EID 1 or Security EID 4688)."""
        stamp = utc_time or self._timestamp()
        if as_4688:
            fields = {
                "NewProcessName": image_path,
                "ParentProcessName": parent_image,
                "CommandLine": command_line,
                "SubjectUserName": user.split("\\")[-1],
                "TokenElevationType": "%%1938",
            }
            event = TelemetryEvent(
                event_id=4688,
                channel=SECURITY_CHANNEL,
                utc_time=stamp,
                fields=fields,
                provider="Microsoft-Windows-Security-Auditing",
                description="Security process creation (4688)",
            )
        else:
            fields = {
                "Image": image_path,
                "ParentImage": parent_image,
                "CommandLine": command_line,
                "User": user,
                "IntegrityLevel": integrity_level,
                "ProcessId": str(4000 + self._tick),
            }
            event = TelemetryEvent(
                event_id=1,
                channel=SYSMON_CHANNEL,
                utc_time=stamp,
                fields=fields,
                provider="Microsoft-Windows-Sysmon",
                description="Sysmon process creation (EID 1)",
            )
        self.validate(event)
        return event

    def image_load(
        self,
        image_path: str,
        image_loaded: str,
        signed: bool = False,
        signature_status: str = "Unavailable",
        utc_time: Optional[str] = None,
    ) -> TelemetryEvent:
        """Builds a Module/Image Load event (Sysmon EID 7)."""
        event = TelemetryEvent(
            event_id=7,
            channel=SYSMON_CHANNEL,
            utc_time=utc_time or self._timestamp(),
            fields={
                "Image": image_path,
                "ImageLoaded": image_loaded,
                "Signed": "true" if signed else "false",
                "SignatureStatus": signature_status,
            },
            provider="Microsoft-Windows-Sysmon",
            description="Sysmon image load (EID 7)",
        )
        self.validate(event)
        return event

    def process_access(
        self,
        source_image: str,
        target_image: str,
        granted_access: str = "0x1010",
        call_trace: str = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d2b4",
        utc_time: Optional[str] = None,
    ) -> TelemetryEvent:
        """Builds a Process Access event (Sysmon EID 10)."""
        event = TelemetryEvent(
            event_id=10,
            channel=SYSMON_CHANNEL,
            utc_time=utc_time or self._timestamp(),
            fields={
                "SourceImage": source_image,
                "TargetImage": target_image,
                "GrantedAccess": granted_access,
                "CallTrace": call_trace,
            },
            provider="Microsoft-Windows-Sysmon",
            description="Sysmon process access (EID 10)",
        )
        self.validate(event)
        return event

    def file_create(
        self,
        image_path: str,
        target_filename: str,
        utc_time: Optional[str] = None,
    ) -> TelemetryEvent:
        """Builds a File System Activity event (Sysmon EID 11 — FileCreate)."""
        event = TelemetryEvent(
            event_id=11,
            channel=SYSMON_CHANNEL,
            utc_time=utc_time or self._timestamp(),
            fields={
                "Image": image_path,
                "TargetFilename": target_filename,
                "CreationUtcTime": utc_time or self.base_time,
            },
            provider="Microsoft-Windows-Sysmon",
            description="Sysmon file create (EID 11)",
        )
        self.validate(event)
        return event

    def script_block(
        self,
        script_block_text: str,
        path: str = "",
        message_number: int = 1,
        message_total: int = 1,
        utc_time: Optional[str] = None,
    ) -> TelemetryEvent:
        """Builds a PowerShell Script Block Logging event (EID 4104)."""
        event = TelemetryEvent(
            event_id=4104,
            channel=POWERSHELL_CHANNEL,
            utc_time=utc_time or self._timestamp(),
            fields={
                "ScriptBlockText": script_block_text,
                "Path": path,
                "MessageNumber": str(message_number),
                "MessageTotal": str(message_total),
            },
            provider="Microsoft-Windows-PowerShell",
            description="PowerShell script block (EID 4104)",
        )
        self.validate(event)
        return event

    # -- schema-boundary generation --------------------------------------

    def generate_variations(
        self,
        spec: CommandSpec,
        as_4688: bool = False,
    ) -> List[TelemetryEvent]:
        """Emits one validated process-creation event per syntactic mutation of *spec*.

        In ``offline_mock`` mode only the canonical baseline rendering is emitted,
        producing a deterministic, variation-free fixture set.
        """
        self.reset_timeline()
        if self.offline_mock:
            mutations = [("baseline", spec.render())]
        else:
            mutations = self.mutator.mutate_all(spec)

        events: List[TelemetryEvent] = []
        for name, cmdline in mutations:
            image_path = spec.image_path
            parent = spec.parent_image
            # Wrapper mutations re-home the Image onto the wrapper host binary.
            if name.startswith("wrapper_"):
                wrapper_key = name.split("_", 1)[1]
                image_path, _binary = CommandLineMutator.WRAPPERS[wrapper_key]
            event = self.process_creation(
                image_path=image_path,
                command_line=cmdline,
                parent_image=parent,
                user=spec.user,
                integrity_level=spec.integrity_level,
                as_4688=as_4688,
            )
            event.fields["MutationName"] = name
            events.append(event)
        return events

    def to_sequence(self, sequence_id: str, events: List[TelemetryEvent], description: str = "") -> EventSequence:
        """Wraps a list of events into a validated :class:`EventSequence`."""
        seq = EventSequence(sequence_id=sequence_id, description=description)
        for event in events:
            self.validate(event)
            seq.add(event)
        return seq

    # -- validation -------------------------------------------------------

    def validate(self, event: TelemetryEvent) -> None:
        """Enforces schema completeness and RFC 2606 endpoint containment.

        Raises:
            TelemetrySafetyError: on schema gaps or forbidden destinations.
        """
        required = _REQUIRED_FIELDS.get(event.event_id)
        if required is None:
            raise TelemetrySafetyError(f"Unsupported Event ID {event.event_id}; no schema registered.")
        missing = required - set(event.fields.keys())
        if missing:
            raise TelemetrySafetyError(
                f"Event ID {event.event_id} is missing required schema fields: {sorted(missing)}"
            )
        assert_safe_text(" ".join(str(v) for v in event.fields.values()))


#: Minimum schema keys enforced per supported Event ID.
_REQUIRED_FIELDS: Dict[int, set] = {
    1: {"Image", "ParentImage", "CommandLine"},
    4688: {"NewProcessName", "ParentProcessName", "CommandLine"},
    7: {"Image", "ImageLoaded"},
    10: {"SourceImage", "TargetImage", "GrantedAccess"},
    11: {"Image", "TargetFilename"},
    4104: {"ScriptBlockText"},
}
