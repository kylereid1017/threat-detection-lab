"""Cross-OS Endpoint Forensic Artifact Analyzer & Timeline Correlator.

Implements Hayabusa / Chainsaw (EVTX), RegRipper (Registry), and EZ Tools
(Prefetch / Amcache) style forensic triage rules across Windows, Linux, macOS,
and Cloud Control Planes (Microsoft 365, Azure/Entra ID, AWS, Google Workspace).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class ForensicArtifactEvent:
    """Normalized endpoint or cloud forensic artifact record."""

    timestamp_utc: str
    host_or_tenant: str
    os_platform: str  # "windows", "linux", "macos", "m365", "azure", "aws", "gworkspace"
    artifact_source: str  # e.g. "evtx_sysmon", "evtx_security", "registry_hive", "prefetch", "systemd", "launchd", "unified_audit_log"
    event_id_or_key: str
    process_or_principal: str
    command_or_value: str
    parent_or_context: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ForensicDetectionHit:
    """Single forensic triage alert emitted on an artifact event."""

    rule_id: str
    title: str
    severity: str  # "critical", "high", "medium"
    os_platform: str
    forensic_tool_equivalent: str  # e.g. "Hayabusa / Chainsaw", "RegRipper", "PECmd / AmcacheParser"
    mitre_technique: str
    evidence_summary: str
    event: ForensicArtifactEvent


@dataclass
class ForensicTimelineReport:
    """Correlated multi-artifact forensic timeline and incident summary."""

    total_events_scanned: int
    total_hits: int
    platforms_observed: list[str]
    mitre_techniques_observed: list[str]
    severity_counts: dict[str, int]
    hits: list[ForensicDetectionHit] = field(default_factory=list)


def evaluate_forensic_artifact(event: ForensicArtifactEvent) -> list[ForensicDetectionHit]:
    """Evaluate a single endpoint or cloud artifact against cross-OS forensic rules."""
    hits: list[ForensicDetectionHit] = []
    cmd_lower = event.command_or_value.lower()
    proc_lower = event.process_or_principal.lower()
    parent_lower = event.parent_or_context.lower()
    key_lower = event.event_id_or_key.lower()

    # =========================================================================
    # WINDOWS INTERNALS: EVTX (Hayabusa / Chainsaw), Registry (RegRipper), & EZ Tools
    # =========================================================================
    if event.os_platform == "windows":
        # 1. Windows Registry RunMRU ClickFix / LOLBin Execution (RegRipper equivalent)
        if "runmru" in key_lower and any(
            lol in cmd_lower for lol in ("mshta", "powershell", "cmd /c", "http://", "https://", "-enc")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-WIN-REG-001",
                    title="Windows Registry RunMRU Suspicious LOLBin / ClickFix Entry",
                    severity="critical",
                    os_platform="windows",
                    forensic_tool_equivalent="RegRipper (runmru.pl) / Registry Explorer",
                    mitre_technique="T1204.004",
                    evidence_summary=f"RunMRU key {event.event_id_or_key} recorded user-pasted cradle: {event.command_or_value}",
                    event=event,
                )
            )

        # 2. Windows Registry Run / RunOnce / Services User-Writable Persistence
        if any(k in key_lower for k in ("currentversion\\run", "currentversion\\runonce", "services\\")) and any(
            p in cmd_lower for p in ("\\appdata\\", "\\temp\\", "\\users\\public\\", "programdata\\", "regsvr32", "rundll32")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-WIN-REG-002",
                    title="Windows Registry Persistence Pointing to User-Writable Path",
                    severity="high",
                    os_platform="windows",
                    forensic_tool_equivalent="RegRipper (soft_run.pl / svc.pl) / RECmd",
                    mitre_technique="T1547.001",
                    evidence_summary=f"Persistence key {event.event_id_or_key} launches {event.command_or_value}",
                    event=event,
                )
            )

        # 3. EVTX Sysmon 10 / Security 4656 LSASS Credential Dumping (Hayabusa / Chainsaw)
        if event.event_id_or_key in ("10", "4656") and "lsass.exe" in cmd_lower and any(
            mask in cmd_lower for mask in ("0x1010", "0x1410", "0x1fffff", "0x143a")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-WIN-EVTX-001",
                    title="LSASS Memory Access with Credential-Dumping GrantedAccess Mask",
                    severity="critical",
                    os_platform="windows",
                    forensic_tool_equivalent="Hayabusa / Chainsaw (Sysmon EID 10)",
                    mitre_technique="T1003.001",
                    evidence_summary=f"{event.process_or_principal} accessed lsass.exe ({event.command_or_value})",
                    event=event,
                )
            )

        # 4. EVTX PowerShell 4104 Malicious ScriptBlock (AMSI bypass / Encoded / Reflection)
        if event.event_id_or_key == "4104" and any(
            ind in cmd_lower
            for ind in ("amsiutils", "amsiinitfailed", "frombase64string", "virtualalloc", "downloadstring")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-WIN-EVTX-002",
                    title="PowerShell EID 4104 Suspicious ScriptBlock (AMSI Bypass / In-Memory Cradle)",
                    severity="critical",
                    os_platform="windows",
                    forensic_tool_equivalent="Hayabusa / Chainsaw (PowerShell Operational EID 4104)",
                    mitre_technique="T1059.001",
                    evidence_summary=f"ScriptBlock execution captured: {event.command_or_value[:100]}",
                    event=event,
                )
            )

        # 5. EVTX System 7045 / Security 4697 Malicious Service Installation
        if event.event_id_or_key in ("7045", "4697") and any(
            ind in cmd_lower for ind in ("cmd.exe /c", "powershell", "\\temp\\", "\\appdata\\", "\\\\.\\pipe\\")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-WIN-EVTX-003",
                    title="Suspicious Windows Service Installed (Cobalt Strike / Lateral Movement)",
                    severity="critical",
                    os_platform="windows",
                    forensic_tool_equivalent="Hayabusa / Chainsaw (System EID 7045 / Security EID 4697)",
                    mitre_technique="T1543.003",
                    evidence_summary=f"Service binary path: {event.command_or_value}",
                    event=event,
                )
            )

        # 6. EZ Tools Prefetch (PECmd) / Amcache (AmcacheParser) Suspicious Execution
        if event.artifact_source in ("prefetch", "amcache", "shimcache") and any(
            ind in cmd_lower for ind in ("\\temp\\", "\\users\\public\\", "mimikatz", "rclone", "anydesk", "screenconnect")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-WIN-EZ-001",
                    title="Endpoint Execution Artifact (Prefetch / Amcache) of Intrusion or RMM Binary",
                    severity="high",
                    os_platform="windows",
                    forensic_tool_equivalent="Eric Zimmerman PECmd / AmcacheParser / AppCompatCacheParser",
                    mitre_technique="T1219",
                    evidence_summary=f"{event.artifact_source.upper()} artifact {event.event_id_or_key}: {event.command_or_value}",
                    event=event,
                )
            )

    # =========================================================================
    # LINUX INTERNALS: ld.so.preload Rootkits, systemd Persistence, memfd Fileless
    # =========================================================================
    elif event.os_platform == "linux":
        if "ld.so.preload" in key_lower or "ld_preload" in cmd_lower:
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-LIN-INT-001",
                    title="Linux Dynamic Linker Hijacking via /etc/ld.so.preload or LD_PRELOAD",
                    severity="critical",
                    os_platform="linux",
                    forensic_tool_equivalent="OSquery / Velociraptor Linux Internals Triage",
                    mitre_technique="T1574.006",
                    evidence_summary=f"Shared library preload registered: {event.command_or_value}",
                    event=event,
                )
            )
        if ("systemd" in event.artifact_source or ".service" in key_lower) and any(
            p in cmd_lower for p in ("/tmp/", "/dev/shm/", "/var/tmp/", "curl ", "wget ", "bash -c")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-LIN-INT-002",
                    title="Linux systemd Service Executing from Ephemeral Path (/tmp or /dev/shm)",
                    severity="high",
                    os_platform="linux",
                    forensic_tool_equivalent="Velociraptor Linux.Sys.Systemd / auditd",
                    mitre_technique="T1543.002",
                    evidence_summary=f"Unit {event.event_id_or_key} ExecStart={event.command_or_value}",
                    event=event,
                )
            )
        if "memfd:" in cmd_lower or "/proc/self/fd/" in cmd_lower:
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-LIN-INT-003",
                    title="Linux Fileless Anonymous Memory Execution (memfd_create)",
                    severity="critical",
                    os_platform="linux",
                    forensic_tool_equivalent="OSquery process_memory_map / Velociraptor",
                    mitre_technique="T1620",
                    evidence_summary=f"Process {proc_lower} executing from anonymous descriptor: {event.command_or_value}",
                    event=event,
                )
            )

    # =========================================================================
    # MACOS INTERNALS: LaunchAgents/LaunchDaemons, TCC.db, Keychain & JXA/osascript
    # =========================================================================
    elif event.os_platform == "macos":
        if ("launchagents" in key_lower or "launchdaemons" in key_lower) and any(
            p in cmd_lower for p in ("/tmp/", "/users/shared/", "osascript", "curl", "python", "sh -c")
        ):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-MAC-INT-001",
                    title="macOS LaunchAgent / LaunchDaemon Persistence Invoking Script or Temp Binary",
                    severity="high",
                    os_platform="macos",
                    forensic_tool_equivalent="OSquery launchd / Velociraptor MacOS.Persistence",
                    mitre_technique="T1543.004",
                    evidence_summary=f"Plist {event.event_id_or_key} ProgramArguments: {event.command_or_value}",
                    event=event,
                )
            )
        if "tcc.db" in cmd_lower or "dump-keychain" in cmd_lower or ("osascript" in proc_lower and "display dialog" in cmd_lower):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-MAC-INT-002",
                    title="macOS Keychain Credential Theft or TCC Privacy Database Manipulation",
                    severity="critical",
                    os_platform="macos",
                    forensic_tool_equivalent="OSquery macos_tcc / Unified Log Triage",
                    mitre_technique="T1555.001",
                    evidence_summary=f"{event.process_or_principal} executed {event.command_or_value}",
                    event=event,
                )
            )

    # =========================================================================
    # CLOUD & SAAS PLATFORMS: Microsoft 365, Azure/Entra ID, AWS, Google Workspace
    # =========================================================================
    elif event.os_platform in ("m365", "azure", "aws", "gworkspace"):
        if event.os_platform == "m365" and (
            "new-inboxrule" in key_lower or "set-inboxrule" in key_lower
        ) and any(ind in cmd_lower for ind in ("rss subscriptions", "deleteitem", "forwardto", "markasread")):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-CLD-M365-001",
                    title="Microsoft 365 Post-Compromise Stealth Inbox Rule Creation",
                    severity="high",
                    os_platform="m365",
                    forensic_tool_equivalent="Microsoft 365 Unified Audit Log / KQL CloudAppEvents",
                    mitre_technique="T1564.008",
                    evidence_summary=f"Principal {event.process_or_principal} configured stealth rule: {event.command_or_value}",
                    event=event,
                )
            )
        if event.os_platform in ("azure", "gworkspace") and (
            "consent to application" in key_lower or "oauth_token_grant" in key_lower
        ) and any(scope in cmd_lower for scope in ("mail.readwrite", "directory.readwrite.all", "gmail.modify", "admin.directory")):
            hits.append(
                ForensicDetectionHit(
                    rule_id="FOR-CLD-IAM-001",
                    title="Cloud Identity Illicit OAuth Application Consent (High-Privilege Mail/Directory Scope)",
                    severity="critical",
                    os_platform=event.os_platform,
                    forensic_tool_equivalent="Entra ID AuditLogs / Google Workspace Token Audit",
                    mitre_technique="T1528",
                    evidence_summary=f"OAuth grant by {event.process_or_principal}: {event.command_or_value}",
                    event=event,
                )
            )

    return hits


def correlate_forensic_timeline(
    events: Iterable[ForensicArtifactEvent],
) -> ForensicTimelineReport:
    """Run all forensic artifact rules across an event stream and produce a correlated timeline."""
    event_list = sorted(events, key=lambda e: e.timestamp_utc)
    all_hits: list[ForensicDetectionHit] = []
    platforms: set[str] = set()
    techniques: set[str] = set()
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0}

    for ev in event_list:
        platforms.add(ev.os_platform)
        ev_hits = evaluate_forensic_artifact(ev)
        for h in ev_hits:
            all_hits.append(h)
            techniques.add(h.mitre_technique)
            sev_counts[h.severity] = sev_counts.get(h.severity, 0) + 1

    return ForensicTimelineReport(
        total_events_scanned=len(event_list),
        total_hits=len(all_hits),
        platforms_observed=sorted(platforms),
        mitre_techniques_observed=sorted(techniques),
        severity_counts=sev_counts,
        hits=all_hits,
    )
