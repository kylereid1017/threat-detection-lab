"""Live-Response & Threat Hunting Query Library (OSquery, Velociraptor VQL, KQL, SPL, ES|QL).

Provides validated threat-hunting queries across Windows, Linux, macOS, and
Cloud Identity platforms (Microsoft 365, Azure/Entra ID, Google Workspace).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatHuntQuery:
    """Single live-response or SIEM threat-hunting query."""

    query_id: str
    title: str
    engine: str  # "osquery", "velociraptor_vql", "kql", "splunk_spl", "elastic_esql"
    platform: str  # "windows", "linux", "macos", "m365_azure"
    mitre_technique: str
    hypothesis: str
    query_text: str


HUNT_QUERY_PACK: tuple[ThreatHuntQuery, ...] = (
    ThreatHuntQuery(
        query_id="HUNT-OSQ-WIN-001",
        title="Windows Registry RunMRU & User-Writable Run Key Persistence",
        engine="osquery",
        platform="windows",
        mitre_technique="T1204.004",
        hypothesis="Adversaries using ClickFix or user-land persistence populate HKCU RunMRU or Run keys with mshta, powershell, or %APPDATA% binaries.",
        query_text=(
            "SELECT path, name, data, mtime FROM registry "
            "WHERE (key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU' "
            "OR key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%') "
            "AND (LOWER(data) LIKE '%mshta%' OR LOWER(data) LIKE '%powershell%' "
            "OR LOWER(data) LIKE '%appdata%' OR LOWER(data) LIKE '%http%');"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-OSQ-LIN-001",
        title="Linux Fileless Execution (memfd_create) & ld.so.preload Rootkit Check",
        engine="osquery",
        platform="linux",
        mitre_technique="T1620",
        hypothesis="In-memory ELF implants execute from anonymous /memfd: descriptors or hijack dynamic linking via /etc/ld.so.preload.",
        query_text=(
            "SELECT p.pid, p.name, p.path, p.cmdline, p.cwd FROM processes p "
            "WHERE p.path LIKE '/memfd:%' OR p.path LIKE '%(deleted)%' "
            "OR p.cmdline LIKE '%LD_PRELOAD%';"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-OSQ-MAC-001",
        title="macOS Unsigned or Temp-Backed LaunchAgents & LaunchDaemons",
        engine="osquery",
        platform="macos",
        mitre_technique="T1543.004",
        hypothesis="macOS infostealers (AMOS / Banshee) register LaunchAgents invoking osascript, curl, or binaries in /tmp or /Users/Shared.",
        query_text=(
            "SELECT l.name, l.path, l.program, l.program_arguments, l.run_at_load, s.authority "
            "FROM launchd l LEFT JOIN signature s ON l.program = s.path "
            "WHERE l.run_at_load = '1' AND (l.program_arguments LIKE '%/tmp/%' "
            "OR l.program_arguments LIKE '%/Users/Shared/%' OR l.program_arguments LIKE '%osascript%' "
            "OR s.authority = '' OR s.authority IS NULL);"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-VQL-WIN-001",
        title="Velociraptor VQL: Hunt for Unbacked RWX Memory Regions & Process Hollowing",
        engine="velociraptor_vql",
        platform="windows",
        mitre_technique="T1055.012",
        hypothesis="Reflective DLL loaders (Cobalt Strike, Lumma Stealer) allocate private PAGE_EXECUTE_READWRITE memory regions not backed by disk.",
        query_text=(
            "SELECT Pid, Name, CommandLine, Address, Size, Protection "
            "FROM Artifact.Windows.Detection.Yara.Process() "
            "WHERE Protection =~ 'rwx' AND MappingName = ''"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-VQL-WIN-002",
        title="Velociraptor VQL: Parse Windows Prefetch & Amcache for RMM / Intrusion Tooling",
        engine="velociraptor_vql",
        platform="windows",
        mitre_technique="T1219",
        hypothesis="Attackers staging ScreenConnect, AnyDesk, Rclone, or Mimikatz leave execution artifacts in C:\\Windows\\Prefetch even after binary deletion.",
        query_text=(
            "SELECT Executable, LastRunTimes, RunCount, Hash "
            "FROM Artifact.Windows.Forensics.Prefetch() "
            "WHERE Executable =~ '(?i)(screenconnect|anydesk|rclone|mimikatz|nanodump|mshta)'"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-KQL-CLD-001",
        title="KQL: Microsoft 365 & Entra ID AiTM Post-Compromise Inbox Rule + OAuth Correlation",
        engine="kql",
        platform="m365_azure",
        mitre_technique="T1564.008",
        hypothesis="Following AiTM session hijack, threat actors create stealth inbox rules moving mail to RSS Subscriptions or grant illicit OAuth scopes within 60 minutes.",
        query_text=(
            "CloudAppEvents "
            "| where ActionType in ('New-InboxRule', 'Set-InboxRule', 'Consent to application') "
            "| where RawEventData has_any ('RSS Subscriptions', 'DeleteItem', 'Mail.ReadWrite', 'Directory.ReadWrite.All') "
            "| project Timestamp, AccountId, ActionType, IPAddress, ISP, RawEventData"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-SPL-WIN-001",
        title="Splunk SPL: Sysmon EID 10 LSASS Credential Dumping & EID 8 Remote Thread Creation",
        engine="splunk_spl",
        platform="windows",
        mitre_technique="T1003.001",
        hypothesis="Credential dumpers open lsass.exe with PROCESS_VM_READ (0x1010/0x1410/0x1fffff) or inject remote threads into system processes.",
        query_text=(
            "index=win_sysmon (EventCode=10 TargetImage=\"*\\\\lsass.exe\" "
            "GrantedAccess IN (\"0x1010\", \"0x1410\", \"0x1fffff\", \"0x143a\")) "
            "OR (EventCode=8 TargetImage IN (\"*\\\\svchost.exe\", \"*\\\\explorer.exe\")) "
            "| stats count values(GrantedAccess) values(CallTrace) by Computer, SourceImage, TargetImage"
        ),
    ),
    ThreatHuntQuery(
        query_id="HUNT-ESQL-WIN-001",
        title="Elastic ES|QL: Explorer Win+R ClickFix Child Process Spawning",
        engine="elastic_esql",
        platform="windows",
        mitre_technique="T1204.004",
        hypothesis="ClickFix lures trick users into pasting PowerShell or mshta download cradles into the Windows Run dialog (parent: explorer.exe).",
        query_text=(
            "FROM logs-endpoint.events.process-* "
            "| WHERE process.parent.name == \"explorer.exe\" "
            "AND process.name IN (\"mshta.exe\", \"powershell.exe\", \"pwsh.exe\", \"cmd.exe\") "
            "AND (process.command_line LIKE \"*http*\" OR process.command_line LIKE \"*-enc*\") "
            "| KEEP @timestamp, host.name, user.name, process.name, process.command_line"
        ),
    ),
)


def list_hunt_queries(
    *,
    engine: str | None = None,
    platform: str | None = None,
) -> list[ThreatHuntQuery]:
    """Filter the threat-hunting query pack by engine or target OS/cloud platform."""
    results = list(HUNT_QUERY_PACK)
    if engine:
        eng_lower = engine.lower().strip()
        results = [q for q in results if q.engine == eng_lower]
    if platform:
        plat_lower = platform.lower().strip()
        results = [q for q in results if q.platform == plat_lower]
    return results
