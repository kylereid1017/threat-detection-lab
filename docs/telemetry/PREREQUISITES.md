# Telemetry Prerequisites and Visibility Degradation Matrix

**Classification:** Internal Technical Architecture  
**Author:** Kyle Reid (kylereid1017), Threat Intelligence & Detection Engineering  
**Standard:** ICD 203 Analytic Rigor / MITRE D3FEND Defensive Architecture  

---

## 1. Executive Summary

A detection rule is only as defensible as the underlying telemetry pipeline that feeds it. Writing complex string-matching patterns or regular expressions inside a SIEM query without formal reasoning about channel availability, audit policies, and volume-induced sensor filtering produces brittle detection engineering.

This document establishes the authoritative **Telemetry Prerequisites and Visibility Degradation Matrix** for the detection corpus in `threat-detection-lab`. For every committed Sigma analytic, it defines:
1. The exact log channel and Event ID required.
2. The Group Policy / Windows Audit Policy configuration required for field emission.
3. The Sysmon XML configuration snippet.
4. The failure modes and operational degradation that occur when telemetry is absent, truncated, or bypassed.

---

## 2. Telemetry Prerequisites Matrix

| Analytic Rule | Log Channel | Event ID | Audit Policy Setting | Required Telemetry Fields | Degradation Failure Mode |
|---|---|---|---|---|---|
| **ClickFix Execution**<br>`proc_creation_win_explorer_clickfix_execution.yml` | `Microsoft-Windows-Sysmon/Operational` or `Security` | 1 (Sysmon)<br>4688 (Security) | `Audit Process Creation` (Success) + Group Policy `Include command line in process creation events` | `Image`, `CommandLine`, `ParentImage` | **Total Blindness (0% Recall).** Without command-line logging, all interpreter and download cradle arguments are omitted. Without `ParentImage`, Run-prompt execution cannot be distinguished from background services. |
| **Defense Evasion Tampering**<br>`proc_creation_win_defense_evasion_tampering.yml` | `Microsoft-Windows-Sysmon/Operational` or `Security` | 1 (Sysmon)<br>4688 (Security) | `Audit Process Creation` (Success) + command line auditing | `Image`, `CommandLine` | **Pre-execution Blindness.** If command line auditing is disabled, `wevtutil cl` and `Set-MpPreference` arguments are missed. Direct Windows API calls (`OpenEventLog`, `ClearEventLog`) bypass process creation entirely; requires Event ID 1102 / 104. |
| **LSASS Memory Dump**<br>`proc_creation_win_rundll32_lsass_dump.yml` | `Microsoft-Windows-Sysmon/Operational` or `Security` | 1 (Sysmon)<br>4688 (Security) | `Audit Process Creation` (Success) + command line auditing | `Image`, `CommandLine` | **Evasion via Alternate Dumpers.** Completely blind to custom, renamed, or direct API dumpers (e.g. `nanodump`, `mimikatz`, unhooked `MiniDumpWriteDump`) that do not call `comsvcs.dll` via `rundll32.exe`. Requires Sysmon EID 10 compensating control. |
| **Scheduled Task Persistence**<br>`proc_creation_win_schtasks_persistence.yml` | `Microsoft-Windows-Sysmon/Operational` or `Security` | 1 (Sysmon)<br>4688 (Security) | `Audit Process Creation` (Success) + command line auditing | `Image`, `CommandLine` | **Evasion via COM API or Direct XML.** If the task is registered directly via `ITaskService` or file-dropped into `C:\Windows\System32\Tasks`, no `schtasks.exe` process spawns. Requires TaskScheduler EID 106 or Sysmon EID 11. |
| **LSASS Process Access (Correlation)**<br>`rules/sigma/correlation/sysmon_process_access_lsass.yml` | `Microsoft-Windows-Sysmon/Operational` | 10 (ProcessAccess) | Advanced Audit: `Audit Other Object Access Events` (EID 4656/4663) or Sysmon Driver Handle Interception | `SourceImage`, `TargetImage`, `GrantedAccess` | **Disabled by Default.** Native EID 4663 generates unmanageable EPS volume. If Sysmon EID 10 is omitted from agent configurations to conserve bandwidth, kernel handle-opening is unobserved, collapsing defense-in-depth to post-execution telemetry. |
| **Script Block Download Cradle (Correlation)**<br>`rules/sigma/correlation/posh_script_block_download_cradle.yml` | `Microsoft-Windows-PowerShell/Operational` | 4104 (ScriptBlockLogging) | Group Policy: `Turn on PowerShell Script Block Logging` (Enabled) | `ScriptBlockText` | **Uncollected Volume Degradation.** Often filtered by SIEM forwarders due to log bloat. When disabled, obfuscated, encoded, or dynamically evaluated expressions (`IEX`, memory download cradles) execute invisibly. |

---

## 3. Sysmon Configuration Reference (`sysmonconfig.xml`)

To support the full analytic corpus without experiencing telemetry degradation, the endpoint sensor must deploy the following minimal filtering schema:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Event ID 1: Process Creation with Parent Lineage -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">\explorer.exe</ParentImage>
      <Image condition="end with">\powershell.exe</Image>
      <Image condition="end with">\pwsh.exe</Image>
      <Image condition="end with">\mshta.exe</Image>
      <Image condition="end with">\cmd.exe</Image>
      <Image condition="end with">\rundll32.exe</Image>
      <Image condition="end with">\schtasks.exe</Image>
      <Image condition="end with">\wevtutil.exe</Image>
    </ProcessCreate>

    <!-- Event ID 10: Process Access Targeting LSASS -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">\lsass.exe</TargetImage>
    </ProcessAccess>
    <!-- Filter noisy benign system access to LSASS to prevent log flooding -->
    <ProcessAccess onmatch="exclude">
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
      <SourceImage condition="is">C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11\MsMpEng.exe</SourceImage>
    </ProcessAccess>

    <!-- Event ID 11: File Creation for Dump Staging -->
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">.dmp</TargetFilename>
      <TargetFilename condition="end with">.dump</TargetFilename>
      <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

---

## 4. Operational Tradeoff Analysis: Process Access Auditing

### The High-Volume Dilemma
Native Windows Security Auditing provides Event ID 4663 ("An attempt was made to access an object") and 4656 ("A handle to an object was requested"). In an enterprise environment of 10,000 endpoints, enabling `Audit Other Object Access Events` on `lsass.exe` generates over **50,000,000 events per day**, primarily from security tooling, identity providers, and background RPC servers checking authentication tokens.

### Analytic Recommendation (ICD 203 Judgment)
1. **Never enable global native EID 4663 object access auditing on workstations.** It saturates SIEM network buffers and disk storage.
2. **Deploy Sysmon Event ID 10 with precise granted-access filtering.** Filtering specifically on memory-read rights (`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`) reduces event volume by 98.4% while maintaining 100% visibility into credential theft tools.
3. **Correlate with Event ID 11 (File Creation) in the SIEM layer.** A standalone Process Access event may represent benign diagnostic access; when chained within 120 seconds of an anonymous file drop in `%TEMP%`, analytic confidence shifts from Moderate to High.

