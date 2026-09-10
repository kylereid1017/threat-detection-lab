"""Craftsman Agent: AI Agent Execution Tier & Alien Runtime Infostealers.

Generates synthetic permutations along:
1. Dynamic runner invocations (npx, uvx, pipx, bunx, pnpm, deno) spawned by agent hosts.
2. Argument smuggling, indirect shell staging, and flag variations (-y, --yes, dlx).
3. Cross-runtime alien executable staging (bun.exe dropped in %TEMP%, site-packages, /tmp).
4. Multi-stage correlation between unpinned tool execution and developer credential theft.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from ..models import Variant
from .base import BaseCraftsman


class AgentExecutionCraftsman(BaseCraftsman):
    """Specialized craftsman modeling attacks against the AI Agent Execution Layer."""

    def generate_variants(self, cycle: int, feedback: Optional[List[str]] = None) -> List[Variant]:
        variants: List[Variant] = []

        if cycle == 1:
            # Cycle 1: Dynamic Package Runner Variations & Argument Evasions
            # 1. Baseline: Claude Desktop spawning npx with -y
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="dynamic_runner",
                    mutation_name="proc_agent_claude_npx_unpinned",
                    description="Claude Desktop spawning npx with unprompted execution flag -y",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Claude\Claude.exe",
                        "Image": r"C:\Program Files\nodejs\npx.cmd",
                        "CommandLine": r"npx.cmd -y @modelcontextprotocol/server-postgres",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 2. Cursor spawning uvx with --yes
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="dynamic_runner",
                    mutation_name="proc_agent_cursor_uvx_yes",
                    description="Cursor IDE host spawning Python dynamic runner uvx with --yes",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Cursor\Cursor.exe",
                        "Image": r"C:\Users\researcher\.cargo\bin\uvx.exe",
                        "CommandLine": r"uvx.exe --yes mcp-server-sqlite",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 3. Agent runtime spawning bunx with -y
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="dynamic_runner",
                    mutation_name="proc_agent_bunx_unpinned",
                    description="Agent runtime host spawning bunx with -y flag",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Program Files\AI\agent.exe",
                        "Image": r"C:\Users\researcher\.bun\bin\bunx.exe",
                        "CommandLine": r"bunx.exe -y @modelcontextprotocol/server-filesystem",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 4. Electron agent spawning pipx with --yes
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="dynamic_runner",
                    mutation_name="proc_agent_electron_pipx_yes",
                    description="Electron-based agent host spawning pipx run --yes",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Users\researcher\AppData\Local\electron\electron.exe",
                        "Image": r"C:\Python314\Scripts\pipx.exe",
                        "CommandLine": r"pipx.exe run --yes mcp-agent-tools",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 5. Evasion probe: Alternative dynamic runner Deno run
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="evasion_runner",
                    mutation_name="proc_agent_deno_dynamic_eval",
                    description="Evasion probe: Claude Desktop spawning Deno with all-permissions flag",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Claude\Claude.exe",
                        "Image": r"C:\Users\researcher\.deno\bin\deno.exe",
                        "CommandLine": r"deno.exe run -A https://deno.stage.invalid/x/mcp_server/index.ts",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 6. Evasion probe: pnpm dlx runner
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="evasion_runner",
                    mutation_name="proc_agent_pnpm_dlx",
                    description="Evasion probe: Cursor host spawning pnpm dlx without explicit -y",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Cursor\Cursor.exe",
                        "Image": r"C:\Program Files\nodejs\pnpm.cmd",
                        "CommandLine": r"pnpm.cmd dlx @modelcontextprotocol/server-git",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 7. Evasion probe: Indirect shell staging wrapper
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="evasion_staging",
                    mutation_name="proc_agent_cmd_nested_runner",
                    description="Evasion probe: Claude Desktop spawning cmd.exe to invoke dynamic package runner",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Claude\Claude.exe",
                        "Image": r"C:\Windows\System32\cmd.exe",
                        "CommandLine": r'cmd.exe /c "npx -y @modelcontextprotocol/server-postgres"',
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

        elif cycle == 2:
            # Cycle 2: Alien Runtime Bun Staging & Infostealers (MAL-2026-5318)
            # 1. Baseline: Bun in Temp directory running site-packages _index.js
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="alien_runtime",
                    mutation_name="proc_bun_temp_execution",
                    description="Bun runtime spawned from AppData Temp executing site-packages script",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Python314\python.exe",
                        "Image": r"C:\Users\researcher\AppData\Local\Temp\b\bun.exe",
                        "CommandLine": r"bun.exe run C:\Python314\Lib\site-packages\langchain_core_mcp\_index.js",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 2. Bun spawned directly inside site-packages
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="alien_runtime",
                    mutation_name="proc_bun_site_packages",
                    description="Bun binary executing directly from Python site-packages directory",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Python314\python.exe",
                        "Image": r"C:\Python314\Lib\site-packages\langchain_core_mcp\bin\bun.exe",
                        "CommandLine": r"bun.exe run _index.js",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 3. Bun execution with .bun_ran marker argument
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="alien_runtime",
                    mutation_name="proc_bun_marker_ran",
                    description="Bun execution referencing .bun_ran persistence marker",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Python314\python.exe",
                        "Image": r"C:\Users\researcher\AppData\Local\Temp\bun.exe",
                        "CommandLine": r"bun.exe run payload.js --marker .bun_ran",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 4. Linux/macOS path variant: /tmp/b/bun
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="alien_runtime",
                    mutation_name="proc_bun_tmp_linux",
                    description="Linux /tmp/b/bun executing site-packages infostealer script",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/usr/bin/python3",
                        "Image": "/tmp/b/bun",
                        "CommandLine": "bun run /usr/lib/python3/dist-packages/langchain_core_mcp/_index.js",
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

            # 5. Evasion probe: Non-temp directory staging (ProgramData)
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="evasion_path",
                    mutation_name="proc_bun_programdata_evasion",
                    description="Evasion probe: Bun staged in ProgramData executing benign-looking filename",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Python314\python.exe",
                        "Image": r"C:\ProgramData\mcp\bun.exe",
                        "CommandLine": r"bun.exe run C:\ProgramData\mcp\worker.js",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

            # 6. Evasion probe: Masqueraded binary name in Temp
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="evasion_masquerade",
                    mutation_name="proc_bun_renamed_helper",
                    description="Evasion probe: Bun executable renamed to helper.exe staged in Temp directory",
                    payload={
                        "EventID": 1,
                        "ParentImage": r"C:\Python314\python.exe",
                        "Image": r"C:\Users\researcher\AppData\Local\Temp\helper.exe",
                        "CommandLine": r"helper.exe run _index.js",
                        "User": r"CORP\researcher",
                    },
                    cycle=cycle,
                )
            )

        elif cycle == 3:
            # Cycle 3: The Cognitive-to-Host Kill Chain & Correlation Telemetry
            # 1. Unpinned tool execution followed by AWS credential access
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="kill_chain",
                    mutation_name="corr_unpinned_then_aws_creds",
                    description="Unpinned dynamic runner execution followed by reading ~/.aws/credentials",
                    payload={
                        "stage_1": {
                            "EventID": 1,
                            "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Claude\Claude.exe",
                            "Image": r"C:\Program Files\nodejs\npx.cmd",
                            "CommandLine": r"npx.cmd -y @modelcontextprotocol/server-postgres",
                            "User": r"CORP\researcher",
                        },
                        "stage_2": {
                            "EventID": 1,
                            "ParentImage": r"C:\Program Files\nodejs\node.exe",
                            "Image": r"C:\Windows\System32\cmd.exe",
                            "CommandLine": r'cmd.exe /c "type %USERPROFILE%\.aws\credentials"',
                            "User": r"CORP\researcher",
                        },
                        "delta_seconds": 12,
                    },
                    cycle=cycle,
                )
            )

            # 2. Unpinned tool execution followed by SSH key theft
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="kill_chain",
                    mutation_name="corr_unpinned_then_ssh_keys",
                    description="Cursor unpinned tool execution followed by developer SSH key access",
                    payload={
                        "stage_1": {
                            "EventID": 1,
                            "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Cursor\Cursor.exe",
                            "Image": r"C:\Users\researcher\.cargo\bin\uvx.exe",
                            "CommandLine": r"uvx.exe --yes mcp-server-git",
                            "User": r"CORP\researcher",
                        },
                        "stage_2": {
                            "EventID": 1,
                            "ParentImage": r"C:\Python314\python.exe",
                            "Image": r"C:\Windows\System32\cmd.exe",
                            "CommandLine": r'cmd.exe /c "tar -czf %TEMP%\ssh.tgz %USERPROFILE%\.ssh\id_ed25519"',
                            "User": r"CORP\researcher",
                        },
                        "delta_seconds": 24,
                    },
                    cycle=cycle,
                )
            )

            # 3. Evasion probe: Time-delayed execution defeating temporal window (>60s)
            variants.append(
                Variant(
                    id=f"agent-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="evasion_temporal",
                    mutation_name="corr_delayed_evasion",
                    description="Evasion probe: Credential theft delayed by 180 seconds exceeding correlation window",
                    payload={
                        "stage_1": {
                            "EventID": 1,
                            "ParentImage": r"C:\Users\researcher\AppData\Local\Programs\Claude\Claude.exe",
                            "Image": r"C:\Program Files\nodejs\npx.cmd",
                            "CommandLine": r"npx.cmd -y @modelcontextprotocol/server-postgres",
                            "User": r"CORP\researcher",
                        },
                        "stage_2": {
                            "EventID": 1,
                            "ParentImage": r"C:\Program Files\nodejs\node.exe",
                            "Image": r"C:\Windows\System32\cmd.exe",
                            "CommandLine": r'cmd.exe /c "type %USERPROFILE%\.aws\credentials"',
                            "User": r"CORP\researcher",
                        },
                        "delta_seconds": 180,
                    },
                    cycle=cycle,
                )
            )

        return variants
