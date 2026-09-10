# AI Agent Execution Layer Detections & Defense

## Goal

Detect and prevent exploitation of the Model Context Protocol (MCP) and agent execution tier
across developer workstations and AI agent environments. Specifically:
1. Detect AI agent hosts spawning unpinned, dynamic package runners (`npx -y`, `uvx`, `pipx`, `bunx`) that bypass lockfile verification and package integrity controls.
2. Detect foreign/alien runtimes (such as the Bun JavaScript runtime) spawned from suspicious locations (temporary directories, user cache, Python `site-packages`) by compromised agent packages.
3. Correlate unpinned dynamic tool executions with immediate unauthorized credential harvesting (`.aws/credentials`, `.ssh/id_ed25519`, browser stores).
4. Provide proactive posture auditing via `tools/agent_audit.py` for Claude Desktop, Cursor, and custom agent configuration files before runtime launch.

---

## Background & Threat Model

The Model Context Protocol (MCP) establishes a client-host-server architecture where AI agent
runtimes (Claude Desktop, Cursor, Claude Code, etc.) execute local servers to expose tools, resources,
and prompts. Because these servers execute with the developer's user privileges, local tool execution
is an unmonitored attack vector:

1. **Unpinned Dynamic Execution (`npx -y`)**: Many official tutorials and third-party setups configure MCP servers using dynamic runners (`npx -y @package` or `uvx package`). Dynamic runners automatically download and execute the latest release from public registries (npm, PyPI) without lockfiles, package hashes, or subresource integrity checks. This renders the agent immediately susceptible to maintainer account takeover, typosquatting, and malicious package releases.
2. **Alien Runtime Obfuscation (Exemplar: `groq-mcp` / `MAL-2026-5321`)**: Compromised Python packages in agent ecosystems abuse auto-loading `.pth` files or setup scripts to download a standalone, single-file JavaScript runtime (`bun.exe`) into `%TEMP%` and execute an obfuscated JavaScript infostealer (`_index.js`). This executes completely outside the visibility of Python runtime scanners or package analyzers.
3. **Compound Typosquats**: Attackers publish modular names imitating legitimate agent libraries (e.g. `@prefix/modelcontextprotocol-sdk` or `modelcontextprotocol-tools`) rather than simple character permutations.

---

## Authored Detection Content

### 1. Process Creation: Unpinned Dynamic Tool Execution
- **File**: [`rules/sigma/proc_creation_agent_runtime_unpinned_tool_execution.yml`](file:///c:/Users/kyler/Projects/threat-detection-lab/rules/sigma/proc_creation_agent_runtime_unpinned_tool_execution.yml)
- **ID**: `c7b2e1f4-3d6a-4c89-9a25-8e1f0b7c4d32`
- **Logic**: Identifies agent hosts (`Claude.exe`, `Cursor.exe`, `electron.exe`, `agent.exe`) spawning dynamic runners (`npx.cmd`, `uvx.exe`, `pipx.exe`, `bunx.exe`) with unprompted execution flags (`-y`, `--yes`).
- **ATT&CK**:
  - `T1195.001` (Supply Chain Compromise: Compromise Software Dependencies and Development Tools)
  - `T1059.007` (Command and Scripting Interpreter: JavaScript)

### 2. Process Creation: Alien Runtime Bun Infostealer
- **File**: [`rules/sigma/proc_creation_agent_alien_runtime_bun_infostealer.yml`](file:///c:/Users/kyler/Projects/threat-detection-lab/rules/sigma/proc_creation_agent_alien_runtime_bun_infostealer.yml)
- **ID**: `e5a8d2c1-7b94-4f32-8a16-9c4d2e0f1b78`
- **Logic**: Detects `bun.exe` executed from temporary folders (`\Temp\`, `\AppData\Local\Temp\`, `\tmp\`) or referencing Python distribution paths (`site-packages`, `dist-packages`, `_index.js`, `.bun_ran`).
- **ATT&CK**:
  - `T1059.007` (Command and Scripting Interpreter: JavaScript)
  - `T1574.013` (Hijack Execution Flow: Python Environment Modification)
  - `T1036` (Masquerading)

### 3. Correlation Rule: Unpinned Tool Spawning Followed by Credential Access
- **File**: [`rules/sigma/correlation/correlation_agent_unpinned_tool_credential_access.yml`](file:///c:/Users/kyler/Projects/threat-detection-lab/rules/sigma/correlation/correlation_agent_unpinned_tool_credential_access.yml)
- **ID**: `f9a2c4e6-8b01-4d35-9e72-1c3f5a7d9b14`
- **Type**: Event correlation (`temporal` sequence, 60-second window)
- **Condition**: Unpinned tool execution (`agent_runtime_unpinned_tool_execution`) followed on the same host/user by developer credential access (`proc_creation_macos_dev_credential_theft` or file access to `.aws`, `.ssh`, `.gnupg`, browser state).
- **ATT&CK**:
  - `T1552.001` (Unsecured Credentials: Credentials in Files)
  - `T1539` (Steal Web Session Cookie)

---

## Defensive Engineering & Operational Auditing

### `tools/agent_audit.py`
A local configuration auditing scanner that validates agent configs against static security baselines:
1. **Unpinned Dynamic Execution Detection**: Flags commands invoking `npx -y`, `uvx`, or `pipx run` without explicit hash/version pinning.
2. **Missing Script Execution Suppression**: Warns if dynamic npm/pip commands omit `--ignore-scripts`.
3. **Protected Registry Typosquats**: Computes compound and Damerau-Levenshtein distance against known high-value namespaces (`@modelcontextprotocol`, `anthropic`, `langchain`, `llamaindex`).
4. **Known Malicious Package Hits**: Matches packages against OpenSSF confirmed-malicious database entries.
5. **Plaintext Secret Exposure**: Scans server `env` dictionaries for hardcoded API keys, bearer tokens, and private secrets.
6. **Excessive Root Scopes**: Warns if filesystem tools are mounted to root directories (`/`, `C:\`, `C:\Users\`).

### Upstream Specification: MCP Telemetry & Capabilities
- **File**: [`docs/upstream/MCP_TELEMETRY_AND_CAPABILITY_SPECIFICATION.md`](file:///c:/Users/kyler/Projects/threat-detection-lab/docs/upstream/MCP_TELEMETRY_AND_CAPABILITY_SPECIFICATION.md)
- Proposes two upstream additions to the Model Context Protocol standard:
  1. `mcp.tool_call` structured telemetry schema with execution duration, payload hashing, client session lineage, and permission provenance.
  2. Static capability manifests (`mcp-manifest.json`) declaring permissible filesystem root paths, allowed network hosts, and child execution constraints.

---

## Measured Results & Swarm Integration

The analytics were integrated into the lab's autonomous sparring swarm and evaluated against:
1. **Committed Positive Fixtures**:
   - `tests/fixtures/sigma/positive/agent_claude_npx_unpinned.json`
   - `tests/fixtures/sigma/positive/agent_alien_bun_temp_exec.json`
   - **Recall**: 1.0 (100% on owned fixtures; zero false negatives).
2. **Enterprise Noise Floor Benchmark**:
   - Evaluated against high-volume synthetic background telemetry across workstation noise profiles.
   - **False Positive Rate**: 0.00% across all 2,500 background events.
3. **MITRE ATT&CK and D3FEND Verification**:
   - Added verified mappings for `T1036` (Process Spawn Analysis, Process Analysis) and `T1574.013` (Script Execution Analysis, Dynamic Analysis).
   - Zero taxonomy defects or identifier collisions.
4. **Full Test Suite**:
   - 356 unit tests passing across all suites (`tests/test_agent_audit.py`, `tests/test_agent_population_study.py`, `tests/test_sigma_rules.py`, `tests/test_swarm.py`).

---

## Telemetry Prerequisites & Limitations

- **Process Creation Logging with Arguments**: Windows Sysmon Event ID 1 or Security Event ID 4688 with command-line argument auditing enabled (`IncludeCommandLineInProcessCreationEvents = 1`). Without argument logging, dynamic flags (`-y`) and script paths are invisible.
- **Parent Process Lineage**: Sysmon `ParentImage` required to identify agent runtime parents (`Claude.exe`, `Cursor.exe`).
- **Binary Renaming / Relocation**: If an attacker renames `bun.exe` or drops it outside common temporary/site-packages paths, file creation hashing or code signature validation is required.

---

## Reproducing

```bash
# Run unit tests
python -m unittest tests/test_agent_audit.py tests/test_agent_population_study.py tests/test_sigma_rules.py tests/test_swarm.py -v

# Audit sample configuration
python tools/agent_audit.py --config corpus/agent/sample_claude_desktop_config.json --format text

# Run enterprise noise floor benchmark
python -c "from tools.swarm.noise_floor import run_benchmark; print(run_benchmark(benign_count=200).to_markdown())"
```
