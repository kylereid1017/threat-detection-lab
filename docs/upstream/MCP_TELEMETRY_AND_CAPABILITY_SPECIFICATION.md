# RFC: Model Context Protocol Tool Execution Telemetry & Capability Specification

**Author:** Kyle Reid (`threat-detection-lab`)  
**Date:** 2026-09-06  
**Status:** Proposal prepared for upstream consideration (`modelcontextprotocol/specification`)  
**Scope:** Client-to-Server Protocol, Tool Invocation Telemetry, and Server Capability Boundaries

---

## 1. Motivation and Empirical Evidence

The Model Context Protocol (MCP) standardizes how AI applications and autonomous agents interact with local tools, data sources, and services. In the current reference implementation, MCP servers run as local child processes (spanned via `stdio` or communicating via Server-Sent Events) that execute with the ambient privileges of the calling user.

An empirical population study conducted over **2,500 active packages** across npm and PyPI (`docs/research/agent-execution-layer-population-study.md`) revealed significant operational security vulnerabilities:

| Measured Dimension | Empirical Value | 95% Wilson Binomial CI | Security Implication |
|---|---|---|---|
| **CLI Binary Privilege (`bin`)** | **58.67%** | [53.02%, 64.10%] | Packaged specifically for unvetted dynamic invocation via `npx -y` or `uvx`. |
| **Lifecycle Install Hooks** | **26.00%** | [21.36%, 31.25%] | Passive arbitrary code execution window upon dependency installation (`preinstall`, `postinstall`). |
| **Compound Name Imitations** | **3.20%** | [2.58%, 3.97%] | 95.2% of lookalikes are compound lures exploiting modular `@scope/mcp-*` conventions. |
| **OIDC Provenance Rate** | **16.55%** | [14.99%, 18.24%] | 83.45% do not use GitHub Actions OIDC / Trusted Publishing (absence of OIDC does not establish whether static PATs, 2FA, or granular tokens are used, but marks absence of cryptographic build provenance). |


### The Core Architectural Deficit
1. **Zero Telemetry Standard:** When an autonomous agent runtime (Claude Desktop, Cursor, or an autonomous loop) invokes a tool server that executes a subprocess, connects to an external host, or reads a local configuration file, the host operating system (EDR, Sysmon, auditd) observes an unassociated child process. Host security cannot distinguish an intentional agent tool invocation from command-line injection or compromised tooling.
2. **Ambient Privilege Inheritance:** An MCP server currently declares what tools it exposes to the LLM, but has no mechanism to declare what system privileges it requires from the host. A SQLite reader server inherits access to `~/.ssh/id_rsa`, `~/.aws/credentials`, and full network egress by default.
3. **Unpinned Execution Antipattern:** The prevailing documentation idiom (`npx -y @modelcontextprotocol/server-postgres`) bypasses package-lock integrity checks, pulling and executing the latest registry package dynamically.

---

## 2. Specification Proposal

### Part I: The Standardized Agent Tool-Call Telemetry Stream

MCP clients SHOULD emit a structured audit telemetry event for every tool execution request and response. The audit record MUST be recorded locally in a machine-readable format (JSON-L or local syslog/ETW channel) to allow correlation by endpoint detection and response (EDR) agents.

#### Event Schema: `mcp.tool_call`
```json
{
  "spec_version": "1.0",
  "event_type": "mcp.tool_call",
  "timestamp": "2026-09-06T00:15:30.124Z",
  "session": {
    "session_id": "sess-8f3a9e1b-4c2d",
    "agent_runtime": "claude-desktop",
    "agent_version": "1.8.2",
    "client_pid": 14208
  },
  "server": {
    "server_name": "filesystem",
    "transport": "stdio",
    "server_pid": 18452,
    "package_identity": "@modelcontextprotocol/server-filesystem@0.6.2",
    "command": "node",
    "integrity_sha512": "sha512-abc123..."
  },
  "invocation": {
    "call_id": "call-991240",
    "tool_name": "read_file",
    "argument_hashes": {
      "path": "sha256-4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
    },
    "duration_ms": 14.2,
    "status": "success",
    "output_bytes": 1042,
    "output_hash": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

#### Key Design Rationale
- **Argument & Output Hashing:** Storing cryptographic hashes of arguments and outputs by default prevents accidental logging of sensitive data (PII, credentials, proprietary source code) while still enabling forensically sound audit integrity.
- **Parent/Child PID Binding:** Binding `client_pid` to `server_pid` provides the missing link required by process-tree detection engines to correlate EDR process-creation alerts with AI agent context.

---

### Part II: Declarative Server Capability Manifest

MCP server definitions SHOULD include a declarative capability manifest. Runtimes can enforce these capabilities prior to execution or present them to users during server installation:

```json
{
  "name": "example-mcp-server",
  "version": "1.0.0",
  "capabilities": {
    "filesystem": {
      "mode": "restricted",
      "allowed_paths": ["${WORKSPACE_ROOT}/data", "${TMPDIR}"]
    },
    "network": {
      "egress_allowed": true,
      "domains": ["api.example.com"]
    },
    "environment": {
      "inherit_all": false,
      "allowlist": ["API_KEY", "DEBUG"]
    },
    "process_execution": {
      "can_spawn_child": false
    }
  }
}
```

#### Enforcement Modes
1. **Advisory Mode:** The client inspects the declared capabilities and alerts the user if a server attempts actions outside its declared scope.
2. **Containment Mode:** On platforms supporting containerization or OS sandboxing (e.g. macOS sandbox-exec, Linux bubblewrap/AppArmor, Windows AppContainer), the client executes the MCP server subprocess constrained strictly to declared capabilities.

---

### Part III: Prohibition of Unpinned Dynamic Execution Idioms

Client configuration schemas (e.g. `claude_desktop_config.json`) MUST deprecate unpinned dynamic execution flags:
1. `npx -y <pkg>` without an exact `@version` specifier is prohibited.
2. `uvx <pkg>` without `--from <pkg>==<version>` is prohibited.
3. Runtimes SHOULD enforce `--ignore-scripts` during background package resolution to neutralize the 26.0% passive lifecycle install hook attack surface.

---

## 3. Upstream Submission Readiness

This proposal does not introduce breaking changes to the core JSON-RPC 2.0 transport. It adds an operational telemetry layer and sandboxing guidelines that make MCP suitable for enterprise defense and regulated environments.
