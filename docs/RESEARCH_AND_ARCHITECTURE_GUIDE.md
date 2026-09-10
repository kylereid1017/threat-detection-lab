# Research, Architecture, and Learning Guide: Threat Detection Lab

This guide explains the foundational concepts, security hypotheses, engineering architectures, and empirical proofs developed in the **Threat Detection Lab**.

It is written for developers, security researchers, and engineers seeking to understand:
1. **The Core Problem:** Why autonomous AI agents and local tool protocols (MCP) break traditional security models.
2. **The Security Hypotheses:** What claims the project tests and what it empirically proves.
3. **The Subsystem Architectures:** How the capability graph, adversarial swarm, detection engine, and CTI pipeline operate under the hood.
4. **The Empirical Methodology:** How we measure risk, calibrate claims, and verify defensive controls using real-world data.

---

## 1. The Big Picture: Why Traditional Security Fails Against AI Agents

### 1.1 The Architectural Shift
In late 2024 and through 2026, software development underwent an inflection point: the transition from conversational AI (chatbots) to **action-oriented autonomous AI agents**. 

To make Large Language Models (LLMs) useful, developers connect them to tools using standardized protocols, predominantly Anthropic's **Model Context Protocol (MCP)**. Through commands such as `npx -y @modelcontextprotocol/server-filesystem` or `uvx mcp-server-git`, agents are given direct access to:
- Local filesystems (reading code, configurations, and documents)
- Internal databases (PostgreSQL, SQLite)
- Enterprise collaboration platforms (Slack, Discord, GitHub, Jira)
- Web browsers and web fetchers (Puppeteer, Brave Search, Fetch)

### 1.2 The Failure of Traditional Controls
Traditional enterprise security operates on three assumptions that **collapse** in the presence of autonomous agents:

| Traditional Assumption | Why It Collapses in the Agent Execution Tier |
|---|---|
| **Malware has a malicious binary payload** | Agent tools are ordinary Node.js, Python, or Go programs. They contain no shellcode, buffer overflows, or compiled malware. |
| **Attacks exploit memory or code vulnerabilities** | Compromise occurs through **natural language prompt injection**. An untrusted webpage or email tells the model to read a file and send it out; the agent executes this via its legitimate API. |
| **Vulnerabilities exist within a single package** | Individual packages are benign. A web-fetcher is benign; a Slack bot is benign; a filesystem tool is benign. Standard vulnerability scanners (Dependabot, Snyk, npm audit) report **0 vulnerabilities**. |

**The fundamental insight:** Risk in the AI agent execution layer is **compositional**. Security cannot be evaluated by inspecting tools in isolation; it must be evaluated across the **entire interconnected set of capabilities** granted to an agent.

---

## 2. Core Security Hypotheses: What We Are Proving

The laboratory tests and verifies five central scientific hypotheses:

### Hypothesis 1: The "Lethal Trifecta" (Compositional Exfiltration)
*Framing credited to Simon Willison; formalized and measured empirically in this laboratory.*

> **Hypothesis:** An autonomous data exfiltration pathway forms when an agent possesses three specific capability legs simultaneously:
> 1. **Private Data Access:** Ability to read local files, databases, source code, or credentials.
> 2. **Untrusted Content Ingress:** Ability to ingest unvetted data from the outside world (web search, browser automation, email, issue trackers).
> 3. **Outbound Exfiltration:** Ability to transmit data to an external network destination (HTTP POST, webhooks, message sending, remote repository pushes).

```
                 THE LETHAL TRIFECTA
                 
               [ Untrusted Ingress ]
             (Web Fetch, Scraping, Email)
                         /   \
          Prompt        /     \   Ingests
        Injection      /       \  Unvetted Text
                      v         v
             [ AI Agent Reasoning ]
                      |         |
          Instructs   |         | Exfiltrates
          Local Read  |         | Secrets Outward
                      v         v
       [ Private Data ] ------> [ Exfiltration ]
     (Filesystem, DB, Env)    (HTTP POST, Webhook, Slack)
```

**What We Proved:**
- Analyzed **1,387 real-world configurations** mined from public repositories, deduplicated to **336 unique agent configurations**.
- **80 of 336 configurations (23.8%)** close the lethal trifecta.
- **26 of those 80 configurations close ONLY by composition.** No individual package closes the trifecta alone. Roughly **one-third of all active exfiltration hazards are completely invisible to per-package audits**.
- Every single composed closure required **exactly two packages**, proving that lethal chains do not require elaborate multi-tool assemblies.

---

### Hypothesis 2: The Marginal Precipice ($d=1$) & Co-Installation Reality
> **Hypothesis:** The majority of open (uncompromised) agents sit only one capability leg away from full exfiltration, and a single routine tool addition acts as the operational catalyst.

To measure this, we developed the **Distance-to-Closure ($d$)** metric:
- $d=0$: Lethal trifecta is closed (all 3 legs present).
- $d=1$: Two legs present; exactly **one capability leg short** of complete closure.
- $d=2$: One leg present; two legs short.
- $d=3$: Benign base; zero legs present.

**What We Proved:**
1. **The Precipice:** Among open configurations ($N=256$), **26.6% (68 configurations)** sit at distance $d=1$.
2. **The Catalyst:** For **61.8% of configurations at the precipice (42 configurations)**, untrusted ingress and exfiltration are *already running*. Adding a single benign file reader (e.g. `@modelcontextprotocol/server-filesystem`) immediately flips all 42 configurations to closed.
3. **Uniform Mixing Fallacy vs. Co-Installation Grounding:** Naive combinatorial security models assume any tool can be installed with any other (uniform mixing). We proved this vastly distorts risk:
   - `@azure/mcp` yields 67 counterfactual flips under uniform mixing, but **0 grounded flips** in reality (it is never installed alongside open developer configs).
   - `@modelcontextprotocol/server-filesystem` induces **27 grounded flips** (Jaccard affinity 0.46), proving it is the true empirical catalyst of the ecosystem.

---

### Hypothesis 3: AI Supply Chain Anatomy & Compound Typosquatting
> **Hypothesis:** Adversaries targeting the AI developer tier exploit modular scoped package naming (`@scope/package`) rather than traditional character misspellings, and heavily favor Python (PyPI) over JavaScript (npm).

**What We Proved:**
- Triaged the OpenSSF corpus of **232,729 confirmed-malicious package records**.
- **Ecosystem Imbalance:** AI-toolchain imitation is **~8x more concentrated in PyPI (3.052%) than npm (0.384%)**. Defense of AI researchers must prioritize Python registry monitoring.
- **Compound Lures:** Simple single-character typosquats represent only 0.16% of candidate imitations. **95.2% are compound modular lures** (e.g., `@prefix/modelcontextprotocol-sdk`, `@lure/openai-*-mcp`), actively mimicking official sub-packages.

---

### Hypothesis 4: Detection Fragility & Telemetry Prerequisites
> **Hypothesis:** Process-creation command-line detections are fragile and brittle; true resilience requires control-plane telemetry (CloudTrail, Kubernetes audit logs) and multi-event temporal correlation.

**What We Proved:**
- Built `tools/brittleness/` to benchmark 3,144 public SigmaHQ rules: **189 of 192 fragile rules read process creation**, and 33.5% fail to fire without Windows command-line auditing (which is disabled by default).
- For cloud AI environments, an adversary invoking an AWS SDK leaves **zero process command lines**. We implemented control-plane rules (`rules/sigma/cloud/`) reading AWS CloudTrail S3 Data Events and Kubernetes audit logs to detect node role theft and model weight exfiltration (`*.safetensors`) directly where the telemetry occurs.

---

### Hypothesis 5: Adversarial Boundary Mapping (The Swarm)
> **Hypothesis:** Detection rules cannot be certified by static test fixtures alone; autonomous mutation along syntactic, LolBin, and structural axes is required to map the exact boundary where a rule breaks.

**What We Proved:**
- Built a 5-agent closed loop (`tools/swarm/`) that sparred rules across 8,000+ autonomous probe iterations.
- Established the empirical **resilience equilibrium** of production Sigma and YARA rules under continuous multi-axis attack variations, proving that compensating secondary controls (correlation, audit policies) are required when primary process detection is evaded.

---

## 3. Subsystem Architecture & How It Works Under the Hood

```
                               THREAT DETECTION LAB
                               
   +--------------------------------------------------------------------------+
   |                     1. AGENT EXECUTION TIER                              |
   |  tools/agent_graph/                                                      |
   |    - capabilities.py      : Evidence-based capability derivation          |
   |    - composition.py       : Minimal closure graph & critical packages    |
   |    - marginal.py          : Distance-to-closure & co-installation graph  |
   |    - exposure_review.py   : Flagship "What changes if I add this tool?"  |
   |    - export_artifact.py   : Client-side HTML/SVG interactive visualizer  |
   |  tools/agent_audit.py     : Zero-dependency local config scanner         |
   |  tools/agent_sandbox/     : OS-native host confinement (bwrap/Seatbelt)  |
   +--------------------------------------------------------------------------+
                                      |
                                      v
   +--------------------------------------------------------------------------+
   |                     2. DETECTION & BENCHMARK TIER                        |
   |  rules/sigma/ & rules/yara/ : Production detection rules                 |
   |  rules/sigma/cloud/         : CloudTrail & Kubernetes audit rules        |
   |  rules/sigma/correlation/   : Multi-event temporal correlation rules     |
   |  tools/brittleness/         : Sigma dependency & fragility benchmark     |
   |  tools/telemetry_coverage.py: ATT&CK layer-to-telemetry mapper           |
   +--------------------------------------------------------------------------+
                                      |
                                      v
   +--------------------------------------------------------------------------+
   |                     3. ADVERSARIAL SWARM TIER                            |
   |  tools/swarm/                                                            |
   |    - graph_engine.py      : Multi-campaign DAG intrusion state machine   |
   |    - craftsmen/           : Specialized adversarial attack mutators      |
   |    - critic.py            : Pre-flight safety barrier (no live payload)  |
   |    - evaluator.py         : Multi-dialect Sigma engine & time-windows    |
   |    - noise_floor.py       : Enterprise background telemetry (2,500+ evts)|
   +--------------------------------------------------------------------------+
                                      |
                                      v
   +--------------------------------------------------------------------------+
   |                     4. CTI COLLECTION & ENRICHMENT TIER                  |
   |  tools/cti/                                                              |
   |    - sources.py           : CT log streamer, registry & URL normalizer   |
   |    - protected_names.py   : Inventory-derived typosquatting engine       |
   |    - relevance.py         : Frontier AI lab threat model relevance score |
   |    - emit.py              : STIX 2.1 exporter & candidate Sigma emitter  |
   +--------------------------------------------------------------------------+
```

---

### Subsystem A: The Agent Capability Graph & Exposure Review

#### 1. Capability Taxonomy (`capabilities.py`)
Maps packages, dependency trees, and configured environment variables to capabilities, stratified across three evidence tiers:
- **Tier 1 (Declared Text):** Package names, descriptions, and keywords. (e.g. description contains "file system" $\rightarrow$ `fs_read`).
- **Tier 2 (Manifest Structure):** Entrypoints (`bin`), lifecycle hooks (`postinstall`), engine constraints.
- **Tier 3 (Declared Dependencies & Wiring):** Explicit package dependencies (e.g. `axios` $\rightarrow$ `net_egress`) and operator-configured credentials (e.g. `GITHUB_TOKEN` $\rightarrow$ `repo_read`, `repo_write`, `net_egress`).

Each capability maps to exactly one of the three trifecta legs:
- **`private_data`**: `fs_read`, `credential_read`, `database_read`, `repo_read`, `comms_read`, `cloud_read`.
- **`untrusted_ingress`**: `web_fetch`, `search_results`, `browser_automation`, `issue_tracker`, `inbound_messages`, `document_parse`.
- **`exfiltration`**: `net_egress`, `remote_write`, `message_send`, `repo_write`, `fs_write`.

#### 2. Minimal Closure Engine (`composition.py`)
Computes whether an installation closes the trifecta:
1. Calculates the power set of packages.
2. Identifies **inclusion-minimal closures**: subsets of packages that satisfy all 3 legs where removing any single package breaks closure.
3. Identifies **critical packages**: packages whose removal breaks *every* closure path in the agent.

#### 3. Flagship Workflow: Agent Exposure Review (`exposure_review.py`)
Answers the operator's primary question: **"What changes if I add this tool to my current agent?"**

When run:
```powershell
python -m tools.agent_graph.exposure_review --tool @modelcontextprotocol/server-filesystem --args /
```
The engine executes a 6-step analytical pipeline:
1. **Load Configuration:** Parses existing Claude Desktop / Cursor / custom config. Unparsed or unsupported runners are flagged explicitly.
2. **Baseline State:** Computes baseline distance to closure ($d$) and missing legs.
3. **Candidate Synthesis:** Evaluates candidate tool capabilities, including argument-level filesystem scopes (`/` vs `./workspace`).
4. **Delta Assessment:** Computes whether closure flipped (`baseline_closed == False` and `after_closed == True`).
5. **Mitigation Engine:** Proposes concrete architectural mitigations:
   - *Directory Path Scoping:* Restricting root `/` to `./workspace`.
   - *Dual-Profile Separation:* Splitting tools into an *Ingestion Profile* (web tools, no private data) and an *Analysis Profile* (filesystem/DB, no network egress).
   - *Version Pinning:* Pinning exact cryptographic hashes and passing `--ignore-scripts`.
6. **Mitigation Recheck:** Re-runs the composition analyzer against the mitigated state, proving that residual active exfiltration paths drop to zero.

---

### Subsystem B: Detection Engineering & Cloud AI Defense

The detection suite protects the full spectrum of developer and AI infrastructure:

1. **Active-Content SVG Attachments (YARA):**
   - *Target:* Phishing attachments using SVG XML `<script>` or event handlers to trigger browser redirects.
   - *Validation:* 0 false positives on 2,079 benign Bootstrap icons.
2. **Malicious Package Lifecycle Hooks (YARA):**
   - *Target:* Inbound `package.json` and `setup.py` manifests executing encoded download cradles during `preinstall` or `postinstall` (modeling DPRK Famous Chollima campaigns).
   - *Validation:* 0 false positives across 1,755 real benign npm manifests.
3. **Explorer ClickFix Execution (Sigma):**
   - *Target:* Social-engineering lures directing users to press `Win + R` and paste obfuscated PowerShell / MSHTA downloaders into the Windows Run dialog.
4. **macOS Developer Credential Theft (Sigma):**
   - *Target:* Developer script interpreters (`node`, `python`, `bash`) accessing `~/.aws/credentials`, `~/.ssh/id_rsa`, or Chrome cookie databases.
5. **Cloud AI Cluster Defense (Sigma & CloudTrail):**
   - *Target:* Privileged container breakout primitives (`nsenter`), EC2 IMDSv2 session token acquisition for worker node IAM roles, and S3 multipart model weight exfiltration (`*.safetensors`).
   - *Control-Plane Layer:* CloudTrail S3 Data Event audit rules detecting object access by non-pipeline IAM roles.

---

### Subsystem C: The Adversarial Swarm Intelligence Engine

The Swarm is a multi-agent testing harness that evaluates rule resilience through closed-loop sparring:

```
                          SWARM 5-AGENT CLOSED LOOP
                          
                 +---------------------------------------+
                 |              Strategist               |
                 | (Selects technique & evasion strategy)|
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |               Craftsman               |
                 | (Mutates attack along 4 syntax axes)  |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |                Critic                 |
                 | (Safety gate: verifies no live payload)
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |               Detectors               |
                 | (Evaluates against YARA / Sigma engine)
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |           Analyst & Adapter           |
                 | (Calculates DoD, MTTD, & rule patches) |
                 +---------------------------------------+
```

- **Graph Engine (`graph_engine.py`):** Directed Acyclic Graph state machine representing intrusion stages (Initial Access $\rightarrow$ Execution $\rightarrow$ Defense Evasion $\rightarrow$ Credential Access $\rightarrow$ Exfiltration). If a primary analytic is evaded, the state machine branches to adjacent secondary compensating telemetry paths, measuring Depth-of-Defense (DoD) and Mean Time-to-Detect (MTTD).
- **Noise Floor Calibration (`noise_floor.py`):** Evaluates detection rules against 2,500+ realistic benign Windows background events (Intune, SCCM, administrative PowerShell) to mathematically verify zero false-positive rates.

---

### Subsystem D: Cyber Threat Intelligence (CTI) Pipeline

Implements Sherman Kent doctrine and ICD 203 intelligence standards to operationalize indicators into defensible detections:

- **Collectors (`sources.py`):** Normalizes Certificate Transparency (CT) logs, package publication feeds, and URL abuse feeds into a unified schema with provenance tracking.
- **Inventory-Derived Protected Names (`protected_names.py`):** 
  - *Empirical Finding:* A generic vocabulary-based typosquat scorer achieved **0% recall** on real held-out malicious packages.
  - *Solution:* Replaced with an inventory-derived mechanism that computes Damerau-Levenshtein distance and compound lure tokens against the organization's *actual internal dependency inventory*.
  - *Result:* **61.6% recall** at a 2.56% false-positive rate on unseen real malicious packages.
- **Emitters (`emit.py`):** Emits STIX 2.1 JSON bundles (with UUID identifiers and expiration timestamps), SIEM lookup tables, and candidate Sigma draft rules.

---

## 4. How We Test and Verify Everything

The lab enforces strict verification disciplines:

### 1. Test Suite & Code Coverage
- **475 unit and integration tests** executing in 8.3 seconds.
- **86% statement coverage** across all 8,094 lines of code in `tools/`.
- Every bug identified during audits is codified into an automated regression test in `tests/test_review_regressions.py`.

### 2. Zero-Payload Safety Contract
- **No live malware is ever executed.**
- **No untrusted package payloads or tarballs are ever downloaded.**
- All evaluations use metadata, manifests, public registry APIs, and synthetic inert telemetry fixtures.

### 3. Statistical Discipline & Ground Truth
- All empirical rates include **Wilson score 95% binomial confidence intervals**.
- When precision is below 1.0 (false positives exist) and recall is below 1.0 (false negatives exist), claims are explicitly framed as **potential capability co-occurrence** rather than mathematical "lower bounds."
- Real-world validation against external datasets:
  - OpenSSF `malicious-packages` (232,729 records)
  - Real benign manifests (1,755 npm packages)
  - Real benign vector assets (2,079 Bootstrap SVG icons)
  - Real agent configurations (1,387 public files $\rightarrow$ 336 unique configs)

---

## 5. Quick Reference & Core Mental Models

| Concept | Definition | Key Takeaway |
|---|---|---|
| **Lethal Trifecta** | Co-occurrence of Private Data, Untrusted Ingress, and Outbound Exfiltration. | Enables autonomous data theft without software exploits. |
| **Distance-to-Closure ($d$)** | Number of capability legs missing from full trifecta closure ($d=0, 1, 2, 3$). | 26.6% of open developer configurations sit at $d=1$. |
| **Marginal Catalyst** | A benign tool that, when added to an open agent, immediately flips it to closed. | Filesystem access is the #1 catalyst in the ecosystem. |
| **Uniform Mixing Fallacy** | Assuming all tools are equally likely to be installed together. | Naive combinatorial models vastly overstate theoretical risk; co-installation analysis isolates true risk. |
| **Modular Compound Lure** | Typosquatting via scoped package names (e.g. `@org/mcp-*`). | Represents 95.2% of agent tooling typosquats. |
| **Control-Plane Telemetry** | CloudTrail, K8s audit, and API-level logs. | Essential for detecting cloud AI threats where adversaries use cloud SDKs leaving zero command lines. |
| **Sherman Kent Doctrine** | Strict intelligence standard separating observed facts from estimative judgments. | Eliminates certainty bias and unsupported speculation in threat analysis. |

---

## 6. How to Run the Tools

```powershell
# 1. Run the entire regression test suite (475 tests):
python -m unittest discover -s tests

# 2. Measure statement code coverage across tools/ (86% coverage):
python -m coverage run --source=tools -m unittest discover -s tests
python -m coverage report

# 3. Run the Flagship Agent Exposure Review:
python -m tools.agent_graph.exposure_review --tool @modelcontextprotocol/server-filesystem --args /

# 4. Audit your local Claude Desktop configuration for security hygiene:
python -m tools.agent_audit --config "$env:APPDATA\Claude\claude_desktop_config.json"

# 5. Open the Interactive Visual Dashboards in your browser:
# - Lethal Trifecta Sandbox : docs/research/agent-capability-composition.html
# - Research Dossier        : docs/research/agent-execution-layer-dashboard.html
# - Swarm Workbench         : swarm_workbench.html
```
