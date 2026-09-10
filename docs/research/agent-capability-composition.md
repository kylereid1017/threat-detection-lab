# Capability composition in agent toolchains

Measuring how often real agent configurations assemble an exfiltration chain out of individually
ordinary tools.

Interactive analyzer: `agent-capability-composition.html`
Machine-readable results: `../detections/evaluation-agent-composition.json`
Taxonomy verification: `../detections/evaluation-capability-taxonomy.json`

## Credit and prior art, first

**The framing is not mine.** Simon Willison's "lethal trifecta" holds that an agent becomes
dangerous when three properties are present together: access to private data, exposure to content
an attacker can plant, and the ability to communicate outward. Any one alone is ordinary. All three
in one agent is an exfiltration path that needs no exploit and no malicious code. He named Model
Context Protocol tooling directly in the original post.

Ecosystem-scale security measurement of agent tool servers also already exists. Hasan et al.
studied security and maintainability across 1,899 servers. MCPTox benchmarked tool poisoning
against live servers. Huang et al. audited over-privileged tool capabilities across file, network,
and execution axes, which is the closest work to this. MCPZoo measured scanner reliability across
tens of thousands of servers and found most scanner alerts are false.

What none of them measure is capability **co-occurrence across an installed set**. That is the only
thing claimed as new here.

## The question

A technique count is not a risk measure, and neither is a package audit. Consider three servers: one
reads files, one fetches web pages, one posts to an API. Each is ordinary. Each is correctly
described. Each passes any per-package review that exists.

Install all three into one agent and the assembly can read private data, ingest text an attacker
planted, and send the result outward. Nothing is wrong with any package, so nothing flags it.

**The hazard is a property of the installation, not of any package in it.** That is testable, and
this measures it.

## Method

Agent configurations published in public repositories were collected by code search, each server
entry resolved to the package it runs, and capabilities derived statically. Nothing was executed and
no package payload was downloaded.

| Stage | Count |
|---|---|
| Configuration files retrieved | 1,387 |
| Files containing server entries | 1,275 |
| Unique server sets after deduplication | 336 |
| Duplicate server sets collapsed | 178 |
| Distinct packages referenced | 380 |
| Packages resolving to an npm manifest | 205 |

Configurations were deduplicated by their resolved server set, so a template copied into many forks
counts once. Without that the corpus would measure fork popularity rather than configuration
practice.

Capabilities come from three evidence sources: the package name and description, its declared
dependencies, and the credentials the operator wired into it in the configuration. That last source
matters more than it sounds. Agent servers reach services through the runtime's built-in HTTP client
and touch files through the standard library, so a Slack server's dependency set is the protocol SDK
and nothing else. The credential in the configuration is often the only static evidence that exists.

## The taxonomy is verified, and it is not very accurate

Against 23 independently labelled servers, labelled from published documentation before the taxonomy
was run against them:

| Evidence admitted | Precision | Recall |
|---|---|---|
| All sources | 0.733 | 0.532 |
| Dependencies and wiring only | 0.625 | 0.323 |

Two things worth stating plainly.

**The original design was wrong.** It assumed declared dependencies were the strongest evidence and
defaulted to them. Measured, admitting the package's own description improved precision *and* recall
together. Agent servers are thin protocol wrappers whose dependency sets say nothing about what they
are for, while their descriptions say it accurately. The default moved to admit all evidence. The
**Recall of 0.53 means roughly half of real capabilities are missed**, which biases downward; however, **precision of 0.73 means roughly a quarter of assigned capabilities are unverified**, which biases upward. Because these two measurement error modes pull in opposite directions, these figures do not represent strict lower bounds, but rather empirical estimates of potential capability co-occurrence across real public configurations. Neither is good enough to make a claim about any individual package, and both are stated wherever a number appears.

## Results

| Measurement | Count | Share |
|---|---|---|
| Configurations analyzed | 336 | |
| Chain closed | 80 | 23.8% |
| Closed by a single package | 54 | 16.1% |
| **Closed only by composition** | **26** | **7.7%** |

**Of the configurations where a chain closes, roughly a third close only because of how the tools
combine.** No single package in those 26 closes the chain alone, so no per-package review, registry
scan, or maintainer audit would surface them. That is the finding.

**Every composed closure needed exactly two packages.** Not three, in any case measured. The chain
does not require an elaborate assembly; two ordinary tools are enough, because most servers already
supply two of the three legs and only one more is needed.

The packages appearing most often as critical, meaning their removal breaks every closure in that
configuration:

| Package | Configurations where critical |
|---|---|
| `@modelcontextprotocol/server-github` | 13 |
| `@modelcontextprotocol/server-filesystem` | 12 |
| `shadcn` | 6 |
| `@upstash/context7-mcp` | 4 |
| `@executeautomation/playwright-mcp-server` | 3 |

**None of these packages is malicious, and none is doing anything wrong.** They appear here because
they are widely installed and because they supply a leg that nothing else in those configurations
supplies. Being critical is a structural position, not a defect. The two official servers at the top
of the list are there because they are the two most useful servers in the ecosystem.

## Marginal closure risk and ecosystem proximity

A static audit asks: "is package X safe?" That question fails because almost every server is individually benign. The systemic question is:
**"What is the marginal composition risk of adding server X, given what developers already have installed?"**

Measuring the 256 open configurations across the deduplicated population reveals how close the ecosystem sits to the precipice.

### 1. Distance-to-closure distribution & recall sensitivity band

Distance $d \in \{0, 1, 2, 3\}$ measures how many capability legs an installation lacks before closing an exfiltration chain:

| Distance | State | Open Configurations ($N=256$) | Share of Open | Total Configurations ($N=336$) | Share of Total |
|---|---|---|---|---|---|
| $d=0$ | Chain Closed | — | — | 80 | 23.8% |
| $d=1$ | **Marginal Precipice** | **68** | **26.6%** | **68** | **20.2%** |
| $d=2$ | Intermediate | 44 | 17.2% | 44 | 13.1% |
| $d=3$ | Unconfigured / Benign Base | 144 | 56.2% | 144 | 42.9% |

**More than a quarter of all open configurations (26.6% of open, 20.2% of total) sit exactly one capability leg short of a complete exfiltration chain.** They require no attacker infrastructure, no exploit, and no malware. They are one routine tool addition away from full closure.

**Recall of 0.53 biases distance toward openness in a known direction.** If roughly half of real capabilities are missed by static derivation, configurations measured as one capability leg short may already be closed in production. The distance distribution is therefore biased toward openness, meaning the 26.6% figure is an upper bound on distance (i.e. the true distance is smaller, not larger).

To test sensitivity to evidence strictness, the distance distribution was evaluated across all three evidence tiers:

| Evidence Tier | Evidence Admitted | Closed ($d=0$) | Distance 1 (Precipice) | Distance 2 | Distance 3 |
|---|---|---|---|---|---|
| **Tier 1** | **All Evidence** (Declared Text + Deps + Wiring) | **80 (23.8%)** | **68 (26.6% open, 20.2% total)** | 44 (17.2%) | 144 (56.2%) |
| **Tier 2** | **Manifest Structure** (Deps + Configured Wiring) | 74 (22.0%) | 56 (21.4% open, 16.7% total) | 35 (13.4%) | 171 (65.3%) |
| **Tier 3** | **Declared Dependencies Only** | 74 (22.0%) | 54 (20.6% open, 16.1% total) | 32 (12.2%) | 176 (67.2%) |

Across all three evidence thresholds, 20.6% to 26.6% of open configurations sit at distance 1.

### 2. Missing legs at the precipice ($d=1$, $n=68$)

Examining the 68 configurations that sit at distance 1 reveals which capability acts as the final catalyst:

| Missing Leg | Count | Share of $d=1$ | Share of Open ($N=256$) | Share of Total ($N=336$) | What is already present |
|---|---|---|---|---|---|
| **Private Data** | **42** | **61.8%** | **16.4%** | **12.5%** | **Untrusted Ingress + Exfiltration** |
| Exfiltration | 15 | 22.1% | 5.9% | 4.5% | Private Data + Untrusted Ingress |
| Untrusted Ingress | 11 | 16.2% | 4.3% | 3.3% | Private Data + Exfiltration |

**For 61.8% of configurations at the precipice (16.4% of all open configurations), untrusted ingress and exfiltration are already active.** These developers have already connected web fetching or browser automation alongside an outbound communication channel. Introducing a single internal database reader or filesystem server—such as `@modelcontextprotocol/server-filesystem`—instantly completes the lethal trifecta across all 42 configurations.

### 3. Ranked marginal closure contributions: unweighted vs. co-installation grounded

Simulating the addition of candidate package X across every open configuration that lacks it answers the counterfactual question. However, evaluating package X across *every* open configuration assumes **uniform mixing**—treating a cloud deployment server as equally plausible in a design workstation as a filesystem tool.

To correct for this, the counterfactual is joined directly with the empirical co-installation graph. The unweighted count represents the theoretical upper bound, while the co-installation grounded count restricts flips to configurations containing at least one tool historically observed co-installed with package X (weighted by Jaccard similarity):

| Package | Legs Supplied | Closes Alone? | Composed Flips (Unweighted Upper Bound) | Grounded Flips (Co-Installed Reality) | Max Pair Jaccard |
|---|---|---|---|---|---|
| `@azure-devops/mcp` | `exfiltration`, `private_data` | No | 67 (26.2% open, 19.9% total) | 10 (3.9% open) | 0.20 |
| `@modelcontextprotocol/server-slack` | `exfiltration`, `private_data` | No | 67 (26.2% open, 19.9% total) | 9 (3.5% open) | 0.23 |
| `@fxflow/mcp-server` | `exfiltration`, `private_data` | No | 67 (26.2% open, 19.9% total) | 8 (3.1% open) | 0.20 |
| `@upstash/context7-mcp` | `untrusted_ingress`, `exfiltration` | No | 57 (22.3% open, 17.0% total) | **25 (9.8% open)** | **0.39** |
| `@modelcontextprotocol/server-filesystem` | `private_data` | No | 42 (16.4% open, 12.5% total) | **27 (10.5% open)** | **0.46** |
| `@azure/mcp` | `exfiltration`, `private_data` | No | 67 (26.2% open, 19.9% total) | **0 (0.0% open)** | 0.00 |

This comparison exposes the uniform-mixing distortion:
- Packages like `@azure/mcp` show 67 unweighted flips under uniform mixing, but **0 grounded flips** because they are never co-installed with open developer configurations in reality.
- Conversely, `@modelcontextprotocol/server-filesystem` (27 grounded flips, Jaccard 0.46) and `@upstash/context7-mcp` (25 grounded flips, Jaccard 0.39) have high co-installation affinity and represent the true empirical closure catalysts.

### 4. Co-installation network, calibrated threshold, and template prevalence

For a population of 336 configurations, a support threshold of 2 captures transient noise. Raising the threshold to `min_support >= 3` isolates genuine architectural patterns:

- **Calibrated Network Topology ($\text{support} \ge 3$):** 35 edges connecting 18 distinct packages into a single connected component (`component_size_distribution: [18]`), with 362 isolated singletons.
- **Functional Community (Developer Core Workstation, 18 packages):**
  Centred on filesystem access (`server-filesystem`), persistent memory (`server-memory`), workflow reasoning (`server-sequential-thinking`), source control (`server-github`), web fetching (`@upstash/context7-mcp`), and database querying (`server-postgres`). This workstation core is structurally positioned directly at the distance-1 precipice.
- **Top Co-Installed Pairs:**
  - `@modelcontextprotocol/server-filesystem` + `@modelcontextprotocol/server-memory` (co-occurred 11 times)
  - `@modelcontextprotocol/server-filesystem` + `@modelcontextprotocol/server-sequential-thinking` (co-occurred 10 times)
  - `@modelcontextprotocol/server-filesystem` + `@modelcontextprotocol/server-github` (co-occurred 9 times)
  - `@modelcontextprotocol/server-filesystem` + `@upstash/context7-mcp` (co-occurred 7 times)
- **Template Prevalence Signal:**
  Of 1,387 retrieved files and 1,275 valid server configurations, 178 duplicate configuration sets were identified and collapsed (a 13.96% template duplicate rate). Using the deduplicated 336 baseline prevents popular repository template forks from artificially dominating co-installation edge weights while preserving the template propagation signal as an independent metric.

## What a closed chain means

It means the assembly could carry data outward if content it ingests turns hostile. It is not a
claim that exploitation occurred, that any maintainer did anything wrong, or that any package is
malicious.

That distinction is not decoration. The documented incidents in this space show both shapes. The
Cyata chain against the git and filesystem servers required *both* servers together, which is direct
evidence for the composition thesis. The GitHub server case documented by Invariant Labs was a
single legitimate unmodified server whose three legs were all reachable at once. Neither involved a
malicious package.

## Limitations

- **The sample is biased against the finding.** Configurations published to public repositories skew
  toward single-server example configs in server repositories. A real developer's working config
  usually has more servers than an example does, so the composed rate in practice is probably higher
  than 7.7%.
- **761 configurations were dropped** because no server entry resolved to a registry package. Those
  use direct interpreter invocation or remote transports. Whether they compose differently is
  unmeasured.
- **175 of 380 packages had no npm manifest** and were scored from name and wiring alone.
- **Static analysis cannot see runtime behavior.** A capability implemented with the standard
  library, reached by shelling out, or loaded at runtime is invisible here.
- **The three-leg model is coarse.** It does not distinguish a server that reads one scoped directory
  from one that reads a whole home directory, and it treats all outbound channels as equivalent when
  a public gist and an internal API are very different.
- **Ingress reachability is not modeled.** Content an anonymous internet user can plant is a
  different exposure from content only a colleague can plant, and this treats them the same.

## What would improve this most

Ingress reachability tiers, because they are the difference between a chain an attacker can reach
and one they cannot. After that, tool-level rather than server-level capability resolution, which
would need the protocol's own tool declarations rather than package metadata.
