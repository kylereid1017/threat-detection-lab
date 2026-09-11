# Roadmap

> **Retraction note (2026-09-10):** aggregate probe-count and resilience figures cited in completed items below (764 probes / 71.2%, 8,033 probes / 71.4%, ~1.96M probes / 98.3%) were withdrawn as mis-derived — their denominators mixed benign noise-floor events with attack probes. See `docs/cables/ERRATA-2026-09-10.md`; the rebuilt observation-record pipeline and regenerated figures are in `CABLE-2026-STRAT-004-empirical-swarm-synthesis.md`.

## Active Governance & Status Matrix

| Product Tier / Capability | Lifecycle Status | Verified Evidence & Test Coverage | Operational Constraints & Boundary Disclaimers |
|---|---|---|---|
| **Tier 1: Core Detection & Swarm Sparring** | **Verified** | 5 production Sigma/YARA rules, 497 unit tests passing, `tools/swarm/` closed-loop multi-campaign DAG engine with zero false positives on benign corpora. | Closed-loop simulation measures defensive rule boundaries; does not represent live adversary operational campaigns. |
| **Tier 2: CTI Collection & Protected Names Engine** | **Verified** | `tools/cti/` pipeline (96–99% coverage), Certificate Transparency live acquisition, inventory-derived typosquat detection evaluated on 232k OpenSSF records (61.6% recall on covered names, 2.56% FPR on benign). | Zero recall on names outside local inventory; SBOM completeness is a strict prerequisite. |
| **Tier 3: Agent Exposure Review & Capability Composition** | **Verified** | `tools/agent_graph/exposure_review.py` (91% coverage), `composition.py` (99% coverage), `marginal.py` (97% coverage). Evaluated across 336 real configurations; the repository suite is 536 tests. | Capability taxonomy evaluated against 23 labeled benchmarks (precision 0.73, recall 0.53); measures potential capability co-occurrence across static configurations, not runtime telemetry. |
| **Tier 4: Host Confinement & Agent Sandbox** | **Experimental (Linux/macOS) / Blocked (Windows Kernel Confinement)** | Bubblewrap (`bwrap`) isolation on Linux, Seatbelt (`sandbox-exec`) on macOS. | Windows implementation provides advisory environment sanitization and isolated temp trees; **explicitly blocked from claiming OS kernel containment** without virtualization/JobObject enforcement. |
| **Tier 5: Dynamic Sandboxed Live Malware Execution** | **Deferred** | Static analysis, manifest audits, and synthetic telemetry fixtures only. | Strict safety policy: zero unvetted binary execution or payload downloads in development environments. |

---

## Now: make one detection defensible

1. Keep the active-content SVG rule passing in CI.
2. Add provenance-tracked public samples only when redistribution is permitted.
3. Evaluate false positives against a benign SVG corpus and publish the counts.
4. DONE (2026-09-03): revised YARA and Sigma rules from initial Swarm evasion discoveries (expanded root window to 4KB, namespace prefixes, bracket navigation, switch aliases, and secondary LOLBins), maintaining 0 false positives on the benign corpus. *(The resilience figure originally cited here has since been withdrawn — see retraction note above.)*
5. Write a concise research note explaining the mechanism, tradeoffs, and results.

## Next: broaden detection-engineering evidence

6. DONE (2026-09-03): added ClickFix process-creation Sigma rule (`rules/sigma/proc_creation_win_explorer_clickfix_execution.yml`), 12 synthetic fixtures (6 positive, 6 negative), in-memory SQLite regression tests, and multi-SIEM conversion tests (Splunk SPL, Elasticsearch Lucene, CrowdStrike LogScale).
7. DONE (2026-09-03): documented methodology, ATT&CK mapping, telemetry requirements, query translations, and evasion limitations in `docs/detections/explorer-clickfix-execution.md`.
8. Submit a genuinely novel, quality-checked rule upstream only after checking SigmaHQ for duplicates.

## Later: add threat-research depth and analytical rigor

9. DONE (2026-09-03): published research note on active-content SVG phishing (docs/research/) based on public reporting and v0.1.0 measured results.
10. DONE (2026-09-03): built the Adversarial Swarm Harness (`tools/swarm/`) with a 4-layer safety architecture and a closed loop across six specialized roles (Strategist, Craftsmen, Critic, Detectors, Analyst, Adapter) mapping detection boundaries for YARA and Sigma rules.
11. DONE (2026-09-03): published structured threat intelligence cable (`docs/cables/CABLE-2026-001-clickfix-initial-access.md`) analyzing ClickFix / ClearFake initial access campaigns, separating observed facts from analytical judgments, hypotheses, and unknowns under Sherman Kent doctrine.
12. DONE (2026-09-03): published indicator of compromise (IOC) matrix with role context, analytical confidence ratings, and TTL expiration guidance.
13. DONE (2026-09-03): built the PromptEngine, continuous sparring orchestrator, and visual Workbench endless mode to simulate continuous waves of novel attack permutations and track boundary resilience over time.
14. DONE (2026-09-03): built the Self-Healing Loop (`tools/swarm/adapter.py`) and Automated Intelligence Cable Generator (`tools/swarm/cable_writer.py`) producing ICD 203 / Kent doctrine intelligence cables with YAML frontmatter, Diamond Model graphs, and zero-false-positive verified rule patches.
15. DONE (2026-09-03): built the Multi-Stage Kill Chain Campaign Simulator (`tools/swarm/campaign.py`), expanding defensive coverage to 5 MITRE ATT&CK stages (Initial Access, Execution, Defense Evasion, Credential Access, Persistence) with Depth-of-Defense (DoD) scoring and full-chain incident post-mortem cables (`CABLE-2026-004`).
16. DONE (2026-09-03): published Strategic Threat Intelligence Cable (`docs/cables/CABLE-2026-STRAT-001-empirical-swarm-synthesis.md`) synthesizing 764 adversarial probes, and built the automated strategic trend synthesizer (`tools/swarm/synthesizer.py`) adhering to Sherman Kent doctrine and ICD 203 standards.
17. DONE (2026-09-04): Reconciled MITRE D3FEND ontology taxonomy in `tools/swarm/d3fend_mapper.py`: resolved `D3-LSA` collision (`D3-LSA` for Log Storage Auditing, `D3-LSAP` for Local Security Authority Protection), updated official technique identifiers (`D3-PSA`, `D3-SEA`, `D3-SJA`), and verified extended mappings against published ontology with 0 collisions.
18. DONE (2026-09-04): Grounded enterprise noise floor in `tools/swarm/noise_floor.py`: added 16 non-synthetic routine endpoint profiles with volume-weighting reflecting real EDR/agent emissions (>60% volume), and integrated Wilson score 95% binomial confidence intervals on empirical false-positive rate.
19. DONE (2026-09-04): Documented telemetry prerequisites across all production Sigma rules (`rules/sigma/`) and authored architectural telemetry reference `docs/telemetry/PREREQUISITES.md` detailing exact audit policies, Sysmon Event IDs (1, 10, 11, 4104), and sensor degradation modes.
20. DONE (2026-09-04): Exercised multi-stage correlation in production paths (`tools/swarm/graph_engine.py`): wired 2-stage ordered correlation (Sysmon EID 10 ProcessAccess + Sysmon EID 11 FileCreate) with native Sigma correlation syntax (`rules/sigma/correlation/correlation_lsass_dump.yml`).
21. DONE (2026-09-04): Calibrated SIEM query complexity scores against wall-clock execution timings in `tools/swarm/siem_profiler.py`, benchmarking compiled SQLite queries over in-memory enterprise event store and computing Pearson correlation coefficient ($r$).
22. DONE (2026-09-04): Expanded regression test coverage to 89.1% across `tools/` (130 tests passing in <1.5s), including complete CLI dispatch coverage in `tests/test_swarm_cli.py`.
23. DONE (2026-09-04): Synthesized overnight 8,033-probe run in `docs/cables/CABLE-2026-STRAT-002-empirical-swarm-synthesis.md` and interactive executive dashboard (`CABLE-2026-STRAT-002.html`), demonstrating exact statistical convergence at 71.4% resilience (95% Wilson binomial CI: [70.43%, 72.39%]) and categorizing 2,296 evasion gaps into 4 forensic taxonomies. *(Aggregate figures since withdrawn — see retraction note above.)*
24. DONE (2026-09-04): Built the Dual-Mode Real-World Telemetry Replay Engine (`tools/swarm/telemetry_replay.py`), telemetry acquisition CLI with SHA-256 lockfile (`tools/acquire_telemetry.py` & `tools/telemetry_manifest.json`), curated ~89KB in-repo EVTX/JSONL fixtures (`tests/fixtures/telemetry/`), `--replay-telemetry` CLI integration, and strategic synthesizer grounding, raising test suite to 160 tests passing in <1.8s with 89% coverage.

25. DONE (2026-09-05): Staff-Level Multi-Campaign Adversarial Swarm Workbench Expansion:
    - Extended swarm attack surface with two high-threat campaign archetypes directly matching the Anthropic Staff Threat Intel Engineer / Frontier AI threat model:
      (a) DPRK "Contagious Interview" & AI Developer Supply Chain (`SupplyChainCraftsman`, `package.json`/`setup.py` lifecycle hooks, macOS credential harvesting targeting `~/.aws/credentials`, `~/.ssh/id_rsa`, and Chrome cookies, and AWS STS operationalization).
      (b) Frontier AI Lab GPU Training Cluster & Model Weight Exfiltration (`CloudClusterCraftsman`, privileged container breakouts via `nsenter`, EC2 IMDSv2 metadata token acquisition for worker node IAM roles, model checkpoint reconnaissance, and multi-gigabyte S3 multipart weight exfiltration).
    - Added high-fidelity detection rules: YARA for malicious package lifecycle scripts (`rules/yara/developer_malicious_package_hooks.yar`), Sigma for macOS developer credential access (`rules/sigma/proc_creation_macos_dev_credential_theft.yml`), Sigma for cloud AI cluster IMDS/checkpoint exfiltration (`rules/sigma/proc_creation_cloud_imds_checkpoint_exfiltration.yml`), and multi-event correlation rules.
    - Generalized `tools/swarm/graph_engine.py` into a dynamic multi-campaign DAG state machine with automated layout geometry calculation, serialization (`to_dict`, `to_workbench_dict`), and multi-dialect evaluation.
    - Re-architected Adversarial Swarm Workbench (`swarm_workbench.html`) with dynamic Campaign Switching, interactive SVG DAG rendering with curved Bézier branches for secondary compensating paths, a slide-out Telemetry & Attack Variant Inspector Drawer, Pre-Flight Critic Safety Verification, and CTI Diamond Model Dossier HUD.
    - Expanded test suite from 188 to 205 unit tests (all passing in <3.0s with zero failures).

26. DONE (2026-09-05): Documentation, control-plane, and external-validation pass:
    - Restored the full methodology-document surface: every one of the five detections now has a document covering hypothesis, telemetry prerequisites, ATT&CK mapping, measured results, and named limitations. Root cause of the missing ClickFix document was Windows Defender quarantine (signature 2147925971) triggered by intact command-line cradles in the prose; the document was rewritten with defanged examples, now the standing convention.
    - Built `tools/evaluate_manifest_corpus.py` and measured the package lifecycle hook YARA rule against 1,755 real benign dependency manifests. v1 produced 9 false positives (0.51%, 95% CI [0.27%, 0.97%]) on top-tier npm packages including `undici`, `got`, and `node-fetch`, because primitives were matched anywhere in the file. v2 scopes matching to the hook's own JSON value: 0 false positives (CI upper bound 0.22%) with all four craftsman attack variants still detected. Pinned by `tests/test_manifest_false_positives.py`.
    - Added the cloud control-plane layer (`rules/sigma/cloud/`): 5 CloudTrail and Kubernetes audit rules covering node role credential replay, checkpoint retrieval by non-pipeline identities, role chaining, pod escape primitives, and workload exec. The existing cloud rule was process-creation only, which an adversary using a cloud SDK defeats by default.
    - Fixed two degenerate correlation rules that declared `temporal_ordered` while referencing a single stage. Added `rules/sigma/proc_creation_macos_package_manager_hook_execution.yml` as the missing first stage, and fixed rule reference resolution in `tools/swarm/telemetry_replay.py`, which indexed component rules by id only and silently produced correlations that could never fire.
    - Suite raised from 206 to 231 tests, all passing.

27. DONE (2026-09-05): Built the CTI Collection, Enrichment and Operationalization Pipeline (`tools/cti/`), the highest-matching unbuilt item in the North Star roadmap:
    - Collectors normalizing Certificate Transparency, package registry, and malicious URL feed records into one provenance-carrying indicator model, with malformed records counted rather than swallowed.
    - Cross-source deduplication that keeps the strongest confidence, the earliest sighting, and records corroborating sources instead of picking an arbitrary winner.
    - An explainable relevance scorer for the frontier AI lab threat model: Damerau-Levenshtein typosquat detection with homoglyph normalization, brand, lure, asset, and supply chain vocabularies, and a stated reason for every point awarded.
    - A pivot graph that clusters on shared certificates, addresses, and package linkage, and refuses attribute values shared by more than 25 indicators so that shared hosting cannot masquerade as a campaign.
    - Emitters producing STIX 2.1 with a `valid_until` on every indicator, a SIEM lookup table, and candidate Sigma drafts marked `status: unsupported` with an explicit retirement date.
    - Measured on labeled fixtures: 45 records to 74 unique indicators to a 15-item queue, a 79.7% reduction, recovering 15 of 15 labeled relevant indicators with 0 commodity leakage. Documented explicitly as an internal measurement, since the fixtures and labels were authored here.
    - 33 pipeline tests; suite raised to 258 passing.

28. DONE (2026-09-05): Claim discipline pass on the strategic synthesizer and published cables:
    - The synthesizer template asserted, as virtually certain, an asymptotic resilience ceiling of 70-80%. That range was hardcoded prose while the resilience figure beside it was computed, so the two drifted: `CABLE-2026-STRAT-003` asserted the 70-80% ceiling on the same page its own frontmatter reported 98.3%.
    - It also rated analytic confidence HIGH on sample size alone, treating a large volume of self-generated probes as external evidence.
    - Judgments are now derived from the computed figures, every generated cable carries a scope caveat stating the closed-loop limitation, and analytic confidence is capped at MODERATE by construction.
    - All three strategic cables reissued with a dated revision notice. Underlying measurements unchanged.
    - `tests/test_cable_claim_discipline.py` enforces the framing structurally rather than editorially. Suite raised to 266 passing.

29. DONE (2026-09-05): External validation against 232,729 real confirmed-malicious packages (OpenSSF `malicious-packages`, Apache-2.0, hash-pinned via `tools/acquire_malicious_corpus.py`, identities only, no payloads ever downloaded):
    - Landscape finding: AI-toolchain imitation is ~8x more concentrated in PyPI (3.052%) than npm (0.384%), which says a team defending AI researchers should weight Python registry monitoring far above npm.
    - The vocabulary-based relevance scorer measured **0% held-out recall** on real data (0 of 877) where internal fixtures had reported 15 of 15. Concrete proof that a measurement authored alongside the thing it measures is worthless.
    - Replaced with an inventory-derived mechanism (`tools/cti/protected_names.py`): typosquat and compound detection against the organization's own dependency inventory, on the principle that you do not need to know which brand is imitated, only which names are worth imitating. npm recall 61.6% (CI 58.2-64.8) at a measured 2.56% false-positive rate on unseen real packages.
    - Established the operating characteristic: recall on imitations of names outside the inventory is exactly zero at every coverage level, so improving this detection is an SBOM completeness problem, not a tuning problem.
    - Three defects found only by measuring: a URL normalizer reused on scoped package names (`@eslint/object-schema` reducing to `eslint`), the pipeline rewarding packages for its own `ecosystem:name` formatting, and homoglyph folding suppressing the substitution attack it exists to catch.
    - Suite raised to 287 tests, all passing.

30. DONE (2026-09-05): Rule durability benchmark, telemetry-layer coverage mapping, and live CT collection:
    - `tools/brittleness/` scores any Sigma corpus on six declared-dependency dimensions. Corpora are read from git object storage via a bare clone and `git cat-file --batch`, so no rule text is written to disk; 3,144 of 3,144 SigmaHQ rules read with zero losses.
    - SigmaHQ measured: 192 fragile rules, of which **189 read process creation**; 33.5% cannot fire without Windows command-line auditing, which is off by default and which almost no rule declares. This repository scores identically on composite (0.306) and better only on declaring dependencies (documentation gap 0.053 vs 0.603).
    - `tools/telemetry_coverage.py` maps coverage per technique to a telemetry layer. 83% of the public corpus is endpoint; **five cloud techniques have zero rules** (T1552.005, T1530, T1610, T1651, T1538) and T1567.002 has 13 rules with no control-plane coverage.
    - `tools/acquire_ct_snapshot.py` adds live Certificate Transparency acquisition with a hash-pinned snapshot, closing the split the pipeline documented but never implemented. Added registrable-domain pivoting, which surfaced one apex hosting subdomains impersonating two AI brands.
    - Honest negative result recorded: queue reduction on brand-term CT queries is 0.0%, because collection already filtered on relevance. Scoring only earns its place against a broad stream.
    - Upstream contribution package prepared in `docs/upstream/`, unsubmitted, including an explicit list of what must be fixed before the cloud rules are worth anyone's review.
    - Suite raised to 341 tests, all passing.

31. DONE (2026-09-06): Agent Execution Layer Population Study:
    - Quantitative population study of a conservative sample of the Model Context Protocol (MCP) and agent execution tier across npm and PyPI: 2,500 packages directly sampled and analyzed against 70,552 npm keyword packages and 20,374 PyPI projects.
    - Ecosystem growth curve established: abrupt inflection following Anthropic's November 2024 launch (100% of analyzed npm packages and 92.2% of PyPI packages post-launch, surging to 509 packages in August 2026 alone).
    - Manifest privilege surface measured: 58.7% declare CLI binary entrypoints (`bin`) designed for unvetted `npx -y` dynamic invocation; 26.0% declare install lifecycle hooks (`preinstall`, `postinstall`, `prepare`), representing a major passive code-execution window.
    - Typosquatting profile: 3.36% of packages flagged as imitations, with 95.2% being compound lures (`@prefix/modelcontextprotocol-sdk`) rather than simple misspellings, exploiting modular naming.
    - Forensic triage of OpenSSF advisory records: 210 "mcp" advisory name matches triaged into 4 categories (16.7% pre-MCP historical collisions, 4.3% legitimate vendor tools compromised by the Sha1-Hulud worm like `@browserbasehq/mcp` and `@postman/postman-mcp-server`, 5.7% targeted agent attacks like `groq-mcp` and `openai-mcp` impersonators, and 3.8% canaries).
    - Maintainer fragility: 82.95% single-maintainer concentration, only 16.55% OIDC adoption, with the top 1% capturing 98.05% of all downloads, leaving 71.15% in an unvetted long tail.
    - Delivered `tools/acquire_agent_registry.py`, `tools/evaluate_agent_population.py`, full research report `docs/research/agent-execution-layer-population-study.md`, machine-readable data `docs/detections/evaluation-agent-population.json`, hash-pinned lockfiles, and Obsidian vault note.
    - Suite raised from 341 to 350 tests, all passing.

32. DONE (2026-09-06): Strategic Defense of the AI Agent Execution Layer (RFC, Scanner, Detections):
    - Phase 1 (Upstream RFC): Authored the MCP Telemetry & Capability Specification (`docs/upstream/MCP_TELEMETRY_AND_CAPABILITY_SPECIFICATION.md`) proposing standard `mcp.tool_call` structured auditing telemetry and static capability manifests (`mcp-manifest.json`). Updated `docs/upstream/README.md`.
    - Phase 2 (Operational Tool): Built `tools/agent_audit.py`, a zero-dependency CLI scanner for Claude Desktop, Cursor, and custom agent configuration files. Detects unpinned dynamic flags (`-y`), missing `--ignore-scripts`, compound typosquats against `ProtectedRegistry`, confirmed-malicious OpenSSF hits, plaintext API keys/secrets in environment maps, and wide root filesystem mounts. Verified with 6 dedicated unit tests (`tests/test_agent_audit.py`).
    - Phase 3 (Detection Engineering & Swarm Integration):
        - Authored `rules/sigma/proc_creation_agent_runtime_unpinned_tool_execution.yml` (Sysmon Event ID 1: agent host spawning dynamic runners with unprompted `-y` flags).
        - Authored `rules/sigma/proc_creation_agent_alien_runtime_bun_infostealer.yml` (Sysmon Event ID 1: alien JS runtime Bun spawned from temp or site-packages directories).
        - Authored `rules/sigma/correlation/correlation_agent_unpinned_tool_credential_access.yml` (Temporal correlation: unpinned dynamic tool execution followed by developer credential harvesting).
        - Authored positive test fixtures: `agent_claude_npx_unpinned.json` and `agent_alien_bun_temp_exec.json`.
        - Extended D3FEND mapper (`tools/swarm/d3fend_mapper.py`) with verified ontology mappings for `T1036` and `T1574.013` (0 taxonomy defects or collisions).
        - Integrated rules into `tools/swarm/noise_floor.py`: measured 100% recall on owned fixtures and 0.00% false-positive rate across enterprise background profiles.
        - Published full technical detection documentation in `docs/detections/agent-execution-layer-detections.md`.
    - Test suite raised from 350 to 356 tests, all passing.

33. DONE (2026-09-06): Deep Investigation of the AI Agent Execution Layer Vector (5 Tracks & Visual Accompanying Assets):
    - Track 1 & 2 (Forensic Threat Intel & Cognitive-to-Host Bridge): Authored formal threat intelligence cable `docs/cables/CABLE-2026-011-agent-execution-layer-infostealers.md` (TLP:CLEAR, ICD 203 / Sherman Kent doctrine, Diamond Model, forensic dissection of targeted alien runtime infostealers bundling standalone runtime `bun.exe` inside Python `.pth` auto-loaders, defanged IOCs, and Cognitive-to-Host bridge sequence diagram). Updated `docs/cables/INDEX.md`.
    - Track 3 (Host Confinement & Sandbox Engine): Built `tools/agent_sandbox/` (`policy.py`, `launcher.py`, `__init__.py`) providing OS-native isolation: Bubblewrap (`bwrap`) on Linux, Seatbelt (`sandbox-exec`) on macOS, and honest advisory environment sanitization / isolated temp trees on Windows (explicitly disclaiming OS-level kernel confinement on Windows without virtualization, and eliminating PowerShell injection wrappers), enforcing credential blacklists (`.aws`, `.ssh`, `.gnupg`, browser cookies). Verified by 9 unit tests (`tests/test_agent_sandbox.py`).
    - Track 4 (Adversarial Swarm Sparring & Campaign CAMP-AGENT-004): Authored `AgentExecutionCraftsman` (`tools/swarm/craftsmen/agent_execution_craftsman.py`) generating 3 adversarial mutation cycles (dynamic runner variations, alien runtime staging locations, and temporal correlation evasion). Registered `agent_execution_infostealer` campaign in `tools/swarm/graph_engine.py` with multi-stage DAG nodes, primary process detectors, and secondary compensating controls (`agent_config_audit`, `agent_correlation`). Verified by 5 unit tests (`tests/test_agent_execution_craftsman.py`).
    - Track 5 (Real-Time Registry Watchdog & Triage Stream): Built `tools/agent_watchdog.py` providing real-time evaluation of package publication streams against `ProtectedRegistry` typosquats, executable `bin` entrypoints, lifecycle hooks, outbound egress/child process libraries, maintainer fragility, and OpenSSF malicious feeds. Verified by 7 unit tests (`tests/test_agent_watchdog.py`).
    - Executive Visual Dashboard & Generative UI: Delivered `docs/research/agent-execution-layer-dashboard.html` (interactive 5-tab dashboard with SVG ecosystem growth chart, maintainer concentration curve, triage breakdown, interactive kill chain simulator, and live agent configuration scanner demo) and `agent_attack_vector_widget.html`.
    - Phase A Rigor & Claim Discipline Pass:
        - Expanded `tests/test_cable_claim_discipline.py` to audit every published markdown cable (`ALL_CABLES`), eliminating near-certainty forecasts across all cables.
        - Recalibrated `CABLE-2026-011` and `CABLE-2026-001` forecasts to evidence-grounded estimative judgments.
        - Disentangled conflated single-maintainer (82.95%) and non-OIDC (83.45%) metrics in `docs/upstream/README.md` and clarified OIDC provenance definitions in RFC.
        - Documented explicit sampling limitations and v1 cohort scope caveats in `docs/research/agent-execution-layer-population-study.md`.
    - Test Suite: 377 unit tests passing in <6s with zero regressions.


34. DONE (2026-09-06): Capability composition analysis for agent toolchains (`tools/agent_graph/`), testing whether the exfiltration hazard is a property of the installed set rather than of any package:
    - Acquired 1,387 real agent configurations from public repositories, resolved each server entry to the package it runs, and deduplicated to 336 unique server sets (178 duplicate sets collapsed). 380 distinct packages referenced. Nothing executed, no payloads downloaded.
    - Built a capability taxonomy over the three "lethal trifecta" legs (framing credited to Simon Willison), deriving evidence from package name and description, declared dependencies, and the credentials the operator wired in.
    - **Verified the taxonomy against 23 independently labelled servers and falsified its own design assumption.** Dependency evidence was assumed strongest and measured weakest (P=0.625/R=0.323) against admitting all evidence (P=0.733/R=0.532), because agent servers are thin wrappers whose dependency sets say nothing about their purpose. Default moved; failed assumption documented rather than deleted.
    - **Headline measurement: of 336 real configurations, 80 (23.8%) close an exfiltration chain, and 26 of those close only by composition** with no single package closing it alone. Roughly a third of all closures are therefore invisible to per-package review. Every composed closure needed exactly two packages.
    - Shipped a runnable analyzer (`docs/research/agent-capability-composition.html`) in the workbench visual language: paste a config, get the capability graph, minimal closures, and which package to remove to break every chain. Runs entirely client-side with the taxonomy exported from Python so the two cannot drift.
    - Prior art named and positioned against (Hasan et al., MCPTox, Huang et al., MCPZoo): none measure capability co-occurrence across an installed set, which is the only novelty claimed.
    - Suite raised to 407 tests, all passing.

35. DONE (2026-09-06): Marginal Closure Risk and Co-Installation Network Analysis for the Agent Execution Layer:
    - Solved the systemic question: "What is the marginal composition risk of adding server X, given what developers already have installed?"
    - **Measurement 1 (Distance-to-Closure Distribution & Sensitivity Band across $N=336$ real configs, $N=256$ open):**
        - Baseline (Tier 1 All Evidence): 68 open configurations (**26.6% of open, 20.2% of total**) sit at distance $d=1$ (one capability leg short of full exfiltration closure). 44 configs sit at $d=2$ (17.2% open, 13.1% total), and 144 configs sit at $d=3$ (56.2% open, 42.9% total).
        - **Sensitivity Band:** Published distance distribution across all three evidence strictness tiers (Tier 1: 68 at $d=1$ [26.6% open]; Tier 2 Manifest Structure: 56 at $d=1$ [21.4% open]; Tier 3 Declared Dependencies: 54 at $d=1$ [20.6% open]). Because precision is 0.73 and recall is 0.53, these metrics measure potential capability co-occurrence rather than strict lower bounds.
    - **Empirical Catalyst Breakdown ($n=68$ at $d=1$):** for **61.8% of configurations at the precipice (42 configs, 16.4% of open, 12.5% of total), untrusted ingress and exfiltration are already active**; adding a single benign private data reader (e.g. `@modelcontextprotocol/server-filesystem`) immediately flips all 42 to closed!
    - **Measurement 2 (Joined Marginal Simulation with Co-Installation Affinity):**
        - Counterfactual simulation joined with empirical co-installation to eliminate uniform-mixing distortion. Ranked headline metrics by composed flips.
        - Contrast demonstrated: `@azure/mcp` yields 67 flips under uniform mixing but **0 grounded flips** (never observed co-installed in open configs), while `@modelcontextprotocol/server-filesystem` induces **27 grounded flips** (Jaccard affinity 0.46) and `@upstash/context7-mcp` induces **25 grounded flips** (Jaccard affinity 0.39).
    - **Measurement 3 (Calibrated Co-Installation Graph & Template Prevalence):**
        - Raised support threshold from 2 to $\text{support} \ge 3$ on the 336 deduplicated configuration baseline to filter transient pairs. Resulting topology: 35 edges connecting 18 packages in a single connected component (`component_size_distribution: [18]`, Developer Core Workstation) with 362 isolated singletons, isolating noise and avoiding multi-community collapse.
        - Template prevalence reported separately: 1,387 files retrieved, 1,275 valid configs, 178 duplicate sets collapsed (13.96% duplicate rate).
    - **Interactive Working-Set Sandbox:** updated `docs/research/agent-capability-composition.html` with real-time distance badge, active 3-leg cards, evidence sensitivity band table, template prevalence signal card, and marginal recommendations table with unweighted upper bounds alongside co-installation grounded metrics.
    - **Export pipeline & test suite:** updated `tools/agent_graph/export_artifact.py`, regenerated `docs/detections/evaluation-agent-composition.json` and `docs/research/agent-capability-composition.html`.
    - Suite raised to 414 unit tests, 100% passing.

36. DONE (2026-09-06): Trust Repair, Exposure Review Flagship Workflow, and 86% Statement Coverage:
    - **Trust Repair across 14 Confirmed Review Blockers (R01–R14):**
        - R01–R13: Reconciled multi-campaign DAG layout, calibrated Kent doctrine cable synthesis, audited rule patch generation, sandboxed launcher policy with safe TEMP isolation, grounded SIEM profiling, and calibrated CTI emit pipelines.
        - R14 (`tools/swarm/endurance_runner.py`): Replaced global mutable file and directory state with instance-scoped paths; added clean logging handler closure on Windows; returned `None` instead of fabricated default metrics (`0.714`, `1.0`, `0.91`) when zero observations have completed.
    - **Flagship Workflow — Agent Exposure Review (`tools/agent_graph/exposure_review.py`):**
        - Direct operator workflow answering: *"What changes if I add this tool to my current agent?"*
        - Evaluates baseline vs. candidate-added capability legs, distance to trifecta closure, minimal closures formed, newly critical single points of failure, and concrete architectural mitigations (path scoping, dual-profile architectural separation, version pinning).
        - Provides both interactive human-readable terminal output and redacted JSON report exports.
    - **Test Coverage & Verification:**
        - Built comprehensive test suites for previously untested CLI modules (`test_agent_export_artifact.py`, `test_evaluate_manifest_corpus.py`, `test_evaluate_relevance_recall.py`, `test_brittleness_cli.py`, `test_cti_cli.py`, `test_acquire_malicious_corpus.py`, `test_agent_exposure_review.py`).
        - Full test suite: **475/475 tests passing** in CI (<8.0s), zero failures, zero errors.
        - Statement coverage across `tools/`: **86%** (8,078 statements, 1,106 missed), exceeding the 85% requirement with zero live malware downloads and zero uncommitted git side-effects.

37. DONE (2026-09-06): Verification pass over the release-readiness work, and three correctness fixes to the flagship Exposure Review found by running it rather than reading it:
    - Verified all four gates independently: 475 tests passing, `docs/reviews/reproduce_review.py` 9/9, statement coverage 86% against the 85% floor, and the test suite confirmed to mutate nothing under `docs/swarm/results/` (hash comparison before and after a full run). Confirmed the artifact is now genuinely self-contained with the Tailwind CDN removed, and that the taxonomy embedded in the page matches the Python source exactly across all four rule sets (17 capability legs, 81 dependency rules, 18 text rules, 31 wiring rules).
    - Spot-verified the three highest-risk repairs: the PowerShell injection wrapper and false Job Object claims are gone from the Windows sandbox path and replaced with an explicit warning that no OS-level boundary is enforced; the unverified `langchain-core-mcp` lead is purged from code and data; and the endurance runner no longer fabricates 0.714 and 1.0 defaults when no observations exist.
    - **Fixed: modeled exposure paths listed the entire capability taxonomy.** Every closure was described with all 17 capabilities regardless of what its packages held, so every path read identically and credited each tool with capabilities it did not have. Paths now name only the capabilities the closure's own packages hold, grouped by leg and attributed per package.
    - **Fixed: the mitigation recheck was hardcoded to succeed.** Status, residual path count, and the supporting narrative were literals asserting the profile split always works. The recheck now actually partitions the tools, re-analyses each profile, and reports residual closures. On a tool that holds all three legs alone it correctly reports STILL CLOSED with one path remaining, because that tool carries the whole trifecta into whichever profile it lands in. A recheck that cannot report failure is not a recheck.
    - **Fixed: directory scoping advice was misattributed.** It was gated on the `private_data` leg, which also covers repository, mailbox, database and cloud reads, so it told operators to constrain the directory arguments of tools that take none. Now gated on `fs_read`.
    - Added `ExposureReviewCorrectnessTests` pinning all three, since the suite was green while all three shipped. Suite raised to 479 tests, coverage 86%.

## Not yet

Do not start the enrichment CLI or public-data triage study until the first detection has measured corpus results and a finished write-up. One finished, measured detection is worth more than several half-built ones.
