# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Changed
- **Identity and claim vocabulary de-claimed.** The package, CLI, architecture note, and README no
  longer describe this system as an "Adversarial Swarm Intelligence Engine", "multi-agent", or
  "self-healing". No language model or autonomous agent participates in mutation, gating,
  evaluation, or measurement; the harness is a deterministic closed loop and is now named as one.
- **Renames (breaking for scripts importing the internals):** `tools/swarm/autonomous.py` →
  `tools/swarm/sparring.py`, `AutonomousOrchestrator` → `SparringRunner`, `run_autonomous` →
  `run_sparring`, `run_autonomous_campaigns` → `run_campaigns`.
- **CLI flags renamed (breaking for scripts):** `--autonomous` → `--continuous`,
  `--self-heal` → `--propose-patches`.
- **Fixture provenance corrected.** The `mordor_*.jsonl` telemetry fixtures are hand-styled
  synthetic telemetry authored for this repository, modelled on the named OTRF Mordor datasets —
  they are not upstream slices, and earlier descriptions calling them authentic were wrong. The
  manifest now records a `provenance` and `derivation` per dataset, and
  `tools/acquire_telemetry.py` verifies a download's hash in a staging file before replacing a
  fixture (previously it wrote over the fixture first and checked after).
- **Metric names now state their basis.** `resilience_score` / `final_resilience` become
  `detection_rate_on_approved`; an empty denominator reports `n/a (not measured)` rather than a
  figure. Finding confidence is derived from attribution specificity instead of stamped `HIGH`.
- **Self-healing cables retracted and re-templated.** `CABLE-2026-002` and `CABLE-2026-003`
  published a `60.0% → 100.0%` resilience improvement that was a code constant, not a measurement;
  both carry correction notices, and the template now publishes only measured patch-verification
  evidence. See `docs/cables/ERRATA-2026-09-10.md`.
- **Safety is unconditional, not a toggle.** Three `forbid_*` flags that no code path read were
  deleted; the permitted-address policy is now a declared table in the Critic
  (`PERMITTED_ADDRESS_RANGES`), and the "Routable IPv4" label was corrected to "non-reserved".
- **Determinism is verified, not assumed.** The endurance runner seeds its RNG and derives probe
  ids from content; two consecutive CLI runs produce byte-identical artifacts, and regenerating the
  committed boundary maps with the documented command reproduces them exactly. CI runs the
  pair-check on every push.
- **The prompt interface states what it is:** keyword routing, documented as such, with
  content-derived ids — not a model-driven planner.
- **Brittleness figures regenerated under the repaired condition semantics.** The committed
  SigmaHQ report predated the R11 repair (it searched the condition text instead of evaluating
  it) and reported 33.5% command-line bound / 192 fragile rules; the regenerated report records
  **31.0% / 163**. Re-deriving the report's pinned revision with the repaired scorer reproduces
  the new figures exactly, and the corpus's `rules/` subtree is byte-identical between the two
  revisions — the delta is the repair alone. The 2026-09-05 reports are preserved as
  `*_2026-09-05.json`, `docs/brittleness/rederive_at_revision.py` re-derives any pinned
  revision, and the upstream-facing figures (`docs/upstream/README.md`) carry the correction.

### Fixed
- **A concluded run no longer leaks its workbench listener.** `_finish_run()` called `shutdown()`
  without releasing the socket or clearing the attribute, leaving a bound loopback port until
  garbage collection; because the server tries only three ports before giving up silently, leaked
  sockets could quietly cost later runs their workbench. Teardown now routes through one helper
  that also calls `server_close()`.
- **The replay false-positive rate counted only one of its two detection paths.** Events reached
  through a correlation chain were absent from the numerator; on the fixture that exercises it the
  published rate was 33% where the measured rate is 100%.
- **Two classes of Critic false positive removed.** JSON-escaped Windows paths (`\\Claude.exe`)
  were flagged as network destinations, and a file-extension denylist containing `.com` silently
  skipped every `.com` host. Both are pinned by regression tests; the UNC attacks are still caught.
- **The ledger can no longer desync silently.** An append failure marks the run degraded
  (`ledger_complete: false`) instead of being swallowed, so no later resume or report can present
  drifted counters as ledger-backed.
- **Patch application fails loudly on anchor drift** instead of silently doing nothing, and records
  which resolution it used.
- **The regression suite no longer writes into published artifacts.** Orchestrator tests wrote
  through to `docs/swarm/results/`; they now take a scratch directory, and CI fails if a test run
  modifies `docs/swarm/` or `docs/cables/`.
- **Interactive artifacts load no external resources.** `swarm_workbench.html`, the three STRAT
  briefings, and the agent-execution-layer dashboard loaded Tailwind from third-party CDNs
  (including an Antigravity dev URL). Tailwind is now vendored once at
  `docs/assets/vendor/tailwind-play.js`, all five reference the local copy, and
  `tests/test_artifact_self_containment.py` fails if an external script or stylesheet link
  returns.
- **The withdrawn STRAT briefings now open with a withdrawal banner** linking
  `ERRATA-2026-09-10` and `CABLE-2026-STRAT-004`, and `docs/cables/INDEX.md` marks their rows as
  figures-withdrawn.

### Added
- **Repository landing page and README screenshots.** `index.html` links the interactive
  artifacts (ready for GitHub Pages), and the README gains screenshots of the composition
  analyzer, the workbench, and the agent execution layer dashboard (`docs/assets/screenshots/`).
- Dual-Mode Real-World Telemetry Replay Engine (`tools/swarm/telemetry_replay.py`):
  ingests native binary Windows `.evtx` (via `python-evtx`) and normalized JSONL / NDJSON streams
  (Mordor OTRF, Splunk, Elastic NDJSON), normalizes heterogeneous schemas (Security 4688/4698,
  Sysmon 1, 7, 10, 11), evaluates single-event Sigma rules and temporal multi-stage correlation chains,
  and measures alert latency (p50/p95) and empirical false-positive rate with 95% Wilson score
  binomial confidence intervals (ICD 203 Analytic Standard).
- Cryptographic Telemetry Acquisition Tool & Manifest (`tools/acquire_telemetry.py` & `tools/telemetry_manifest.json`):
  CLI and SHA-256 lockfile tracking provenance, licensing, and cryptographic digests for external
  and in-repo telemetry corpora, supporting offline-first `--verify-only` validation.
- In-Repo Compact Telemetry Fixture Suite (`tests/fixtures/telemetry/`, ~89KB total):
  one upstream Sysmon `.evtx` export (`sample_sysmon_process_create.evtx`) and three hand-styled
  synthetic fixtures (`mordor_lsass_dump.jsonl`, `mordor_schtasks_persistence.jsonl`,
  `benign_enterprise_workstation.jsonl`) authored in the repository's `*.corp.example` namespace.
  They are modelled on the named OTRF Mordor datasets but are not upstream slices; the manifest
  records that provenance per dataset, and the `.evtx` copy is hash-pinned locally without an
  offline byte-identity check against the upstream source.
- Swarm CLI Replay Commands (`tools/swarm/cli.py`):
  added `--replay-telemetry`, `--corpus-path`, and `--is-benign` flags emitting ICD 203 telemetry
  replay reports to stdout and `docs/swarm/results/telemetry_replay.json`.
- Strategic Synthesizer Replay Grounding (`tools/swarm/synthesizer.py`):
  integrated empirical telemetry replay metrics and Wilson confidence intervals directly into
  the strategic intelligence cable synthesis pipeline.
- Continuous Workbench Sparring: `Continuous Sparring: ON / OFF` sequential looping in
  `swarm_workbench.html`. The overnight run first published as `CABLE-2026-STRAT-002`
  (8,033 probes / 71.4%) was **retracted on 2026-09-10**: no persisted ledger exists for it, the
  headline rate matched a retired code default, and its denominator mixed benign noise-floor events
  with attack probes. The cable and its dashboard carry retraction notices; see
  `docs/cables/ERRATA-2026-09-10.md`.
- Test Suite Expansion: added `tests/test_telemetry_replay.py` plus coverage for the endurance
  lifecycle, replay, observation-record, and honesty-guard paths; the suite is 545 tests with 87%
  statement coverage across `tools/` (floor 85), enforced in CI.
- MITRE D3FEND Ontology Taxonomy Reconciliation (`tools/swarm/d3fend_mapper.py`):
  disambiguated `D3-LSA` identifier collision (`D3-LSA` Log Storage Auditing, `D3-LSAP` Local
  Security Authority Protection), and updated official technique IDs (`D3-PSA`, `D3-SEA`, `D3-SJA`).
  Each mapping carries its own provenance; the earlier blanket claim that every extended identifier
  had been verified against the ontology is withdrawn, and unverified entries are listed as gaps.
- Grounded Enterprise Noise Floor & Wilson Confidence Intervals (`tools/swarm/noise_floor.py`):
  widened baseline to 16 realistic endpoint profiles, integrated volume-weighting reflecting
  real-world EDR/agent emission ratios (>60% volume), and added Wilson score 95% binomial
  confidence intervals to false-positive rates.
- Telemetry Prerequisites Architecture (`rules/sigma/` & `docs/telemetry/PREREQUISITES.md`):
  added structured `telemetry_prerequisites` YAML blocks across all production Sigma rules and
  authored architectural specification detailing Windows Advanced Audit Policies, Sysmon
  Event IDs (1, 10, 11, 4104), and telemetry degradation modes.
- Multi-Stage Temporal Correlation Engine (`tools/swarm/graph_engine.py` & `rules/sigma/correlation/`):
  implemented native Sigma correlation rule (`correlation_lsass_dump.yml`) chaining Sysmon EID 10
  ProcessAccess with Sysmon EID 11 FileCreate within 120s windows, exercised directly in production
  `GraphEngine` walks.
- Empirical SIEM Query Calibration (`tools/swarm/siem_profiler.py`): calibrated static complexity
  scores against wall-clock SQLite execution times, computing empirical latencies and a Pearson
  correlation coefficient ($r$) from exactly one measurement per rule, so the coefficient is not
  inflated by duplicated cross-backend pairs. A latency is reported only for the backend actually
  timed; the driver attribution is stated only when the measurements support it.
- Test Suite Coverage Expansion: added `tests/test_swarm_cli.py` and `SiemQueryProfilerTests`.
- Strategic Threat Intelligence Synthesizer (`tools/swarm/synthesizer.py`): automated engine
  aggregating empirical threat cables and boundary telemetry to author ICD 203 / Sherman Kent
  doctrine Strategic Intelligence Cables with Diamond Model diagrams and trend breakdowns.
- Strategic Threat Cable: `CABLE-2026-STRAT-001` analyzing 764 autonomous adversarial probes,
  cluster distributions, the 71.2% resilience equilibrium, and multi-stage containment proofs.
- CLI flag `--synthesize-trends` in `tools/swarm/cli.py` for one-command strategic synthesis.
- Autonomous Multi-Stage Kill Chain Campaign Simulator (`tools/swarm/campaign.py`): evaluates
  end-to-end multi-vector intrusions chaining 5 MITRE ATT&CK stages (Initial Access, Execution,
  Defense Evasion, Credential Access, Persistence) and computes Depth-of-Defense (DoD) scores.
- 3 New Production Sigma Rules & Fixture Suites:
  - Defense Evasion: `rules/sigma/proc_creation_win_defense_evasion_tampering.yml` (T1070.001 / T1562.001).
  - Credential Access: `rules/sigma/proc_creation_win_rundll32_lsass_dump.yml` (T1003.001).
  - Persistence: `rules/sigma/proc_creation_win_schtasks_persistence.yml` (T1053.005).
- CLI flag `--campaign` in `tools/swarm/cli.py` for simulated multi-stage intrusion flows.
- Multi-Stage Incident Post-Mortem Cable `CABLE-2026-004` evaluating defense-in-depth containment.
- Kill Chain Campaign Studio integrated into `swarm_workbench.html` with real-time 5-stage timeline.
- Self-Healing Loop (`tools/swarm/adapter.py`): Agent 06 (The Adapter) diagnosing evasion
  gaps, synthesizing candidate patches, and validating them against a zero-false-positive
  regression test gate before proposing rule commits.
- Automated Threat Intelligence Cable Generator (`tools/swarm/cable_writer.py`): authors
  standardized, machine-readable intelligence cables adhering to Sherman Kent doctrine and
  ICD 203 standards with YAML frontmatter, Diamond Model graphs, and root-cause analyses.
- Master threat cables index catalog in `docs/cables/INDEX.md` enabling automated downstream
  LLM trend analysis.
- CLI flag `--self-heal` in `tools/swarm/cli.py` for automated closed-loop patch synthesis.
- Upgraded Visual Workbench (`swarm_workbench.html`): integrated Agent 06 (Adapter) into
  the live pipeline, added Self-Healing toggle, and embedded real-time intelligence cable links.
- Autonomous continuous sparring engine (`tools/swarm/autonomous.py`) for simulating
  endless waves of novel threat mutations and tracking time-series resilience progression.
- Structured Threat Intelligence Cable: `CABLE-2026-001` ("Adversary Initial Access Analysis:
  Multi-Stage ClickFix Social Engineering and Active-Content SVG Lures Delivering InfoStealer Malware")
  adhering to Sherman Kent / ICD 203 doctrine, Diamond Model analysis, and MITRE ATT&CK mapping
  (`docs/cables/CABLE-2026-001-clickfix-initial-access.md`).
- Adversarial Swarm Intelligence Engine (`tools/swarm/`): a controlled multi-agent
  testing harness with a 4-layer safety architecture and 5-agent closed feedback
  loop (Strategist, Craftsmen, Critic, Detectors, Analyst, Adapter) for automated
  detection boundary testing against YARA and Sigma rules.
- Pre-flight safety Critic enforcing RFC 2606 reserved domain boundaries (`.invalid`)
  and syntax validity.
- Specialized Craftsmen mutators (`SvgCraftsman`, `ProcessCraftsman`) exploring
  structural, syntactic, LOLBin, and obfuscation evasion axes.
- Comprehensive architecture documentation (`docs/swarm/architecture.md`) and
  reproducible boundary maps/campaign reports (`docs/swarm/results/`).
- Swarm regression test suite (`tests/test_swarm.py`) covering Critic safety gates,
  Craftsmen generators, and end-to-end closed-loop orchestration.

### Changed
- Tuned YARA rule (`Suspicious_Active_Content_SVG_Attachment`) from Swarm recommendations:
  expanded root search window to 4,096 bytes (`REC-YARA-001`), added XML namespace prefix
  support (`REC-YARA-003`), and added bracket navigation property matching (`REC-YARA-002`).
  Maintained 0 false positives across 2,079 benign Bootstrap icons and resolved initial boundary gaps.
- Tuned Sigma rule (`proc_creation_win_explorer_clickfix_execution.yml`) from Swarm recommendations:
  added numeric/short PowerShell switch aliases (`-w 1`, `-w h`), `rundll32.exe` with URL handlers
  (`REC-SIGMA-004`), and Windows Script Host (`wscript`/`cscript`) remote execution (`REC-SIGMA-005`),
  resolving initial evasion vectors and feeding long-tail continuous sparring (71.2% equilibrium, N=764).
- Second detection: `Suspicious Process Spawning From Explorer Run Prompt (ClickFix Pattern)`
  Sigma rule (`rules/sigma/proc_creation_win_explorer_clickfix_execution.yml`).
- Twelve synthetic process creation fixtures (6 positive, 6 negative) covering
  PowerShell download cradles, hidden window flags, encoded commands, MSHTA, Curl,
  and CMD staging vs. benign interactive launches.
- Automated Sigma test harness (`tests/test_sigma_rules.py`) supporting rule
  schema validation, in-memory SQLite event regression, and multi-SIEM query
  conversion (Splunk SPL, Elasticsearch Lucene, CrowdStrike Falcon LogScale).
- Methodology note with ATT&CK mapping, telemetry requirements, query examples,
  and evasion limitations (`docs/detections/explorer-clickfix-execution.md`).
- Original research note: "Active Content in SVG Phishing Attachments:
  Detection Opportunities and Evasion Tradeoffs"
  (`docs/research/active-content-svg-phishing.md`).

## [0.1.0] — 2026-09-03

### Added
- First detection: `Suspicious_Active_Content_SVG_Attachment` YARA rule
  (script/URI + navigation + external destination combination).
- Eleven synthetic regression fixtures (6 positive, 5 negative) and
  unittest-based regression suite running in GitHub Actions.
- Reproducible benign-corpus evaluation tooling
  (`tools/evaluate_rule.py`) with unit-tested metric and hash-verification
  logic, provenance acquisition lock, and committed JSON results.
- Benign-corpus baseline: 2,079 Bootstrap Icons v1.13.1 SVGs
  (MIT), 0 false positives.
- Methodology note with ATT&CK mapping, measured results, and limitations;
  CONTRIBUTING, SECURITY, and roadmap documents.

### Fixed
- Rule initially required the SVG root at byte 0; now allows an XML
  declaration or leading whitespace within the first 1 KB (found by an
  adversarial fixture, fixed test-first).
- CI pip cache lookup pointed at a nonexistent `requirements.txt`.