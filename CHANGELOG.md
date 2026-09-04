# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added
- MITRE D3FEND Ontology Taxonomy Reconciliation (`tools/swarm/d3fend_mapper.py`):
  disambiguated `D3-LSA` identifier collision (`D3-LSA` Log Storage Auditing, `D3-LSAP` Local
  Security Authority Protection), updated official technique IDs (`D3-PSA`, `D3-SEA`, `D3-SJA`),
  and verified all extended technique mappings against the published MITRE D3FEND ontology.
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
  scores against wall-clock SQLite execution times, computing empirical latencies and Pearson
  correlation coefficient ($r$).
- Test Suite Coverage Expansion: added `tests/test_swarm_cli.py` and `SiemQueryProfilerTests`,
  raising total test count to 130 tests and test coverage across `tools/` to 89.1% in <1.5s.
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
  CONTRIBUTING, SECURITY, and portfolio roadmap documents.

### Fixed
- Rule initially required the SVG root at byte 0; now allows an XML
  declaration or leading whitespace within the first 1 KB (found by an
  adversarial fixture, fixed test-first).
- CI pip cache lookup pointed at a nonexistent `requirements.txt`.