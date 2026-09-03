# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added
- Autonomous continuous sparring engine (`tools/swarm/autonomous.py`) for simulating
  endless waves of novel threat mutations and tracking time-series resilience progression.
- Generative `PromptEngine` (`tools/swarm/prompt_engine.py`) translating natural-language
  operator directives and continuous threat permutations into safe synthetic test fixtures.
- CLI flags `--autonomous`, `--iterations`, and `--prompt` in `tools/swarm/cli.py` for
  scriptable continuous boundary testing.
- Interactive Visual Workbench upgrades (`swarm_workbench.html`): Autonomous Endless
  Sparring mode, Novel Threat Brainstormer button, and real-time boundary gap alerting.
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
  Maintained 0 false positives across 2,079 benign Bootstrap icons and reached 100.0% Swarm resilience.
- Tuned Sigma rule (`proc_creation_win_explorer_clickfix_execution.yml`) from Swarm recommendations:
  added numeric/short PowerShell switch aliases (`-w 1`, `-w h`), `rundll32.exe` with URL handlers
  (`REC-SIGMA-004`), and Windows Script Host (`wscript`/`cscript`) remote execution (`REC-SIGMA-005`),
  reaching 100.0% Swarm resilience.
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