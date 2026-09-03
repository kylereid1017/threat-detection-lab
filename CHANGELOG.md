# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added
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