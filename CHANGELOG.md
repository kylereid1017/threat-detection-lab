# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added
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