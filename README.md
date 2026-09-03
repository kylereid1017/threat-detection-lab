# Threat Detection Lab

A public-safe, test-driven portfolio of detection rules built from public research and synthetic fixtures.

## Detections

### 1. File Inspection: Suspicious active-content SVG attachments (YARA)

Targets SVG email attachments combining script execution/event handlers, navigation behavior, and external destinations commonly associated with credential-phishing redirects. See `docs/detections/suspicious-active-content-svg.md`.

### 2. Endpoint Process Creation: Suspicious process spawning from Windows Explorer (Sigma)

Targets user-assisted host execution common in ClickFix, ClearFake, and social-engineering campaigns where users are instructed to paste malicious downloaders or cradles into the Windows Run dialog (`Win + R`). See `docs/detections/explorer-clickfix-execution.md`.

## Repository layout

- `rules/yara/` — YARA rules
- `rules/sigma/` — Sigma rules (process creation, endpoint telemetry)
- `docs/research/` — original research notes
- `docs/detections/` — methodology, rationale, limitations, and ATT&CK mapping
- `tests/fixtures/` — inert synthetic samples and telemetry events (positive and negative)
- `tests/test_yara_rules.py` — YARA regression tests
- `tests/test_sigma_rules.py` — Sigma schema validation, regression tests, and SIEM conversion tests
- `PORTFOLIO_ROADMAP.md` — a small, ordered delivery plan

## Run locally

Requires Python 3.11+.

    python -m pip install -r requirements-dev.txt
    python -m unittest discover -s tests -v

## Safety and provenance

This repository uses public sources, public tools, and inert synthetic fixtures only. It contains no employer data, customer data, internal metrics, internal terminology, credentials, or live malicious payloads.

## Status

Experimental. This rule is a transparent portfolio exercise, not a production security control. See `docs/detections/suspicious-active-content-svg.md` for assumptions and limitations.

## Research

- [Active Content in SVG Phishing Attachments: Detection Opportunities and Evasion Tradeoffs](docs/research/active-content-svg-phishing.md) — original research note: mechanism, tested detection, measured results, evasion tradeoffs, and layered defenses.
