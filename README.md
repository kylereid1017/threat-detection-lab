# Threat Detection Lab

A public-safe, test-driven portfolio of detection rules built from public research and synthetic fixtures.

## First detection: suspicious active-content SVG attachments

The first rule targets SVG email attachments that combine multiple high-signal behaviors commonly associated with credential-phishing redirects:

- JavaScript execution or event handlers
- navigation or redirect behavior
- an external HTTP(S) destination

It deliberately requires a combination of signals instead of treating every SVG containing a link as malicious.

## Repository layout

- `rules/yara/` — YARA rules
- `docs/research/` — original research notes
- `docs/detections/` — methodology, rationale, limitations, and ATT&CK mapping
- `tests/fixtures/positive/` — inert synthetic samples expected to match
- `tests/fixtures/negative/` — benign synthetic samples expected not to match
- `tests/test_yara_rules.py` — executable regression tests
- `docs/detections/` — methodology, rationale, limitations, and ATT&CK mapping
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
