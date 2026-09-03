# Threat Detection Lab

A public-safe, test-driven portfolio of detection rules built from public research and synthetic fixtures.

## Detections

### 1. File Inspection: Suspicious active-content SVG attachments (YARA)

Targets SVG email attachments combining script execution/event handlers, navigation behavior, and external destinations commonly associated with credential-phishing redirects. See `docs/detections/suspicious-active-content-svg.md`.

### 2. Endpoint Process Creation: Suspicious process spawning from Windows Explorer (Sigma)

Targets user-assisted host execution common in ClickFix, ClearFake, and social-engineering campaigns where users are instructed to paste malicious downloaders or cradles into the Windows Run dialog (`Win + R`). See `docs/detections/explorer-clickfix-execution.md`.

## Adversarial Swarm Intelligence Engine

A sandboxed multi-agent testing harness (`tools/swarm/`) implementing a closed feedback loop across 5 specialized roles (Strategist, Craftsmen, Critic, Detectors, Analyst, Adapter) to systematically probe detection boundaries across structural, syntactic, and LOLBin evasion axes. See `docs/swarm/architecture.md`.

## Repository layout

- `rules/yara/` — YARA rules
- `rules/sigma/` — Sigma rules (process creation, endpoint telemetry)
- `tools/swarm/` — multi-agent adversarial boundary testing engine
- `docs/cables/` — structured threat intelligence cables (ICD 203 / Sherman Kent doctrine)
- `docs/research/` — original research notes
- `docs/detections/` — methodology, rationale, limitations, and ATT&CK mapping
- `docs/swarm/` — architecture notes and empirical boundary maps
- `tests/fixtures/` — inert synthetic samples and telemetry events (positive and negative)
- `tests/test_yara_rules.py` — YARA regression tests
- `tests/test_sigma_rules.py` — Sigma schema validation, regression tests, and SIEM conversion tests
- `tests/test_swarm.py` — Swarm safety gates, mutators, and orchestration tests
- `PORTFOLIO_ROADMAP.md` — a small, ordered delivery plan

## Run locally

Requires Python 3.11+.

```powershell
python -m pip install -r requirements-dev.txt

# Run all unit and regression tests (YARA, Sigma, Swarm)
python -m unittest discover -s tests -v

# Run the Adversarial Swarm against detections (closed-loop)
python -m tools.swarm.cli --target yara --max-cycles 3
python -m tools.swarm.cli --target sigma --max-cycles 3

# Run autonomous continuous sparring with automated self-healing & cable generation
python -m tools.swarm.cli --target sigma --autonomous --iterations 10 --self-heal

# Run simulated multi-stage intrusion campaign across 5 MITRE ATT&CK stages
python -m tools.swarm.cli --campaign infostealer

# Test a custom threat simulation prompt
python -m tools.swarm.cli --target sigma --prompt "Test PowerShell execution with short -w h switch"
```

## Safety and provenance

This repository uses public sources, public tools, and inert synthetic fixtures only. It contains no employer data, customer data, internal metrics, internal terminology, credentials, or live malicious payloads.

## Status

Experimental. These detections are transparent portfolio exercises, not production security controls. See detection methodology notes for operational assumptions and limitations.

## Threat Intelligence & Research

- [CABLE-2026-001: Adversary Initial Access Analysis: Multi-Stage ClickFix Social Engineering and Active-Content SVG Lures Delivering InfoStealer Malware](docs/cables/CABLE-2026-001-clickfix-initial-access.md) — comprehensive campaign analysis, Diamond Model mapping, facts vs. judgments matrix, and MITRE ATT&CK alignment.
- [Active Content in SVG Phishing Attachments: Detection Opportunities and Evasion Tradeoffs](docs/research/active-content-svg-phishing.md) — original research note: mechanism, tested detection, measured results, evasion tradeoffs, and layered defenses.
