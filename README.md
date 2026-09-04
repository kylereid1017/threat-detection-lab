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

# Synthesize accumulated threat cables into an ICD 203 Strategic Intelligence Cable
python -m tools.swarm.cli --synthesize-trends

# Test a custom threat simulation prompt
python -m tools.swarm.cli --target sigma --prompt "Test PowerShell execution with short -w h switch"

# Walk the DAG correlation state machine (defense-in-depth, DoD + MTTD scoring)
python -m tools.swarm.cli --graph --iterations 6

# Run the deterministic zero-false-positive validation gate (ICD 203 summary)
python -m tools.swarm.cli --validate-gate

# Export a MITRE ATT&CK Navigator coverage layer (docs/swarm/results/layer.json)
python -m tools.swarm.cli --export-layer

# Benchmark signal-to-noise against a high-volume benign enterprise corpus
python -m tools.swarm.cli --benchmark-snr --events 2500

# Profile query cost across CrowdStrike LogScale, Splunk SPL, and Elastic Lucene
python -m tools.swarm.cli --profile-siem

# Export the dual-layer MITRE ATT&CK / D3FEND countermeasure matrix
python -m tools.swarm.cli --export-d3fend
```

Open `swarm_workbench.html` in a browser for the interactive state-machine DAG canvas,
which animates a kill-chain walk, branches to secondary telemetry paths on evasion, and
reports live Depth-of-Defense, Mean Time-to-Detect, and Path-to-Objective metrics.

### Detection-as-Code platform (`tools/swarm/`)

The harness is a graph-based, continuously validated Detection-as-Code platform:

- **`telemetry_generator.py`** — schema-driven builder for inert Windows telemetry (Sysmon EID 1 / Security 4688 and correlation event families 7, 10, 11, 4104) with programmatic command-line mutation (argument reordering, integer switch aliases, whitespace, wrapper hosts). Every record is validated against RFC 2606 / RFC 5737 reserved endpoints before evaluation.
- **`graph_engine.py`** — a directed-acyclic-graph state machine over the intrusion lifecycle (Ingress → Execution → Defense Impairment → Credential Telemetry → Persistence). On a primary-analytic miss it branches to an adjacent secondary telemetry path and scores Depth-of-Defense, Mean Time-to-Detect, and path-to-objective containment.
- **`evaluator.py`** — a multi-event Sigma evaluator with temporal correlation windows, requiring several component detections to fire in order within a bounded timespan. Correlation component rules live in `rules/sigma/correlation/`.
- **`validate_gate.py`** / **`export_layer.py`** — the zero-false-positive CI gate and the ATT&CK Navigator layer exporter, wired into `.github/workflows/detection-validation.yml`.
- **`noise_floor.py`** — generates a high-volume corpus of realistic benign Windows background telemetry (Defender, Intune, SCCM, maintenance, administrative PowerShell) and computes precision, recall, F1, and false discovery rate against it. Per-analytic recall is scored only over the events each analytic owns, and corpus metrics are counted per event rather than pooled across rules. The corpus deliberately includes ambiguous administrative activity that genuinely resembles attacker tradecraft, because that is what produces real false positives.
- **`siem_profiler.py`** — compiles every analytic to LogScale, Splunk, and Lucene, then statically scores query cost, flagging leading wildcards, unanchored regexes, and wide OR expansions.
- **`d3fend_mapper.py`** — crosswalks covered ATT&CK techniques onto MITRE D3FEND countermeasures and emits a dual-layer matrix. Mappings carry provenance, and identifier collisions are reported rather than silently resolved.
- **`swarm_workbench.html`** — the interactive state-machine DAG canvas. Its walk constants are regression-tested against the Python engine so the visualiser cannot silently drift from the code it depicts.

## Safety and provenance

This repository uses public sources, public tools, and inert synthetic fixtures only. It contains no employer data, customer data, internal metrics, internal terminology, credentials, or live malicious payloads.

## Status

Experimental. These detections are transparent portfolio exercises, not production security controls. See detection methodology notes for operational assumptions and limitations.

## Threat Intelligence & Research

- [CABLE-2026-001: Adversary Initial Access Analysis: Multi-Stage ClickFix Social Engineering and Active-Content SVG Lures Delivering InfoStealer Malware](docs/cables/CABLE-2026-001-clickfix-initial-access.md) — comprehensive campaign analysis, Diamond Model mapping, facts vs. judgments matrix, and MITRE ATT&CK alignment.
- [Active Content in SVG Phishing Attachments: Detection Opportunities and Evasion Tradeoffs](docs/research/active-content-svg-phishing.md) — original research note: mechanism, tested detection, measured results, evasion tradeoffs, and layered defenses.
