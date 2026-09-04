# Portfolio roadmap

## Now: make one detection defensible

1. Keep the active-content SVG rule passing in CI.
2. Add provenance-tracked public samples only when redistribution is permitted.
3. Evaluate false positives against a benign SVG corpus and publish the counts.
4. DONE (2026-09-03): revised YARA and Sigma rules from initial Swarm evasion discoveries (expanded root window to 4KB, namespace prefixes, bracket navigation, switch aliases, and secondary LOLBins), maintaining 0 false positives on the benign corpus and establishing the empirical 71.2% resilience equilibrium ($N=764$) under continuous multi-axis sparring.
5. Write a concise research note explaining the mechanism, tradeoffs, and results.

## Next: broaden detection-engineering evidence

6. DONE (2026-09-03): added ClickFix process-creation Sigma rule (`rules/sigma/proc_creation_win_explorer_clickfix_execution.yml`), 12 synthetic fixtures (6 positive, 6 negative), in-memory SQLite regression tests, and multi-SIEM conversion tests (Splunk SPL, Elasticsearch Lucene, CrowdStrike LogScale).
7. DONE (2026-09-03): documented methodology, ATT&CK mapping, telemetry requirements, query translations, and evasion limitations in `docs/detections/explorer-clickfix-execution.md`.
8. Submit a genuinely novel, quality-checked rule upstream only after checking SigmaHQ for duplicates.

## Later: add threat-research depth and analytical rigor

9. DONE (2026-09-03): published research note on active-content SVG phishing (docs/research/) based on public reporting and v0.1.0 measured results.
10. DONE (2026-09-03): built the Adversarial Swarm Intelligence Engine (`tools/swarm/`) with a 4-layer safety architecture and 5-agent closed loop (Strategist, Craftsmen, Critic, Detectors, Analyst, Adapter) mapping detection boundaries for YARA and Sigma rules.
11. DONE (2026-09-03): published structured threat intelligence cable (`docs/cables/CABLE-2026-001-clickfix-initial-access.md`) analyzing ClickFix / ClearFake initial access campaigns, separating observed facts from analytical judgments, hypotheses, and unknowns under Sherman Kent doctrine.
12. DONE (2026-09-03): published indicator of compromise (IOC) matrix with role context, analytical confidence ratings, and TTL expiration guidance.
13. DONE (2026-09-03): built the PromptEngine, Autonomous continuous sparring orchestrator, and visual Workbench endless mode to autonomously simulate continuous waves of novel attack permutations and track boundary resilience over time.
14. DONE (2026-09-03): built the Self-Healing Loop (`tools/swarm/adapter.py`) and Automated Intelligence Cable Generator (`tools/swarm/cable_writer.py`) producing ICD 203 / Kent doctrine intelligence cables with YAML frontmatter, Diamond Model graphs, and zero-false-positive verified rule patches.
15. DONE (2026-09-03): built the Autonomous Multi-Stage Kill Chain Campaign Simulator (`tools/swarm/campaign.py`), expanding defensive coverage to 5 MITRE ATT&CK stages (Initial Access, Execution, Defense Evasion, Credential Access, Persistence) with Depth-of-Defense (DoD) scoring and full-chain incident post-mortem cables (`CABLE-2026-004`).
16. DONE (2026-09-03): published Strategic Threat Intelligence Cable (`docs/cables/CABLE-2026-STRAT-001-empirical-swarm-synthesis.md`) synthesizing 764 autonomous adversarial probes, and built the automated strategic trend synthesizer (`tools/swarm/synthesizer.py`) adhering to Sherman Kent doctrine and ICD 203 standards.
17. DONE (2026-09-04): Reconciled MITRE D3FEND ontology taxonomy in `tools/swarm/d3fend_mapper.py`: resolved `D3-LSA` collision (`D3-LSA` for Log Storage Auditing, `D3-LSAP` for Local Security Authority Protection), updated official technique identifiers (`D3-PSA`, `D3-SEA`, `D3-SJA`), and verified extended mappings against published ontology with 0 collisions.
18. DONE (2026-09-04): Grounded enterprise noise floor in `tools/swarm/noise_floor.py`: added 16 non-synthetic routine endpoint profiles with volume-weighting reflecting real EDR/agent emissions (>60% volume), and integrated Wilson score 95% binomial confidence intervals on empirical false-positive rate.
19. DONE (2026-09-04): Documented telemetry prerequisites across all production Sigma rules (`rules/sigma/`) and authored architectural telemetry reference `docs/telemetry/PREREQUISITES.md` detailing exact audit policies, Sysmon Event IDs (1, 10, 11, 4104), and sensor degradation modes.
20. DONE (2026-09-04): Exercised multi-stage correlation in production paths (`tools/swarm/graph_engine.py`): wired 2-stage ordered correlation (Sysmon EID 10 ProcessAccess + Sysmon EID 11 FileCreate) with native Sigma correlation syntax (`rules/sigma/correlation/correlation_lsass_dump.yml`).
21. DONE (2026-09-04): Calibrated SIEM query complexity scores against wall-clock execution timings in `tools/swarm/siem_profiler.py`, benchmarking compiled SQLite queries over in-memory enterprise event store and computing Pearson correlation coefficient ($r$).
22. DONE (2026-09-04): Expanded regression test coverage to 89.1% across `tools/` (130 tests passing in <1.5s), including complete CLI dispatch coverage in `tests/test_swarm_cli.py`.

## Not yet

Do not start the enrichment CLI or public-data triage study until the first detection has measured corpus results and a finished write-up. One defensible artifact is stronger than several scaffolds.
