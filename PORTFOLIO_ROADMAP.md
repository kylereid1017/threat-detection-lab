# Portfolio roadmap

## Now: make one detection defensible

1. Keep the active-content SVG rule passing in CI.
2. Add provenance-tracked public samples only when redistribution is permitted.
3. Evaluate false positives against a benign SVG corpus and publish the counts.
4. Revise the rule from measured errors, not intuition.
5. Write a concise research note explaining the mechanism, tradeoffs, and results.

## Next: broaden detection-engineering evidence

6. DONE (2026-09-03): added ClickFix process-creation Sigma rule (`rules/sigma/proc_creation_win_explorer_clickfix_execution.yml`), 12 synthetic fixtures (6 positive, 6 negative), in-memory SQLite regression tests, and multi-SIEM conversion tests (Splunk SPL, Elasticsearch Lucene, CrowdStrike LogScale).
7. DONE (2026-09-03): documented methodology, ATT&CK mapping, telemetry requirements, query translations, and evasion limitations in `docs/detections/explorer-clickfix-execution.md`.
8. Submit a genuinely novel, quality-checked rule upstream only after checking SigmaHQ for duplicates.

## Later: add threat-research depth

9. DONE (2026-09-03): published research note on active-content SVG phishing (docs/research/) based on public reporting and v0.1.0 measured results.
10. Next campaign analysis: reproduce a public campaign analysis from public reporting and public artifacts, separating observed facts, analytical judgments, hypotheses, and unknowns.
11. Publish indicators with source, first-seen date, confidence, and expiration guidance.

## Not yet

Do not start the enrichment CLI or public-data triage study until the first detection has measured corpus results and a finished write-up. One defensible artifact is stronger than several scaffolds.
