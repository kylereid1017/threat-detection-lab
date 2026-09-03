# Portfolio roadmap

## Now: make one detection defensible

1. Keep the active-content SVG rule passing in CI.
2. Add provenance-tracked public samples only when redistribution is permitted.
3. Evaluate false positives against a benign SVG corpus and publish the counts.
4. Revise the rule from measured errors, not intuition.
5. Write a concise research note explaining the mechanism, tradeoffs, and results.

## Next: broaden detection-engineering evidence

6. Add one Sigma rule with public process-creation telemetry, positive/negative fixtures, validation, and backend conversion tests.
7. Document tuning, expected telemetry, false positives, severity, and ATT&CK mapping.
8. Submit a genuinely novel, quality-checked rule upstream only after checking SigmaHQ for duplicates.

## Later: add threat-research depth

9. Reproduce a public campaign analysis from public reporting and public artifacts.
10. Separate observed facts, analytical judgments, hypotheses, and unknowns.
11. Publish indicators with source, first-seen date, confidence, and expiration guidance.

## Not yet

Do not start the enrichment CLI or public-data triage study until the first detection has measured corpus results and a finished write-up. One defensible artifact is stronger than several scaffolds.
