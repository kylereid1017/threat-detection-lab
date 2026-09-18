# Email Triage Corpus (Jev experiment)

200 records, balanced 4 × 50 across `safe`, `gray`, `spam`, `attack`. Built for the
evaluation designed in `tools/jev_triage/PLAN.md`; labels and inclusion rules are fixed
there and were not tuned after seeing model outputs.

## Composition

| Source | Label | N | Provenance |
|---|---|---|---|
| Apache SpamAssassin public corpus `easy_ham` | safe | 25 | Real mail, 2002–2003. Tarball hash in `email-corpus-lock.json`. |
| Apache SpamAssassin public corpus `hard_ham` | gray | 25 | Legitimate mail designed to look spam-like (the ambiguity band). **Sensitivity run treats these as safe** (both reported). |
| Apache SpamAssassin public corpus `spam` | spam | 25 | Real bulk mail, 2002–2003. |
| Synthetic (inert) | safe / gray / spam | 25 each | LLM-generated (DeepSeek V4.1 Flash), provenance in `synthetic-generation-lock.json`. |
| Synthetic (inert) | attack | 40 | Same generator; per-subtype required mechanics enforced; inertness-validated. |
| Hand-authored (inert) | attack | 10 | `tools/jev_triage/fixtures/hand_authored_attacks.json`. |

## Files

| File | Committed | Note |
|---|---|---|
| `corpus.jsonl` | no (gitignored) | Merged corpus read by the runners; embeds public-corpus content. |
| `normalized_public.jsonl` | no (gitignored) | Normalized public samples (local retention only). |
| `synthetic.jsonl` | yes | Inert synthetic records with full generator metadata. |
| `email-corpus-lock.json` | yes | Sources, tarball SHA-256, pool sizes, sampling seed, exclusion counts. |
| `synthetic-generation-lock.json` | yes | Generator model, prompt hash, batch plan, rejects, output hash. |
| `corpus-manifest.json` | yes | Final counts by label/source + input hashes. |
| `corpus-audit.json` | yes | Manual review ledger: exclusions and kept-with-note flags. |
| `_downloads/` | no (gitignored) | Raw tarballs (retained locally, not redistributed). |

## Reproduction

```bash
python tools/jev_triage/fetch_public_corpus.py   # downloads pinned tarballs, re-samples with seed 20260917
python tools/jev_triage/generate_synthetic.py    # regenerates synthetic emails (LLM; content will differ)
python tools/jev_triage/build_corpus.py          # merges + validates -> corpus.jsonl
```

## Known limitations (carried into every published result)

- Synthetic content is machine-generated; its measured accuracy is **not** evidence of
  real-world efficacy (portfolio rule). It measures mechanics: input contract, latency,
  cost, calibration behavior, cascade economics.
- The public corpus is 2002–2003-era. Modern mail (SPF/DKIM realities, HTML-only bodies,
  tracking infrastructure) is underrepresented; subtype mix is not a 2026 inbox mix.
- Some generated records carry era-drift dates (March/April 2026 templates) — a generator
  artifact, not a labeled feature.
- Non-English-dominant public samples that slipped past the ASCII heuristic were excluded
  during audit (`corpus-audit.json`), applied uniformly to all models.
