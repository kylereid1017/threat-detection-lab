# Jev email triage — reproducibility bundle

A scoped snapshot of the **Jev email-triage** evaluation from the
`threat-detection-lab` monorepo: the pipeline, the per-email run records, the
pre-registration plans, the generated results, and an independent verifier.
The rest of the monorepo is not part of this branch.

## Verify the published numbers (no install, no network, no API keys)

```bash
python tools/jev_triage/verify_published_numbers.py
```

Expect **62 of 64** figures to reproduce; the two DIFFs are a known
float-rounding defect the verifier itself found, documented in
[`docs/research/jev-email-triage/REPRODUCE.md`](docs/research/jev-email-triage/REPRODUCE.md).

## Run the evaluation's tests

```bash
python -m unittest discover -s tests -p "test_jev*"
```

55 tests, well under a second, standard library only.

## What is not in this bundle

The public-corpus email bodies (third-party corpora — SpamAssassin, Nazario,
CEAS_08, Nigerian fraud, Ling) are not redistributed; the manifest records
which files were used and their SHA-256 hashes. The full reproduction guide,
including what cannot be reproduced and why, is
[`docs/research/jev-email-triage/REPRODUCE.md`](docs/research/jev-email-triage/REPRODUCE.md).
