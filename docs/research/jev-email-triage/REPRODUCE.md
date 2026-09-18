# Reproducing the email-triage evaluation

Everything in the write-ups recomputes from the run records committed in this repository.
This page is the recipe. It was tested against a clean checkout containing only tracked
files — no local state, no corpus, no API keys.

**No step here makes a network call or costs anything.** The models were called once, during
the battery; what is committed is the per-email record of what they returned.

---

## The 30-second version

```bash
python tools/jev_triage/verify_published_numbers.py
```

Pure standard library — nothing to install. It re-derives every published figure from the
raw records and prints a PASS / DIFF table. Expect **62 of 64**; the two DIFFs are a known
defect described in [What does not reproduce](#what-does-not-reproduce), and the tool is what
found them.

---

## What you have, and what you don't

| | |
|---|---|
| **Committed** | Per-email run records, the pre-registration plans, the scoring code, the generated results, and the corpus lock/manifest with SHA-256 hashes |
| **Not committed** | The public-corpus email bodies themselves. They are third-party corpora (SpamAssassin, Nazario, CEAS_08, Nigerian fraud, Ling) and this repository does not redistribute them. The manifest records exactly which files were used and their hashes. |

The scale records are committed as deterministic gzip (`*.jsonl.gz`, `mtime=0`); the
plaintext is gitignored. Both forms carry published SHA-256 hashes and verify identically —
the tooling reads either.

Because the corpus is not redistributed, anything keyed on *email content* cannot be re-run
from a clone. Everything keyed on *model output* can, and that is every headline number.

---

## Tier 1 — verify the published figures (no install)

```bash
python tools/jev_triage/verify_published_numbers.py
```

An independent second implementation. It deliberately does not import `score.py` /
`score_scale.py`; it re-derives accuracy, recall, percentiles, the cost model, the threshold
policy, the calibration deciles and the post-hoc remap straight from the records, so
agreement between the two means something. Read-only.

```bash
python tools/jev_triage/verify_published_numbers.py --section scale       # n = 18,314 only
python tools/jev_triage/verify_published_numbers.py --section first       # n = 196 only
python tools/jev_triage/verify_published_numbers.py --section integrity   # hashes + table cross-checks
python tools/jev_triage/verify_published_numbers.py --json                # machine readable
```

It also verifies each record file's SHA-256 against the hash published in the provenance
block of `RESULTS-SCALE.md`, and cross-checks the *generated* tables against the records they
were generated from. Exit status is 0 when everything reproduces, 1 when anything differs.

## Tier 2 — regenerate the results documents (no install)

```bash
python tools/jev_triage/score_scale.py     # -> RESULTS-SCALE.md, results-scale.json
python tools/jev_triage/score.py           # -> RESULTS.md, results.json  (n = 196)
```

Also standard library only. These read the records and rewrite the results files in place.
Diff the output against what is committed: **every number should be identical.** The only
expected differences are the `Generated:` timestamp and, if you are working from the gzip
records, the filenames and hashes quoted in the provenance lines.

Neither script mutates a record. Records are append-only evidence; when a document and a
record disagree, the record is right and the document gets regenerated.

## Tier 3 — the evaluation's own tests (no install)

```bash
python -m unittest discover -s tests -p "test_jev*"
```

55 tests, well under a second — the scoring math, the cascade policy, the scale pipeline and
the record-loading paths.

## Tier 4 — the full repository suite

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests
```

602 tests, about 12 seconds. The extra dependencies (yara-python, pySigma and friends) belong
to the detection-engineering side of this lab, not to the email-triage work — Tiers 1–3 are
the relevant ones here.

---

## What does not reproduce

**1. The calibration decile table in `RESULTS-SCALE.md` is wrong in one cell, and the
verifier flags it.**

```
P-CAL      published calibration table row-count sum   18,391   18,314   DIFF
P-0.2-0.3  published decile 0.2-0.3 row count             610      533   DIFF
```

`calibration()` in `tools/jev_triage/score.py` builds each decile as
`lo <= confidence < lo + 0.1`. In binary floating point `0.2 + 0.1` is `0.30000000000000004`
while the next bucket's lower edge, `3/10`, is `0.29999999999999999`, so every row at
confidence exactly `0.30` satisfies both tests. There are 77 such rows, and the table sums to
18,391 against a scored set of 18,314. The `0.2–0.3` decile should read n = 533, accuracy
0.296.

It affects that one displayed cell and nothing else: none of the six registered criteria
touch calibration, and the only decile quoted in the write-ups is the top one (`0.9–1.0`,
n = 6,757, 93.5% accurate), which has no contested edge and reproduces exactly. The n = 196
calibration table is unaffected — that corpus has no row at confidence exactly 0.30.

It is recorded here rather than quietly patched because the number in the published document
is what was published.

**2. The conjunction arm cannot run from a clone.**

`tools/jev_triage/conjunction_arm_scale.py` reads
`corpus/email/scale/scale-corpus.jsonl` for sender addresses, and that corpus is not
redistributed (above). It also globs only for plaintext `*.jsonl`, so on a clone carrying the
gzip records it stops early with `AssertionError: no scale Jev run found` rather than a
useful message. `CONJUNCTION-ARM-SCALE.md` prints the reproduce command without either
caveat.

The arm is an exploratory post-hoc secondary analysis; no headline figure depends on it.

**3. Re-running the models is not a reproduction step and is not free.**

`run_jev_scale.py` and `run_llm_scale.py` re-issue ~18k API calls against paid endpoints.
The point of committing per-email records is that nobody needs to do that to check the
arithmetic. The models are also not deterministic — a re-run would produce different
confidences, which is a documented limitation of a single-run study, not a reproduction
failure.

---

## Reading order

1. `RESULTS-SCALE.md` — the generated, registered output. Source of truth for numbers.
2. `SCALE-READINGS.md` — post-hoc interpretation, labeled as such, kept separate on purpose.
3. `PLAN-addendum-scale.md` — the pre-registration: criteria and thresholds fixed before any
   data was scored.
4. `RESULTS.md` / `REPORT.md` — the first evaluation (n = 196).
5. `CONJUNCTION-ARM-SCALE.md` — the exploratory secondary arm.

The registered criteria are reported as registered — two of six passed at scale. The misses
are not corrected, re-based or relabeled in that table; the post-hoc reinterpretation lives
in a separate document that says post-hoc on every page.
