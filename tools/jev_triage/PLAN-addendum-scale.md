# Jev Email Triage — Planned Addendum A: Scale Battery (pre-registered)

**Date:** 2026-09-17 · **Status:** design frozen before scale-corpus acquisition beyond
availability checks and before any scoring on scale data. This addendum registers a
second, larger battery under `PLAN.md`; it does not modify the original 200-email
experiment, its corpus, or its results.

**Motivation.** The first battery (n=200, 4x50) is too small for stable per-class
claims; in operational terms a few hundred emails is not a meaningful sample. This
battery scores Jev over a materially larger public-real corpus: all eligible rows from
the sources below, capped per class (expected ~1-2 x 10^4 eligible before caps).
No synthetic and no hand-authored records are used in this battery.

---

## A1. Sources (frozen; pinned)

| ID | Source | URL / DOI | Label | Basis |
|---|---|---|---|---|
| S1 | SpamAssassin `20030228_easy_ham` | spamassassin.apache.org/old/publiccorpus/ | safe | obvious legitimate mail (corpus authors) |
| S2 | SpamAssassin `20030228_easy_ham_2` | same | safe | same |
| S3 | SpamAssassin `20030228_hard_ham` | same | gray | legitimate but spam-looking; **primary mapping to gray; sensitivity run treats as safe** (both reported) |
| S4 | SpamAssassin `20030228_spam` | same | spam | bulk unsolicited mail |
| S5 | SpamAssassin `20030228_spam_2` | same | spam | same |
| S6 | SpamAssassin `20050311_spam_2` | same | spam | same (2005 release) |
| S7 | `Nazario.csv` | Zenodo DOI 10.5281/zenodo.8339691 | attack | curated phishing corpus (all rows label=1) |
| S8 | `Nazario_5.csv` | same | attack | same, extended variant |
| S9 | `Nigerian_5.csv` | same | attack | advance-fee fraud / social-engineering phishing |
| S10 | `Nigerian_Fraud.csv` | same | attack | same |
| S11 | `CEAS_08.csv`, rows label==1 only | same | attack | CEAS 2008 phishing subset; label==0 rows are out of scope (count recorded) |
| S12 | `Ling.csv` | same | conditional | see A3 (include only if class semantics are unambiguous) |

**Citations / licensing.** Zenodo record 8339691 "Phishing Email Curated Datasets"
(CC-BY-4.0), curated by Champa, Rabbi & Zibran — cite: ISDFS 2024 and ICMI 2024 papers
(per the record's own citation note). Apache SpamAssassin public corpus, distributed
publicly for spam-filter testing (readme: spamassassin.apache.org/old/publiccorpus/readme.html).
Corpora are retained locally only and are not redistributed in this repository; only
locks, manifests, and record files (ids/labels/costs; no bodies) are committed.

**Screened out of this battery (not used in any figure; deferred with reasons):**
`TREC_05/06/07.csv` (volume beyond caps), `Enron.csv` (safe-class provenance is a
different curation axis), `SpamAssasin.csv` (direct SA fetch preferred), the
`zefang-liu/phishing-email-dataset` HF compilation (source overlap; single-file
provenance less traceable), `EPVME-Dataset` (packaging), Zenodo 13474746 (thin bodies;
mixed real+generated content).

Availability of all S1–S12 was verified 2026-09-17 (HTTP HEAD / record API); the S7
schema and label distribution were inspected during availability screening (7-column
CSV: sender, receiver, date, subject, body, urls, label; all rows label=1; one
mbox-conversion artifact observed -> A4 rule).

## A2. Composition and caps

Take **all eligible rows per source**; apply global dedupe (A4); then per-class union
caps, applied deterministically by hash order (sort by `content_sha256`, take first N):

| Class | Cap |
|---|---|
| safe | 6,000 |
| gray | 1,000 |
| spam | 4,500 |
| attack | 12,000 |

Caps bind only when exceeded; actual counts are reported from the lock. Cap rationale:
bound wall-clock (~2 h at measured ~0.2-0.4 s/email, sequential single client) and Jev
spend (A9 ceilings).

## A3. Label mapping and build-time determinations

- Fixed mappings as in A1. S11: label==1 -> attack; label==0 rows recorded as
  out-of-scope counts (not exclusions).
- S12 (`Ling.csv`): inspect schema and label distribution at build time. Include rows
  as `spam` only if semantics are unambiguously spam(1)/ham(0); include as `attack`
  only if unambiguously phishing-flagged; otherwise exclude the file and record the
  decision.
- Rows with unparseable/empty labels: excluded (reason `label-unparseable`).
- Champa CSV -> record mapping: `sender`->`from`; `subject`->`subject`;
  `body`->`body`; `receiver`, `date`, `urls` dropped (recorded in the lock).
- **All build-time determinations** (per-file schema, label distributions, inclusion
  decisions, archive sha256/bytes, mapping notes) are written to
  `corpus/email/scale/scale-lock.json` BEFORE any scoring. Determinations made after
  scoring begins are deviations (A12).

## A4. Exclusions (uniform across all sources)

`PLAN.md` §3 rules verbatim: unparseable message; no text body; body > 100 KB; body
< 40 chars; non-ASCII-dominant (< 50% ASCII); missing or empty Subject. Plus, for this
battery:

- **Corpus-conversion artifacts:** mbox internal-data stubs (subject contains
  `FOLDER INTERNAL DATA` or sender contains `MAILER-DAEMON@monkey.org`) — observed in
  the S7 availability check.
- **Dedupe:** `content_sha256(subject + "\n" + body)` — within source and globally
  across the merged corpus. The later occurrence is excluded with reason
  `duplicate-of:<first-source>`; first-seen follows frozen source order S1..S12.

Every exclusion gets a reason and a count in the lock; an audit ledger mirroring
`corpus-audit.json` conventions records kept-with-note decisions.

## A5. Input normalization and model contracts

Identical to `PLAN.md` §3 (normalization) and §4 (Jev contract — 3-question batch,
verbatim): From / Reply-To if present / Subject / body; label = `disposition.choice`;
gate = `disposition.confidence`; model `jev-latest` (actual version recorded from
responses).

## A6. Metrics (pre-declared; recomputed from records only)

- Confusion matrix; per-class precision/recall/support with raw counts; overall accuracy.
- Per-source accuracy (same conventions as `score.py` summarize_run).
- Attack recall on the aggregate attack partition (headline figure).
- Gate: confidence-decile calibration; positions of every attack miss on the
  confidence scale; full two-branch threshold sweep (0.00 -> 1.00, 0.05 steps) with
  auto-coverage, auto-error rate, misroute decomposition, and auto-delivered true
  attacks; the registered operating point **T=0.30** reported explicitly.
- Latency p50/p95/mean (wall-clock at the harness, sequential single client — noted).
- Cost: measured tokens x $0.042/MTok (typesafe.ai, accessed 2026-09-17) -> $/email, $/1k.
- Auxiliary noul means by class.

## A7. Success criteria (registered; each reported PASS/MISS)

- **C1** attack recall >= 0.90 (aggregate attack partition).
- **C2** auto-delivered true attacks at registered T=0.30: **0** (safety invariant; a
  miss is a headline finding, reported first).
- **C3** auto-decide share >= 50% at <= 2% auto-decided exact-label error.
- **C4** cost <= $0.001/email.
- **C5** latency p50 <= 350 ms and p95 <= 1,000 ms.
- **C6** calibration bound: every attack miss at confidence < 0.50 (registered as a
  falsifiable band; the first battery's misses sat <= 0.32).

A miss on any criterion ships as a miss; criteria are not swapped after data.

## A8. Secondary arms (registered; separately labelled)

- **A8.1 Cheap-LLM comparator (DeepSeek V4.1 Flash):** frozen `PLAN.md` §4 prompt;
  deterministic proportional stratified subset of 2,000 emails (per-class allocation =
  round(2000 x class share); within class, hash order; seed 20260917). Run only if the
  key resolves and projected cost <= $3.00 (measured-token proxy x list price); else
  recorded as skipped with reason. Secondary comparison, not headline.
- **A8.2 Sender-recurrence conjunction arm (exploratory; spec frozen here before
  computation):** first-contact share; V0/V1/V2 conjunction variants over sender
  recurrence and threshold grid, mirroring `PLAN-addendum-conjunction-arm.md`
  conventions; ground-truth labels stand in for prior dispositions (perfect-information
  bound — declared); fixed-seed shuffle control mandatory; results in a dedicated
  section labelled post-hoc (spec frozen before computation).
- **A8.3 (not registered):** Claude-tier cascade economics on the scale corpus — out of
  scope this battery (portal budget); do not extrapolate first-battery Claude numbers
  to the scale corpus.

## A9. Stopping rules and ceilings

- Rolling API error rate > 5% over any 200 consecutive observations -> stop,
  investigate, resume via `--resume` (append-only; error rows retained; retries append
  clean observations).
- Spend ceilings: Jev $1.50; comparator $3.00. Exceeding -> stop and report partial;
  deviation recorded.
- No wall-clock cap; runs launch as background jobs with per-item progress lines and a
  run log; per-run resumability required (skip-completed semantics as in `run_jev.py`).

## A10. Artifacts (all new; originals untouched)

- `fetch_scale.py` -> `corpus/email/scale/{_downloads_scale/ (local),
  normalized_scale.jsonl (local), scale-lock.json (committed)}`
- `build_corpus_scale.py` -> `{scale-corpus.jsonl (local), scale-manifest.json (committed)}`
- `run_jev_scale.py` -> `docs/research/jev-email-triage/records/scale/<run>.jsonl`
  (committed; gzip if large, sha256 recorded in RESULTS-SCALE.md)
- `score_scale.py` -> `results-scale.json` + `RESULTS-SCALE.md` (both committed)
- `tests/test_jev_scale.py` pins mapping/cap/dedupe/scoring math on tiny fixtures.

## A11. Limitations (declared up front)

- Era: sources span ~2003-2015 (SA 2003-05; Nazario 2005-07; CEAS 2008). No modern
  inbox; findings generalize to public real-mail samples of that era only.
- Labels are the corpus authors'/curators' as-is; artifacts are audited at build, but no
  independent re-labeling.
- Curation layers may have applied their own filtering before this build.
- Caps truncate unions deterministically; the truncated remainder is unscored.
- Gray support remains small (S3 only).
- Single run; sequential single-client latency basis; no repeated-run variance study.
- No private or employer data anywhere; corpora retained locally, not redistributed.

## A12. Deviations and errata

Any deviation (unreachable source, skipped file, changed mapping, cap binding, error
abort) is recorded in `scale-lock.json` and a DEVIATIONS section of `RESULTS-SCALE.md`.
Corrections follow the errata pattern: wrong figures remain visible as record; the
regenerated artifact supersedes.
