# EG2 Email Triage — Battery C Plan (pre-registered)

**Date:** 2026-10-08 · **Status:** design frozen before the model is downloaded and before
any embedding, fitting, or scoring. Deviations get an explicit entry in the results
DEVIATIONS section (errata pattern as in `tools/jev_triage/PLAN-addendum-scale.md` A12).
**Model under test:** `google/embeddinggemma-2` (EG2), text-only configuration
(`vision_config=None, audio_config=None`, 270M effective), frozen weights.
**Comparator:** Jev scale run `jev-scale-20260917T184615Z` — **recorded** predictions; no
Jev re-calls.
**Scope note:** Battery C of the EG2 triage programme. Batteries A (static phishing-page
screenshots) and B (live page capture) get their own addenda when executed; nothing here
touches URLs, pages, or live content.

---

## C1. Question

Does a frozen, self-hosted EG2 embedding with a fixed linear head classify the Jev scale
corpus (safe / gray / spam / attack) better than Jev's zero-shot calls on the same emails —
specifically on the clean phishing/fraud sources, where Jev's zero-danger property failed
at scale (60 confident-safe attack misses at T=0.30)?

**Declared asymmetry:** EG2's head is *supervised* on in-distribution labels; Jev was
zero-shot. Out-of-fold evaluation (C5.E1) still favours EG2; the cross-source holdouts
(C5.E2) are the fairer generalization test and are reported with equal prominence.

## C2. Corpus (frozen; no new acquisition)

`corpus/email/scale/scale-corpus.jsonl` — 18,314 rows, sha256 of its normalized input
`ede15ebe…4343a` (per `scale-manifest.json`). Labels exactly as registered in
`PLAN-addendum-scale.md` A1/A3. Run aborts if the corpus row count ≠ 18,314 or any
`email_id` is missing from the Jev records (join must be 18,314/18,314 on clean Jev
observations; Jev error rows are resolved by its own latest clean retry, as in
`score_scale.py`).

## C3. Input contract (identical to Jev, plus EG2's task prefix)

Text = `tools/jev_triage/run_jev.py::normalized_state(record)` verbatim (From / Reply-To if
present / Subject / blank line / body), passed to EG2 with the model card's symmetric
`Classification` prefix: `task: classification | query: {text}`.

- **Truncation (max_seq_length):** decided from **timing only**, before any label is read
  by the EG2 pipeline: Phase-0 smoke embeds the first 200 corpus rows (file order) at
  1024 tokens on this machine; if projected full-corpus embed time ≤ 6.0 h → 1024, else
  512. The decision and the measured throughput go into run_meta.
- **Precision:** float32 on CPU (no CUDA on this host). The harness asserts dtype ∈
  {float32, bfloat16} and aborts on float16 (model card: fp16 silently NaNs/degrades). Any
  non-finite embedding → row recorded as error, run halts if > 0.1% rows.
- **Output:** 768-d, L2-normalized. MRL 256-d (first 256 dims, re-normalized) computed from
  the same vectors as a registered sensitivity — no second model pass.

## C4. Head (fixed hyperparameters; no tuning, no selection)

Multinomial logistic regression (scikit-learn `LogisticRegression`, `C=1.0`,
`class_weight="balanced"`, `max_iter=2000`, lbfgs). Reported label = argmax;
**confidence = max class probability**. No hyperparameter search of any kind.

## C5. Evaluation protocol

- **E1 — out-of-fold (all 18,314):** `StratifiedGroupKFold(n_splits=5, shuffle=True,
  random_state=20261008)`, stratify on label, group = sha256 of the normalized subject
  (lowercased, digits → `0`, whitespace collapsed) so templated campaigns cannot straddle
  folds. Every email gets exactly one out-of-fold prediction → row-level join with Jev.
- **E2 — cross-source holdouts (fairer):**
  - E2a: train on all rows except `nazario`; test on `nazario` (1,523 attack).
  - E2b: train on all rows except `nigerian_5`; test on `nigerian_5` (3,274 attack).
- **Label bases:** *registered* (CEAS_08 = attack) is primary. *CEAS-remap* (CEAS_08 =
  spam; the Jev post-hoc precedent in `SCALE-READINGS.md` §3) is fitted and scored
  separately (labels change in training too) and reported alongside, labeled as the
  sensitivity basis.

## C6. Gate policy and matched comparison

Two-branch policy identical to Jev: `pred=attack ∧ conf ≥ T → quarantine`;
`pred=safe ∧ conf ≥ T → deliver`; else escalate. "Delivered attack" = true attack,
pred safe, conf ≥ T.

**Matched auto-share:** Jev's auto-share at its registered T=0.30 is recomputed from the
records. `T_eg2` = the smallest threshold on a 0.001 grid at which EG2's E1 auto-share
(registered basis, full corpus) ≤ Jev's. All "at matched auto-share" figures use `T_eg2`.
The full sweep (0.00→1.00, 0.05 steps) is reported for both models.

## C7. Success criteria (each reported PASS/MISS; registered basis unless stated)

| ID | Criterion |
|---|---|
| **C8a** | E1 attack recall on clean sources (nazario ∪ nigerian_5) ≥ Jev's on the same rows |
| **C8b** | E1 delivered attacks on clean sources at matched auto-share **<** Jev's at T=0.30 (Jev: 60 per `SCALE-READINGS.md`; recomputed) |
| **C8c** | E2a nazario attack recall ≥ **0.80** (cross-source generalization) |
| **C8d** | E2b nigerian_5 attack recall ≥ **0.80** |
| **C8e** | Embed latency (CPU fp32, single process, batch as run) p50 ≤ **1,000 ms/email** — CPU basis declared; GPU target from the proposal is not testable on this host |

Reported, not criteria: exact accuracy (both bases), per-class P/R with raw counts and
confusion matrices, per-source accuracy, calibration deciles, 256-d MRL sensitivity,
safe→attack auto-quarantines, and E1 vs Jev disagreement counts on clean sources.

A miss ships as a miss; criteria are not swapped after data.

## C8. Records and artifacts

- `tools/eg2_triage/embed_email.py` → `corpus/email/scale/eg2/` (local only:
  `embeddings-768.npy`, `ids.json`, `embed-log.jsonl`; embeddings derive from
  non-redistributed content and are not committed). Resumable, append-only log.
- `tools/eg2_triage/score_email.py` → `docs/research/eg2-email-triage/records/<run>.jsonl`
  (committed; one row per email × eval × basis: `run_id, seq, ts_utc, model, eval, basis,
  fold, email_id, source, label_true, label_pred, confidence, probabilities`) plus
  `results-email.json` and `RESULTS-EMAIL.md` — every figure recomputable from records.
- `tests/test_eg2_email_scoring.py` pins grouping, gate, matched-threshold, and join math
  on tiny fixtures.

## C9. Limitations (declared up front)

- Supervised vs zero-shot asymmetry (C1). E1 is optimistic for EG2.
- Corpus era 2003–2008; CEAS_08 label semantics as documented in `SCALE-READINGS.md` §2.
- Subject-grouping reduces but does not eliminate template leakage across folds.
- Truncation may cut long bodies Jev saw in full (Jev itself saw whole emails ≤ 100 KB).
- CPU-only latency; single run; no repeated-run variance study.
- No private or employer data anywhere.
