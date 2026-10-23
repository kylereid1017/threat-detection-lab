# EG2 Email Triage (Battery C) — Results Report

**Date:** 2026-10-09 · **Run ID:** `eg2-email-20261009T030203Z`
**Model:** `google/embeddinggemma-2` (270M text config, frozen, 768-d, max_seq=512)
**Head:** LogisticRegression (C=1.0, balanced weights)
**Comparator:** Jev scale run (`jev-scale-20260917T184615Z`)

## 1. Registered Criteria Outcome (PLAN C7)

| ID | Criterion | Actual | Result |
|---|---|---|---|
| C8a | E1 attack recall on clean sources >= Jev | EG2: 0.9739 vs Jev: 0.9562 | **PASS** |
| C8b | E1 delivered attacks on clean sources at matched auto-share < Jev (60) | EG2: 0 (T=0.795) vs Jev: 60 (T=0.30) | **PASS** |
| C8c | E2a nazario attack recall >= 0.80 | 0.2154 (328/1523) | **MISS** |
| C8d | E2b nigerian_5 attack recall >= 0.80 | 0.0269 (88/3274) | **MISS** |
| C8e | Embed latency CPU p50 <= 1000 ms/email | 667.6 ms | **PASS** |

## 2. Overall Performance Comparison

| Metric | Jev Scale | EG2 E1 (Registered) | EG2 E1 (CEAS Remap) | EG2 256-d MRL |
|---|---|---|---|---|
| Exact Accuracy | 0.5992 (remap basis 0.7716) | **0.9293** | **0.9397** | 0.9212 |
| Clean Attack Recall (Nazario+Nig5) | 0.9562 | **0.9739** | - | - |
| Clean Delivered Attacks (matched share) | 60 (@T=0.30) | **0** (@T=0.795) | - | - |

## 3. Confusion Matrix (Registered Basis, n=18,314)

| True \ Pred | safe | gray | spam | attack | Recall | Precision |
|---|---|---|---|---|---|---|
| safe | 3733 | 87 | 11 | 26 | 0.9679 | 0.9676 |
| gray | 27 | 197 | 15 | 6 | 0.8041 | 0.2362 |
| spam | 26 | 49 | 1998 | 139 | 0.9033 | 0.8466 |
| attack | 72 | 501 | 336 | 11091 | 0.9243 | 0.9848 |

## 4. Cross-source holdouts (PLAN C5.E2 — the fairer generalization test)

- E2a nazario: attack recall 0.2154 (328/1523)
- E2b nigerian_5: attack recall 0.0269 (88/3274)
- MRL 256-d accuracy 0.9212 vs 768-d 0.9293 (registered basis)

## 5. Limitations (PLAN C9)

- EG2's head is supervised on in-distribution labels; Jev was zero-shot. E1 favours EG2.
- Corpus era 2003–2008; CEAS_08 label semantics per `SCALE-READINGS.md` §2.
- Subject-hash grouping reduces but does not remove template leakage.

## 6. Deviations

- Harness errata fixed before scoring (2026-10-08): records now hold every eval × basis row as PLAN C8 specifies (previously E1-registered only); the Jev comparison column is recomputed from records (previously a hard-coded 0.599); pre-written takeaway bullets authored before any data were removed and replaced with computed figures.