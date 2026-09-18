# Jev Email Triage — Experiment Report

**Date:** 2026-09-17 · **Status:** complete — all four Claude tiers measured (routed via Nous Portal); Fable 5.1 on a frozen 60-email subset.
**Design (pre-registered):** `tools/jev_triage/PLAN.md` · **Auto-generated tables:** `RESULTS.md` · **Cost model:** `COST_MODEL.md` (measured) and `COST_PROJECTION.md` (frozen pre-measurement artifact) · **Raw records:** `records/*.jsonl`

All figures below are recomputed from the append-only raw records by
`tools/jev_triage/score.py` (reconciliation: unique clean ids = corpus size for every run, PASS; errored rows stay in the ledger and are retried in place; four audit exclusions applied to every model, `corpus/email/corpus-audit.json`).

---

## Executive summary

1. **Jev alone classifies email fast and almost free — but below the pre-registered
   attack bar.** 65.3% exact-label accuracy; **attack recall 0.860** (bar: 0.90);
   safe recall 0.880; spam 0.630; gray 0.240. 224ms p50, **$0.041 per 1,000 emails**
   (~$0.000041/email).
2. **Against DeepSeek it is a trade, not a win.** DeepSeek: 74.0% exact, attack recall
   0.980, 894ms, $0.098/1k. **On the real (non-generated) public mail both models tie at
   0.514** — the overall gap comes from the synthetic set (DeepSeek 0.868 vs Jev 0.737),
   where the generator's family (DeepSeek) plausibly has a home-field advantage. On
   generator-independent evidence Jev is ≈ accuracy-comparable at 1/2.4 the cost and
   1/4 the latency.
3. **Every Jev attack miss was self-flagged uncertain (confidence ≤ 0.32).** All 7
   misses sit far below any sane auto-action threshold. The two attacks called *safe*
   (at 0.25 / 0.29) are exactly the cases a confidence gate exists to catch.
4. **The cascade's registered safety constraint FAILED as written** (auto-decided
   exact-label error ≤ 2% — unreachable because any benign misroute at the same weight as
   a dangerous one; best case ~20% at high thresholds). Under a harm-weighted
   decomposition it succeeds: at threshold 0.30, **64.8% of traffic auto-decided with
   zero attack→safe deliveries and zero safe→attack quarantines**; the residual auto
   errors are spam→attack (12) and gray→safe (27) — junk into quarantine, ambiguous mail
   delivered as safe.
5. **Routing economics are tier-dependent, and now measured on both ends.** In front of
   DeepSeek (already $0.098/1k) the cascade saves ~26% at an accuracy *loss* — dominated,
   don't build it. In front of Claude tiers, measured at t=0.30: **−63% (Haiku 4.5),
   −66% (Sonnet 5), −65% (Opus 5)** vs pure tier cost, with zero dangerous misroutes.
   Measured Claude economics confirmed the projection's direction and slightly
   exceeded it (projected 59/62/64% → measured 63/66/65%).
6. **The bigger measured surprise: on this corpus, Claude tier buys almost no accuracy
   over DeepSeek Flash.** Haiku 4.5 0.724, Sonnet 5 0.704, Opus 5 0.745, Fable 5.1
   0.746 — against DeepSeek 0.740 and Jev 0.653. Attack recall is where the tiers
   separate (Haiku 0.94 / Sonnet 0.98 / Opus 0.98 vs DeepSeek 0.98). Cost per 1k spans
   60× ($0.098 → $5.82) for ≤5 points of accuracy on this distribution. Caveat: 2003-era
   real mail + synthetic limits what any of these numbers can claim.
7. **The `gray` class is the taxonomy's weak point, not the models'.** No model
   identifies the 2003-era "hard ham" ambiguity band (Jev 0.04, DeepSeek 0.00, Claude
   tiers 0.00–0.12). With hard_ham relabeled `safe` (pre-registered sensitivity):
   Opus 0.847, Fable 0.881, DeepSeek 0.827, Haiku 0.796, Jev 0.750, Sonnet 0.750.

## Pre-registered criteria — outcome

| # | Criterion | Outcome |
|---|---|---|
| 1 | Attack recall ≥ 0.90 | **MISS** — 0.860 (7 misses; all confidence ≤ 0.32) |
| 2 | Jev ≤ $0.001/email | **PASS** — $0.000041/email |
| 3 | Cascade ≥ 60% auto-decided, ≤ 2% wrong (exact) | **MISS as registered** (any threshold ≥ 20% exact-label error). Passes under post-hoc harm-weighted view at t=0.30: 64.8% auto, zero dangerous misroutes. |
| 4 | Cascade ≤ 20% of pure-LLM cost at equal accuracy | **MISS** on DeepSeek (−26% savings, lower accuracy). **Measured vs Claude: −63/−66/−65% savings but at −4.5/−3.6/−4.1 points final accuracy** (cascade final 0.653/0.668/0.704 vs pure 0.724/0.704/0.745 for Haiku/Sonnet/Opus). Savings exceed the projected 62%; the "equal accuracy" clause fails — the escalation budget buys accuracy, it doesn't preserve it for free. |

Three misses on a demanding pre-registration, reported as such. The operational
decompositions and tier-dependence (summary #5) are the actionable findings.

## Measured model comparison (196 scored emails each, identical inputs; Fable on a 59-scored subset)

| model | exact acc | attack recall | safe recall | spam recall | gray recall | p50 ms | $/1k |
|---|---|---|---|---|---|---|---|
| Jev (`jev-1.13.0`) | 0.653 | 0.860 | 0.880 | 0.630 | 0.240 | 224 | $0.0414 |
| DeepSeek V4.1 Flash | 0.740 | 0.980 | 0.820 | 0.891 | 0.280 | 894 | $0.0983 |
| Claude Haiku 4.5 (Portal) | 0.724 | 0.940 | 0.860 | 0.717 | 0.380 | 1074 | $0.7818 |
| Claude Sonnet 5 (Portal) | 0.704 | 0.980 | 0.740 | 0.826 | 0.280 | 2533 | $2.0630 |
| Claude Opus 5 (Portal) | 0.745 | 0.980 | 0.980 | 0.717 | 0.300 | 3176 | $5.8234 |
| Claude Fable 5.1 (Portal, subset) | 0.746 | 1.000 | 1.000 | 0.786 | 0.200 | 5029 | $9.0964 |

Claude calls ran through a local proxy to Nous Portal (OpenAI-compatible route
to Anthropic models) so the unmeasured half of this experiment could be bought with a
$3.36 Portal balance instead of a direct-API top-up. Token counts and per-call billed
cost are the provider's own figures; spot checks match Anthropic list prices exactly.
Latency includes the local proxy hop (millisecond-scale; each call is multi-second
regardless). A routing caveat worth one line: Portal-mediated is not byte-identical to
direct-API, but it is the same models at the same billed prices.

### Per-source accuracy (generator-bias check)

| group | n | Jev | DeepSeek |
|---|---|---|---|
| Public 2003 real mail | 72 | 0.514 | 0.514 |
| Synthetic (generated by DeepSeek) | 114 | 0.737 | 0.868 |
| Hand-authored attacks | 10 | 0.700 | 0.900 |

The synthetic-set gap is consistent with generator familiarity; the tie on real mail is
the fairer signal, with the caveat that both models are weak (≈0.51) on 2003-era mail.

### Jev calibration (accuracy by confidence decile)

Monotone rising through 0.8 (0.2→0.32, 0.5→0.63, 0.7→0.88) — usable as a gate.
**The top decile (0.9–1.0, n=56) is only 0.804 accurate** — mild overconfidence at the
very top; don't treat 0.95+ as near-certainty. All attack misses sat ≤ 0.32.

### Auxiliary nouls (mean value by true label)

| label | deception_present | requests_credentials_or_payment |
|---|---|---|
| safe | 0.077 | 0.040 |
| gray | 0.210 | 0.108 |
| spam | 0.518 | 0.271 |
| attack | 0.669 | 0.574 |

Strong separation — usable as secondary channels (e.g. a `safe` disposition with
`deception_present > 0.5` warrants review) at zero extra call cost.

## Cascade economics (measured, both DeepSeek and Claude)

**Jev → DeepSeek:** at t=0.30, 64.8% auto-decided, cascade $0.0727/1k vs pure
$0.0983/1k (−26%) with final accuracy 0.679 vs 0.740 pure. **Dominance check: the
cascade is worse accuracy at every threshold; at useful thresholds it is not even
cheaper.** At DeepSeek-level prices, Jev-in-front is not worth the complexity.

**Jev → Claude tiers (measured; escalated traffic answered by real Claude runs on the
same corpus):** cost per 1k emails, pure vs cascade at t=0.30 (64.8% auto-decided):

| tier | pure $/1k | cascade $/1k | savings | projected | cascade final acc | pure acc |
|---|---|---|---|---|---|---|
| Haiku 4.5 | $0.7818 | $0.2914 | **63%** | 59% | 0.653 | 0.724 |
| Sonnet 5 | $2.0630 | $0.6981 | **66%** | 62% | 0.668 | 0.704 |
| Opus 5 | $5.8234 | $2.0494 | **65%** | 64% | 0.704 | 0.745 |

(Fable 5.1 excluded — subset run, no full-corpus cascade. Full sweeps in `RESULTS.md`.)

The honest trade: at t=0.30 the cascade pays ~2–7 accuracy points for 63–66% savings;
pure Claude pays ~1.6–2.8× the cascade price to get those points back. **Two thirds of
traffic is answered in ~0.22s instead of ~1.1–5.9s.**

## What this means for the prototype (and what is claimable)

**Defensible to claim today:**
- "A System One model fronts email triage at ~$0.04/1k emails and 0.22s/email, auto-handling
  ~65% of traffic with zero dangerous misroutes on a 200-email mixed corpus (real 2003
  public mail + inert synthetic), escalating only uncertainty."
- "Its confidence signal is real: every attack it missed, it flagged below 0.32."
- "Measured against live Claude tiers: 63–66% cost reduction (Haiku/Sonnet/Opus) at the
  operational threshold with zero dangerous misroutes; attack recall of escalated traffic
  0.94–0.98."
- "On this corpus, model tier bought almost no accuracy: 60× price span ($0.098→$5.82/1k)
  moved exact accuracy by ≤5 points — routing and latency economics dominate model choice."

**Not claimable (yet):** real-world efficacy (synthetic + 2003-era mail), Portal-vs-direct
API parity (within-noise assumption, not measured side-by-side), production readiness at
any specific threshold.

## Next steps (ranked)

1. **Optional direct-API parity check:** re-run the Sonnet subset against direct Anthropic
   access (~$5 top-up) and diff against the Portal run — closes the one provenance caveat
   on the Claude tables.
2. **Fix the gray class**: split "legitimate but spam-looking" (hard_ham-like) from "true
   ambiguity"; consider reporting 4-way + a separate `needs_review` noul (the aux nouls
   already separate the classes better than the gray label does).
3. **Modern-mail corpus**: a consented, read-only export (no live inbox hookup) would
   test the 2026 distribution; the current corpus cannot speak to it.
4. **Threshold policy**: adopt t=0.30 with the harm-weighted rule (zero attack→safe /
   safe→attack on auto-decided), re-measured per domain before any deployment.
5. **Repeat-run variance study** before quoting any single number in a deck (single-run
   corpus results carry unstated variance).

## Limitations (carried forward from PLAN.md §9)

- Synthetic accuracy is not evidence of real-world efficacy; inert fixtures prove
  mechanics.
- Public corpus is 2002–2003-era; not a 2026 inbox mix.
- Single run per model; no repeated-measurement study.
- Claude tiers ran routed via Nous Portal (OpenAI-compatible proxy), not direct API;
  billing verified against list prices, behavioral parity assumed not proven.
- Opus (33) and Sonnet (6) rows initially hit the 64-token output cap and were retried
  at 512; error rows remain in the ledger, retries appended (per-row `max_tokens`
  recorded). Fable 5.1 ran a frozen 60-email subset; an earlier Fable pass was retired
  (see `records/retired/README.md`) and its spend is included in the cost ledger.
- Exact-label scoring treats all misroutes equally; harm-weighted view is post-hoc,
  labeled as such.
- Four records excluded via audit (`corpus-audit.json`) from all models uniformly.

## Provenance

- Corpus: `corpus/email/` — lock `email-corpus-lock.json` (tarball SHA-256, seed 20260917),
  generator lock `synthetic-generation-lock.json`, merged hash in `corpus-manifest.json`,
  audit ledger `corpus-audit.json`.
- Runs: `records/jev-*.jsonl` (200) + `records/deepseek-*.jsonl` (200) +
  `records/portal-anthropic_claude-{haiku,sonnet,opus}*.jsonl` (200 each, retries
  appended) + `records/portal-anthropic_claude-fable-5_1-*.jsonl` (60-subset) —
  session spend ledger in `COST_MODEL.md` ($2.96 of a $3.36 Portal balance).
- Reproduce: `fetch_public_corpus.py` → `generate_synthetic.py` → `build_corpus.py` →
  `run_jev.py` → `run_llm.py` (provider deepseek and portal) → `score.py` →
  `cost_model.py` (+ `cost_projection.py` for the frozen pre-measurement numbers).
- Tests: `tests/test_jev_triage_scoring.py` (13 behavioral tests, pure functions).
