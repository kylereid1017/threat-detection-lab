# PLAN Addendum — Conjunction Arm (exploratory)

**Status:** Spec frozen 2026-09-17, BEFORE any computation. This is an *exploratory / post-hoc*
analysis on data that already exists (the `jev-20260917T143754Z` run and the committed corpus) —
it is NOT a pre-registered confirmatory experiment. Rationale for freezing the spec anyway: the
reader can see the spec predates the numbers. Every output must be labeled
`post-hoc (spec frozen before computation)`.

## Question

Does adding a **sender-recurrence leg** to the confidence gate change the deployable envelope
(auto-share at safe precision) on this corpus — and how much volume is structurally unreachable
because of first contact?

## Inputs (both committed)

- `records/jev-20260917T143754Z.jsonl` — observations: `email_id`, `confidence`, `label_pred`,
  `label_true`, `latency_ms`, `source`.
- `corpus/email/corpus.jsonl` (sha256 `2b894c7c…`) — `email_id`, `from`, `from_addr`,
  `from_name`, `label`, `source`, file order as committed.

Join on `email_id`; assert 200/200 join before any metric is computed.

## Signals

- **A (confidence):** auto-eligible iff `confidence >= T`. Grid: T ∈ {0.25, 0.30, 0.35};
  0.30 flagged as the cascade-comparison point; 0.35 as the registered two-branch policy point.
  No selection — the full grid is reported.
- **B (recurrence, as-of corpus order):** for message *i*, `H(s)` = multiset of `label_true`
  of EARLIER messages from the same sender key. Key1 = `from_addr`; Key2 = the domain part of
  `from_addr` (sensitivity only).

## Variants

Registered two-branch auto-action rule applies to every variant: auto-act only when
`label_pred ∈ {attack, safe}` (attack → quarantine, safe → deliver); everything else escalates.

- **V0 (baseline):** auto-act iff A.
- **V1 (seen-before):** auto-act iff A ∧ |H(s)| ≥ 1.
- **V2 (prior-agreement):** auto-act iff A ∧ H(s) ≠ ∅ ∧ every label in H(s) == label_pred.

## Metrics (per variant × T × key)

- `auto_share` = auto-acted / 200.
- Dangerous auto-errors: (pred safe ∧ true attack) — delivered attack; (pred attack ∧ true
  safe) — quarantined legitimate. Report exact counts, never rates alone. `pred attack ∧ true spam`
  reported separately as class-confusion residual.
- `first_contact_share`: messages whose sender key has no prior row in corpus order.
- Escalation composition by `label_true` (attack / gray / safe / spam).

## Limitations (stated up front)

- `label_true` as prior history is **perfect memory** — an optimistic upper bound for any
  recurrence leg; real prior dispositions are noisier and adversarially influenceable.
- Corpus file order is only a proxy for arrival order. A fixed-seed shuffled-order sensitivity is
  reported to show order sensitivity.
- n=200; corpus-scoped claims only. Synthetic partition caveats apply (generator home field).

## Handlers (falsifiers / outcomes that are still publishable)

- If V2 auto_share collapses under first-contact prevalence → that is a negative result; report
  it as such with the structural reading.
- If V2 lifts auto-precision at modest volume cost → report as a candidate direction for a future
  pre-registered run; no re-tuning claims, no threshold selection.
- Any mismatch in the 200/200 join → stop; nothing reported.

## Outputs

- `docs/research/jev-email-triage/CONJUNCTION-ARM.md` (results, labeled post-hoc) + transcript.
- Optional per-message CSV under `records/` — committed only after review.
