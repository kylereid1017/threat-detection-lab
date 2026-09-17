# Conjunction Arm — exploratory analysis (post-hoc)

**Label:** post-hoc — spec frozen in `tools/jev_triage/PLAN-addendum-conjunction-arm.md`
*before* computation (2026-09-17). Not a pre-registered confirmatory experiment.
**Reproduce:** `python tools/jev_triage/conjunction_arm.py` (repo root; reads committed
records only; writes nothing).

> **Correction (2026-09-17, post-review):** the original `from_addr`-only sender key was
> absent on public-corpus rows and collapsed all 75 of them into one shared bucket. The
> "Results" table below is preserved as the committed record; the **Correction section
> near the end carries the regenerated numbers**, which supersede the readings that
> depended on the sender keys (first-contact share, V1/V2 volumes, V1/V2 order
> sensitivity). V0 rows, the threshold cliff, the latency block, and the escalation
> composition are sender-independent and unaffected.

## Question

Does adding a sender-recurrence leg to the confidence gate change the deployable envelope
(auto-share at safe precision) on this corpus — and how much volume is structurally
unreachable by any recurrence leg?

## Inputs

`records/jev-20260917T143754Z.jsonl` (200 observations) joined 200/200 to
`corpus/email/corpus.jsonl` (sha256 printed by the script). Labels: 4 × 50
safe/gray/spam/attack.

## Method (as frozen)

- **A (confidence):** auto-eligible iff `confidence >= T`; grid T ∈ {0.25, 0.30, 0.35}.
- **B (recurrence, as-of corpus order):** H(sender) = true labels of earlier messages from
  the same sender. Key 1 = `from_addr`; key 2 = domain part.
- **Variants:** V0 = confidence only (registered two-branch rule: auto-quarantine on
  confident attack, auto-deliver on confident safe; everything else escalates);
  V1 = A ∧ seen-before; V2 = A ∧ prior history exists ∧ every prior label == prediction.
- No selection on results; the full grid is reported.

## Results (counts; n = 200)

| key | variant | T | auto | delivered attacks | quarantined legit | spam-q | escalated | first-contact |
|-----|---------|---|------|-------------------|-------------------|--------|-----------|---------------|
| addr | V0 | 0.25 | 135 | **2** | 0 | 14 | 65 | 126 |
| addr | V0 | 0.30 | 129 | 0 | 0 | 13 | 71 | 126 |
| addr | V0 | 0.35 | 126 | 0 | 0 | 13 | 74 | 126 |
| addr | V1 | 0.25 | 43 | 0 | 0 | 6 | 157 | 126 |
| addr | V1 | 0.30 | 41 | 0 | 0 | 6 | 159 | 126 |
| addr | V1 | 0.35 | 40 | 0 | 0 | 6 | 160 | 126 |
| addr | V2 | 0.25–0.35 | 18 | 0 | 0 | 0 | 182 | 126 |
| domain | V0 | 0.30 | 129 | 0 | 0 | 13 | 71 | 119 |
| domain | V1 | 0.30 | 44 | 0 | 0 | 6 | 156 | 119 |
| domain | V2 | 0.25–0.35 | 20 | 0 | 0 | 0 | 180 | 119 |

(Full 18-cell grid in script output; domain-key V0 identical to addr except first-contact 119.)

## Readings

1. **The safety envelope cannot be raised by recurrence.** 63% of this corpus (126/200) is
   first-contact sender traffic — no recurrence leg can touch it. Confidence-only already
   auto-resolves 64.5% at zero dangerous errors; adding recurrence can only *sharpen* the
   auto-handled set while shrinking it: V1 → 20.5% auto (zero dangerous, 6 class-confusions),
   V2 → 9% auto (zero dangerous, zero confusions). This mirrors the structural first-contact
   ceiling documented in the queue-triage setting (78–85% unreachable there; 63% here — the
   bill scales with traffic mix, not implementation).
2. **The threshold cliff is visible.** At T=0.25 the gate auto-delivers 2 attacks
   (`zoom-billing.example` @ 0.25, `netshield-secure.example` @ 0.29 — both predicted safe).
   The registered 0.30 threshold sits immediately above the observed miss band (misses
   self-flagged ≤ 0.32); 0.35 loses another 3 messages of auto-share for no safety gain.
   The gate's safety property is real but local to its threshold — quote it with the band.
3. **Order sensitivity is a first-class caveat.** V0 is order-invariant (129); V1 is stable
   under shuffle (41 → 41); **V2 collapses (18 → 1, seed 7)** — its volume under corpus order
   is an artifact of same-class clustering, not a property transferable to arrival streams.
   V2's zero-error result is reported as observed, not as a deployable claim.
4. **Escalation composition at V0/T=0.30 (addr):** 71 escalated = 8 attacks, 21 gray,
   35 spam, 7 safe. The escalated slice carries the entire attack burden plus the ambiguity.

## Latency (same run; sequential single client)

Overall p50 224.8 ms / p95 369.2 ms / max 842.0 ms. Per-partition p50 spans 221–247 ms,
p95 spans 270–331 ms (synthetic n=115; spamassassin partitions n=25 each; hand-authored
n=10). Sequential single-client timing — throughput under concurrency is unmeasured.

## Correction (2026-09-17, post-review)

**Root cause.** The script built sender keys from `from_addr` only. Public-corpus rows
carry no `from_addr` (their sender lives in the display `from` header), so all 75
public rows fell into one shared "" bucket: their real senders were never keyed, and
every public row after the first was falsely "seen-before". Every figure that depends
on sender keys was affected — first-contact counts, V1/V2 volumes, and the V1/V2
order-sensitivity check. V0 rows, the threshold cliff, the latency block, and the
escalation composition are sender-independent and unchanged.

**Fix.** `sender_key()` now falls back to parsing the address out of `from`
(`Name <addr>` → `addr`), which was available in the spec's input list. The script is
the regenerated artifact; **every corrected number below comes from re-running it.**

| key | variant | T | auto | delivered attacks | quarantined legit | spam-q | escalated | first-contact |
|-----|---------|---|------|-------------------|-------------------|--------|-----------|---------------|
| addr | V0 | 0.25 | 135 | **2** | 0 | 14 | 65 | 190 |
| addr | V0 | 0.30 | 129 | 0 | 0 | 13 | 71 | 190 |
| addr | V0 | 0.35 | 126 | 0 | 0 | 13 | 74 | 190 |
| addr | V1 | 0.25–0.35 | 4 | 0 | 0 | 0 | 196 | 190 |
| addr | V2 | 0.25–0.35 | 4 | 0 | 0 | 0 | 196 | 190 |
| domain | V0 | 0.30 | 129 | 0 | 0 | 13 | 71 | 170 |
| domain | V1 | 0.25 / 0.30 / 0.35 | 15 / 14 / 14 | 0 | 0 | 1 | 185/186/186 | 170 |
| domain | V2 | 0.25–0.35 | 6 | 0 | 0 | 0 | 194 | 170 |

Order sensitivity, corrected (key=addr, T=0.30, corpus order → seed-7 shuffle):
V0 129 → 129; **V1 4 → 4; V2 4 → 4** (order-stable).

**Revised readings (supersede Results readings 1–3 where they differ).**

1. **First contact is ~95% (190/200) by address and ~85% (170/200) by domain** — the
   original 63% figure undercounted public-mail sender diversity by collapsing it into
   one bucket. Sender-recurrence legs are structurally near-inert on this corpus:
   V1/V2 can auto-act on at most ~2% (address) / ~3–7% (domain) of volume. The
   queue-triage comparison stands and sharpens: first-contact walls of this kind
   (78–85% unreachable there; 95% here) are a property of the traffic mix, and here
   the wall is higher.
2. **The corrected V1/V2 order check is stable (4 → 4).** The earlier "V2 collapses
   18 → 1 under shuffle" finding is superseded — that instability was itself an
   artifact of the shared bucket. The methodological requirement is unchanged:
   order/permutation controls remain mandatory for recurrence-dependent signals —
   they are what surfaced this defect chain.
3. Unchanged: the threshold cliff (T=0.25 auto-delivers 2 attacks; registered 0.30
   sits above the observed miss band), the latency block, and the V0/T=0.30 escalation
   composition.

This correction supersedes the 63%-first-contact reading circulated in the 2026-09-17
session report. The corrected conclusion for the recurrence arm is stronger and
simpler: on this corpus there is almost nothing for a recurrence leg to reach.

## Limitations

- `label_true` as prior history = perfect memory; optimistic for any recurrence leg.
- Corpus order as arrival proxy; seed-7 shuffle sensitivity reported above.
- n=200; V2 cells as small as 18 (1 under shuffle).
- Synthetic partition = generator home field; corpus-scoped claims only.
- Exploratory (post-hoc); changes nothing in the registered results.

## Files

- Spec: `tools/jev_triage/PLAN-addendum-conjunction-arm.md` (frozen before computation)
- Script: `tools/jev_triage/conjunction_arm.py` (regenerates the corrected grid in the
  Correction section; the original defective join is described there)
