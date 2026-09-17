# Scale battery — sender-recurrence conjunction arm (post-hoc; spec frozen before computation)

**Registration.** `PLAN-addendum-scale.md` A8.2 (written 2026-09-17, before any scale computation).
**Run basis.** `jev-scale-20260917T184615Z` (18,314 scored; sha256 in `RESULTS-SCALE.md` provenance).
**Inputs.** Scale records + `corpus/email/scale/scale-corpus.jsonl`
(sha256 `ede15ebe5eef62e465fd0184e792c520a3c7b75c279c87ccc9b746f44234343a`).
**Sender key.** Address parsed from `from` (corrected convention — see the Correction section
of `CONJUNCTION-ARM.md`); 771 no-sender rows are excluded from recurrence keys and counted
(analyzed n = 17,543).
**Declared stand-ins.** Ground-truth labels stand in for prior human dispositions
(perfect-information bound). **Order control.** Fixed-seed (7) shuffle; both orders reported.

## Results (threshold grid)

| key | variant | T | auto | auto % | delivered attacks | quarantined legit | spam-q | escalated | first-contact |
|---|---|---|---|---|---|---|---|---|---|
| addr | V0 | 0.25 | 10,829 | 61.7 | 1,316 | 4 | 422 | 6,714 | 13,559 |
| addr | V0 | 0.30 | 10,726 | 61.1 | 1,300 | 3 | 422 | 6,817 | 13,559 |
| addr | V0 | 0.35 | 10,493 | 59.8 | 1,251 | 3 | 401 | 7,050 | 13,559 |
| addr | V1 | 0.25 | 3,306 | 18.9 | 16 | 3 | 36 | 14,237 | 13,559 |
| addr | V1 | 0.30 | 3,256 | 18.6 | 15 | 2 | 36 | 14,287 | 13,559 |
| addr | V1 | 0.35 | 3,208 | 18.3 | 15 | 2 | 32 | 14,335 | 13,559 |
| addr | V2 | 0.25 | 3,198 | 18.2 | 0 | 0 | 0 | 14,345 | 13,559 |
| addr | V2 | 0.30 | 3,150 | 18.0 | 0 | 0 | 0 | 14,393 | 13,559 |
| addr | V2 | 0.35 | 3,108 | 17.7 | 0 | 0 | 0 | 14,435 | 13,559 |
| domain | V0 | 0.30 | 10,726 | 61.1 | 1,300 | 3 | 422 | 6,817 | 8,730 |
| domain | V1 | 0.25 | 6,541 | 37.3 | 109 | 3 | 271 | 11,002 | 8,730 |
| domain | V1 | 0.30 | 6,479 | 36.9 | 105 | 2 | 271 | 11,064 | 8,730 |
| domain | V1 | 0.35 | 6,395 | 36.5 | 101 | 2 | 255 | 11,148 | 8,730 |
| domain | V2 | 0.25 | 4,724 | 26.9 | 1 | 0 | 0 | 12,819 | 8,730 |
| domain | V2 | 0.30 | 4,672 | 26.6 | 1 | 0 | 0 | 12,871 | 8,730 |
| domain | V2 | 0.35 | 4,617 | 26.3 | 0 | 0 | 0 | 12,926 | 8,730 |

Order sensitivity (key=addr, T=0.30; corpus order -> seed-7 shuffle):
V0 10,726 -> 10,726 · V1 3,256 -> 3,251 · V2 3,150 -> 3,066.

Latency (sequential single client), overall: n=18,314 p50 220.3 / p95 349.4 ms.
Per source (p50/p95 ms): ceas_08 214.9/331.0 · ling 224.1/326.1 · nazario 213.2/314.1 ·
nigerian_5 219.0/325.4 · easy_ham 249.0/409.5 · easy_ham_2 219.2/343.2 ·
hard_ham 221.5/314.7 · spam 219.8/326.1 · spam_2 222.0/347.5. (One slow-call outlier:
max 21.3 s; retained.)

## Readings (post-hoc)

1. **First contact: 77.3% by address (13,559/17,543); 49.8% by domain (8,730).** At scale,
   recurrence volume genuinely exists (unlike the 200-email corpus's 95% first-contact), and
   every recurrence leg now has real reachable volume.
2. **Prior-agreement (V2) auto-resolves 18.0% of analyzed volume (3,150) with zero delivered
   attacks, zero quarantined legitimate mail, zero spam leaks at the registered threshold.**
   The yield is measured on public data at n = 17,543 analyzed rows. (Perfect-information caveat: the yield is an upper
   bound, not a deployable number.)
3. **Seen-before-only (V1) is not safe alone:** 15 delivered attacks (address) / 105 (domain)
   at T=0.30. Recurrence alone is not the gate; agreement with priors is.
4. V0 (confidence-only) delivers 1,300 attacks at T=0.30 on this basis (1,301 on the
   all-rows basis; the difference is one no-sender row). V2 removes all of them by
   construction of the conjunction.
5. **Order-stability:** V0 exact; V1 within 5 rows; V2 within 84 rows (2.7% drift). The
   200-corpus V2 instability was the `from_addr` defect; with the corrected sender key the
   conjunction arm is order-stable at scale.
6. Dangerous-count terms inherit the CEAS_08 label caveat documented in `SCALE-READINGS.md`
   Section 2; the structural readings above (first-contact, reachability, V2 construction)
   do not depend on it.

## Limitations

- Perfect-information stand-in for prior dispositions; single shuffle seed.
- Registered labels used as-is; CEAS_08 contamination applies to dangerous-count columns.
- No-sender rows (771) excluded from recurrence keys; their history is unresolvable by design.
- Post-hoc relative to the scale battery; spec frozen before computation (A8.2).

**Reproduce:** `python tools/jev_triage/conjunction_arm_scale.py`
