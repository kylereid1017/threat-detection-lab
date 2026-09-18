# Scale Battery — Readings (post-hoc interpretation)

Companion to the generated `RESULTS-SCALE.md` (registered output; recompute:
`python tools/jev_triage/score_scale.py`). Everything beyond the registered tables is
**post-hoc interpretation**, labeled as such. The registered criteria are quoted verbatim.

## 1. Registered outcome (as measured, no substitutions)

| id | criterion | actual | result |
|---|---|---|---|
| C1 | attack recall >= 0.90 | 0.480 | MISS |
| C2 | auto-delivered attacks at T=0.30 == 0 | 1,301 | MISS |
| C3 | >= 50% auto at <= 2% auto-error | 60.8% auto / 18.1% error | MISS |
| C4 | <= $0.001/email | $0.000043 | PASS |
| C5 | p50 <= 350 ms; p95 <= 1000 ms | 220 / 349 ms | PASS |
| C6 | every attack miss at confidence < 0.50 | max miss conf 1.0; 6,238 misses | MISS |

n = 18,314 scored; exact accuracy 0.599. Registration: `PLAN-addendum-scale.md` (A7).

## 2. What drove the misses: the CEAS_08 partition (post-hoc)

The attack partition (12,000) = nazario 1,523 + nigerian_5 3,274 + ceas_08 7,203.
Sampling CEAS label-1 rows that Jev called `spam` or `safe` at conf >= 0.9 shows the
partition is not a phishing-email set: the rows are bulk spam (pharma / replica-watch /
window ads), mailer bounces ("WARNING. Mail Delayed ... mail server queue",
NOPAM non-delivery notices), newsletters (CNN.com Daily Top 10) and mailing-list
traffic (an [lwv-healthcare] unsubscribe thread). DeepSeek reads the same rows the same
way — the identical failure mode across models is the signature of label semantics, not
model error. CEAS pred distribution (n=7,203): spam 4,332 · safe 1,253 · attack 1,175 ·
gray 443.

Per-source attack recall as measured:

| source | attack support | recall |
|---|---|---|
| nazario | 1,523 | 0.891 |
| nigerian_5 | 3,274 | 0.987 |
| ceas_08 | 7,203 | 0.163 |

Attack -> safe auto-delivery at T=0.30: 1,301 total — ceas_08 1,241, nazario 48,
nigerian_5 12.

## 3. Post-hoc sensitivity: CEAS_08 re-mapped to `spam` (evident semantics)

Re-scored from the same records with `ceas_08` true labels treated as `spam`
(recomputation only; no re-run).

| metric | registered basis | remap basis |
|---|---|---|
| exact accuracy | 0.599 | 0.7716 |
| attack recall | 0.480 (n=12,000) | **0.9562** (n=4,797) |
| safe recall | 0.917 | 0.9168 |
| auto share @0.30 | 60.8% | 60.8% |
| auto error @0.30 | 18.1% | 28.1% |
| attacks auto-delivered @0.30 | 1,301 | **60** (0.33% of corpus) |

Under the remap basis C1 would pass; C2 still misses (60 != 0). The clean-source residual
is the honest scale finding: **nazario 48/1,523 (3.2%) and nigerian_5 12/3,274 (0.4%)
confident-safe attack misses** — including one nigerian_5 row at confidence 1.000
(scale-08914). The zero-danger property observed on the 200-email corpus does not survive
on clean real phishing at n ~ 4.8k.

## 4. What held at scale

- Latency: p50 220 ms / p95 349 ms (C5 PASS; flat vs 224/369 ms on the 200-email run).
- Cost: $0.0432 / 1k measured (C4 PASS; flat vs $0.041).
- Calibration: top decile (0.9-1.0) 0.935 accurate at n=6,757; mid deciles 0.24-0.55.
- Safe-class: precision 0.697, recall 0.917 (safe -> attack: 7 rows).

## 5. Comparator (A8.1, registered secondary arm)

Common subset n=2,000 (attack support 1,310), both models on their frozen contracts:

| model | accuracy | attack recall | p50 | $/1k |
|---|---|---|---|---|
| jev (jev-latest) | 0.472 | 0.292 | 222 ms | 0.0425 |
| deepseek-flash | 0.421 | 0.181 | 833 ms | 0.1026 |

Both models fall to the same CEAS rows; Jev leads on recall at ~41% of the cost.
The subset inherits the label caveat (Section 2).

## 6. Conjunction arm (A8.2)

See `CONJUNCTION-ARM-SCALE.md` (post-hoc; spec frozen before computation). Headline:
first contact 77.3% (address) / 49.8% (domain); prior-agreement conjunction auto-resolves
18.0% of analyzed volume with zero dangerous misroutes on registered labels; order-stable.

## 7. Standing limitations

- CEAS_08 label semantics (Section 2): the registered-basis aggregate is dominated by a
  partition that is not phishing; do not quote the raw aggregate without this context.
- Prior-agreement arms use ground-truth labels as prior dispositions
  (perfect-information stand-in) — optimistic bounds.
- Era: sources span 2003-2008; no modern inbox. Single run; sequential latency basis.
- 771 no-sender rows (ling; part of nigerian_5) are excluded from recurrence analyses
  only; they remain scored in the battery.

*Basis note: "delivered attacks" counts rows with true=attack, pred=safe, conf >= T under
the two-branch policy; attack->spam misses escalate rather than deliver.*
