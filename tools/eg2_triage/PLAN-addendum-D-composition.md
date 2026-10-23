# EG2 Triage — Battery D: Jev × EG2 composition (pre-registered)

**Date:** 2026-10-08 · **Status:** frozen before Battery C embeddings exist and before any
composition, stacking, or baseline is computed. Deviations go to a DEVIATIONS section in the
results file. **No new model calls:** Jev inputs are the recorded scale run
`jev-scale-20260917T184615Z`; EG2 inputs are Battery C's out-of-fold (E1) predictions and
its consolidated embeddings.

## D1. Question

Jev is a cheap zero-shot "system one" triage call. EG2 is a self-hosted embedding with a
trained linear head. Does putting them together beat either alone? Specifically:

1. **Confirmation (precision):** when Jev flags an email as an attack and EG2 must agree,
   does attack precision rise, and at what cost in recall?
2. **Veto (safety tail):** of Jev's confident-safe auto-deliveries, how many true attacks
   does EG2 catch, and how much legitimate mail does it hold back?
3. **Gate cascade (economics):** Jev auto-resolves what it is confident about; EG2 decides
   Jev's escalations. What share reaches a human, and how many attacks are auto-delivered?
4. **Stacking:** does adding Jev's recorded outputs as features improve EG2's head?

## D2. Inputs and label basis

- Jev features per email (latest clean observation, as in `score_scale.py`): argmax label,
  `confidence`, the four `disposition.probabilities`, `deception_present.noul`,
  `requests_credentials_or_payment.noul` (missing values → 0.0, counted and reported).
- EG2: Battery C E1 out-of-fold predictions on the **same** fold assignment
  (`StratifiedGroupKFold(5, shuffle=True, random_state=20261008)`, subject-hash groups).
- **Primary basis for Battery D: CEAS-remap** (CEAS_08 → spam; the published post-hoc
  precedent). Reason, declared before data: under the registered basis "attack" includes
  bulk spam, so "attack precision" is not interpretable. EG2 predictions for this basis come
  from Battery C's remap-basis E1 head. The registered basis is reported alongside.
- "Attack" = positive class; everything else (safe/gray/spam) = negative.

## D3. Policies (all computed from records)

| ID | Policy | Flags as attack when |
|---|---|---|
| J | Jev alone | Jev argmax = attack |
| E | EG2 alone | EG2 argmax = attack |
| J∧E | Jev flags, EG2 confirms | both argmax = attack |
| J∨E | Either | either argmax = attack |

**Veto (V):** start from Jev's registered two-branch gate at T=0.30. A Jev confident-safe
delivery is held (escalated instead) when EG2 argmax = attack.

**Cascade (G):** stage 1 = Jev two-branch at T=0.30. Escalated emails go to stage 2 =
EG2 two-branch at threshold T2 ∈ {0.50, 0.90} (both registered; the sweep 0.30–0.99 in
0.01 steps is reported). Still unresolved after stage 2 → human.

## D4. Metrics

- **Per policy:** TP, FP, FN, TN, precision, recall, FPR on negatives, each with a Wilson 95% CI.
- **Projected precision** at attack prevalence 1:1,000 and 1:10,000, from measured recall
  and FPR. This is labeled PROJECTION everywhere.
- **Paired tests:** exact McNemar, J∧E vs J on negatives (FP change) and on positives
  (recall change). Same for E vs J.
- **Veto:** Jev confident-safe deliveries of attacks, before → after. Clean sources
  (nazario ∪ nigerian_5) are reported separately, so the published 60 is recomputed.
  Legitimate deliveries held, as count and % of Jev's correct safe deliveries.
- **Cascade, per T2:** auto-resolved share (stage 1 / stage 2 / total), human share,
  delivered attacks, quarantined safe mail, auto-error rate.
- **Comparison point for the cascade:** EG2 alone with its two-branch threshold chosen on
  a 0.001 grid to match the cascade's human share.

## D5. Stacking and controls (same folds as Battery C E1)

- **S-E:** EG2 768-d only (Battery C head, refit here on the remap basis for parity).
- **S-J:** Jev features only (6 numbers + one-hot argmax).
- **S-EJ:** EG2 768-d concatenated with the Jev features. The Jev features are
  standardized on train folds only.
- **T-IDF (supervised bag-of-words control):** `TfidfVectorizer(ngram_range=(1,2),
  min_df=2, max_features=200000, sublinear_tf=True)` on the same normalized text EG2
  saw. TF-IDF is not truncated (it sees the full text while EG2 sees 512 tokens). This
  asymmetry is declared and favors TF-IDF. The vectorizer is fit on train folds only.
- **Head:** identical to Battery C (`LogisticRegression(C=1.0, class_weight="balanced",
  max_iter=2000)`).
- **Label efficiency:** EG2 head and T-IDF trained on n ∈ {25, 100, 400} examples per
  class, sampled from each train fold (`random_state=20261008`). Each is scored on that
  fold's test rows.
- **Metrics:** attack one-vs-rest PR-AUC and ROC-AUC, macro-F1, clean-source attack
  recall, safe→attack false quarantines.
- **CIs:** 2,000-resample stratified bootstrap (seed 20261008) on PR-AUC differences.

## D6. Criteria (PASS/MISS, remap basis)

| ID | Criterion |
|---|---|
| D-a | J∧E has fewer false positives than J (McNemar exact p < 0.05) **and** J∧E recall ≥ 0.90 |
| D-b | Veto cuts Jev's clean-source confident-safe attack deliveries by ≥ 50% while holding ≤ 1.0% of Jev's correct safe deliveries |
| D-c | S-EJ attack PR-AUC > S-E (bootstrap 95% CI of the difference excludes 0) |
| D-d | S-E attack PR-AUC > T-IDF (bootstrap 95% CI of the difference excludes 0) |

Reported, not criteria: everything else in D4/D5, both bases.

## D7. Limitations (declared)

- **Source confound:** on the remap basis, every attack comes from two sources (nazario,
  nigerian_5) and every negative from others. A supervised head can learn provenance. The
  Battery C cross-source holdouts and the T-IDF control are the checks. Neither removes the
  confound.
- **Supervision asymmetry:** EG2 is supervised, Jev is zero-shot (as in Battery C).
- **Corpus:** era 2003–2008; one operator; single run.
