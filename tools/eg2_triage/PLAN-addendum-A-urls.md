# EG2 Triage — Battery A: URL + screenshot re-run with records (pre-registered)

**Date:** 2026-10-08 · **Status:** frozen before any new embedding, Jev call, or score.

**Why this exists.** The first URL benchmark (`benchmark_urls.py`, commit `d1aa508`) was
not pre-registered and kept no per-sample predictions. Without those, paired tests, error
overlap, and composition can't be computed, and some claims in its report can't be traced
to a record ("Arm 3 caught 7 of those 23"; the shared-hosting examples; GPU latency). This
addendum registers a re-run on the **identical sample** that keeps every prediction. The
original JSON stays as-is.

## A1. Sample

Same loader and sampling as `benchmark_urls.py`: rows with a URL and an image that exists,
all phishing rows, legitimate rows sampled with `n=672, random_state=42`. The sample is
then shuffled with `random_state=42`. Expected size: 336 phishing / 672 legitimate. The
run aborts on any other count.

## A2. Arms (EG2 frozen, fp32 CPU, 768-d, L2-normalized)

| Arm | Input |
|---|---|
| A1 URL | `task: classification \| query: url: {url}` |
| A2 Image | `<|image|>` + screenshot, no prefix |
| A3 Interleaved | `task: classification \| query: url: {url} <|image|>` + screenshot |
| A4 Late fusion (concat) | [A1 ; A2] (1,536-d) |
| A5 Late fusion (score avg) | mean of A1 and A2 out-of-fold P(phish) |
| A0a Confound: file size | `log(file_size_bytes)` alone |
| A0b Confound: capture metadata | `log(file_size_bytes)`, `redirect_count`, `log1p(page_load_time_ms)` |
| J Jev on the URL (zero-shot) | Jev scale contract (same questions). State = `From: (unknown)\nSubject: (none)\n\n{url}` |

- **Head:** `LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000,
  random_state=42)`, as in the original.
- **Jev score:** `disposition.probabilities.attack`. Flag = argmax is attack.
- **Jev records:** append-only and resumable. Expected cost is under $0.10.

## A3. Cross-validation

- **CV-R (reproduction):** `StratifiedKFold(5, shuffle=True, random_state=42)`, threshold 0.5.
  **Check:** the A1–A3 confusion matrices must equal the committed JSON exactly. A
  mismatch is logged as a deviation and does not stop the run.
- **CV-G (primary for every new claim):** `StratifiedGroupKFold(5, shuffle=True,
  random_state=20261008)`. Group = site directory (second segment of `file_name`), so
  several pages of one site can't straddle folds.

## A4. Statistics (CV-G unless stated)

- **CIs:** Wilson 95% on recall, FPR, and precision.
- **Paired tests:** exact McNemar on positives and on negatives separately, for A3 vs A1,
  A3 vs A2, A3 vs A4, and A2 vs A1.
- **AUC differences:** paired stratified bootstrap (2,000 resamples, seed 20261008) on
  ROC-AUC and PR-AUC for the same pairs.
- **Operating points:** TPR at FPR ≤ 1%, and the highest TPR with zero false positives.
- **Complementarity:** error-overlap table (A1 misses caught by A2 and vice versa, plus
  double faults), and within-class Spearman ρ of A1 vs A2 out-of-fold scores.
- **Calibration:** Brier score and 10-bin equal-mass ECE per arm.

## A5. Slices (definitions fixed here, before data)

- **S-host (shared hosting, builders, shorteners).** The URL host ends with one of:
  `sites.google.com, docs.google.com, forms.gle, drive.google.com, storage.googleapis.com,
  canva.site, my.canva.site, canva.com, sharepoint.com, 1drv.ms, onedrive.live.com,
  azurewebsites.net, web.app, firebaseapp.com, pages.dev, workers.dev, r2.dev, vercel.app,
  netlify.app, github.io, webflow.io, wixsite.com, weebly.com, glitch.me, square.site,
  godaddysites.com, blogspot.com, typeform.com, jotform.com, notion.site, dropbox.com,
  box.com, wetransfer.com, linktr.ee, flowcode.com, qrco.de, bit.ly, tinyurl.com, t.co,
  clk.li, 2no.co, rebrand.ly, cutt.ly, is.gd, ow.ly, s.id, shorturl.at, rb.gy, t.ly`.
  Recall and FPR per arm on this slice. If n < 20 for either class, the slice is
  descriptive only.
- **S-hardneg.** Legitimate rows with page_type ∈ {login, signup, payment, checkout}.
  FPR per arm.

## A6. Composition (Jev on URL × EG2)

- **Policies:** J, A3, J∧A3, J∨A3 (as Battery D), plus **render-gate**: EG2 (A3) is
  computed only for URLs Jev did not call confident-safe at T=0.30. Jev confident-safe
  URLs are delivered without a render.
- **Metrics:** render share, recall, FPR, and phishing URLs delivered without a render.

## A7. Criteria (PASS/MISS, CV-G)

| ID | Criterion |
|---|---|
| A-a | Reproduction: CV-R A1–A3 confusion matrices equal the committed JSON |
| A-b | A3 has fewer false positives than A1 (McNemar exact p < 0.05) |
| A-c | A3 beats A2, the best single arm, on false positives or on misses (McNemar exact p < 0.05 on either) |
| A-d | A3 PR-AUC > A4 late fusion (bootstrap 95% CI of the difference excludes 0); tests whether the shared space matters |
| A-e | Confound probe A0a ROC-AUC < 0.75. Otherwise the image arm is flagged as partly a page-complexity detector |
| A-f | A3 recall > Jev-on-URL recall, at an A3 threshold whose FPR ≤ Jev's FPR |

## A8. Limitations (declared)

- One public dataset, captured in one session (2026-07-16). Legitimate pages were captured
  before phishing pages, so capture time separates the classes perfectly. A0 covers the
  measurable side of that, not all of it.
- 672 negatives: the smallest resolvable FPR is 0.15%. No claim below that is possible
  from this data.
- Jev-on-URL gives Jev only the link, with no email context. That is the scenario under
  test, not Jev's normal input.
