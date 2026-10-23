# EG2 Triage — Batteries L, G, N, K, R (pre-registered)

**Date:** 2026-10-09 · **Status:** frozen before any of these analyses are computed.

**Inputs.** Cached embeddings from Batteries A and X. Recorded Battery A, V and X
predictions. The Battery A label audit.

**New model calls.** Only Battery R makes new calls: EG2 re-embeds the transformed
screenshots, plus at most 300 Haiku 5.5 calls under the existing $5 cap.

**Data.**

- **A:** the 2026 benchmark, 336 phishing / 672 legitimate sites. The phishing labels are
  noisy (`AUDIT-A-PHISH.json`).
- **X:** Phishpedia, 987 live, brand-annotated phishing sites.

## L — How many labels does the page reader need?

**Split.** A's sites are divided into train and test halves with
`GroupShuffleSplit(test_size=0.5, random_state=20261009)`. Groups are site directories.

**Training.** For each n ∈ {10, 25, 50, 100, 150} per class, run 20 draws (seeds 0–19).
Each draw samples n phishing and n legitimate sites from the A train half and fits the
registered head (`LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000)`).

**Arms.**

- A3 (URL + screenshot), primary.
- A1 (URL text), comparison.

**Test.**

- Recall on all 987 X sites at threshold 0.5.
- ROC-AUC of X phishing against A test-half legitimate sites.
- Recall on X at the threshold that gives FPR ≤ 1% on the A test-half legitimate sites.
  This threshold is read off the test negatives, so it is declared a ranking view, not a
  deployable threshold.

**Exploratory variant ("visible labels").** The phishing pool is restricted to A train
sites that Haiku 4.5 (V3) called phishing. LLM-filtered labels; reported, not a criterion.

**Report.** Median and 10th–90th percentile across draws.

**Criteria.**

| ID | Criterion |
|---|---|
| L-a | A3 at n = 50: median X recall at 0.5 ≥ 0.90 |
| L-b | A3 at n = 50: median ROC-AUC ≥ 0.95 |

## G — EG2 first, vision LLM only when EG2 is unsure

**Scores.**

- EG2 A3 on A: Battery A out-of-fold probabilities (CV-G).
- EG2 A3 on X: Battery X probabilities from the full-A head.
- LLM verdicts: Haiku 5.5 V3 (primary) and Haiku 4.5 V3.

**Policy.** For (lo, hi) ∈ {(0.2, 0.8), **(0.1, 0.9)** primary, (0.05, 0.95)}:

- p ≥ hi → flag
- p ≤ lo → clear
- otherwise → use the LLM verdict

**Metrics.**

- Share of pages sent to the LLM (A ∪ X, and each set alone).
- Recall on X.
- FPR on A legitimate sites.
- Recall on A phishing (noisy labels; reported only).
- The same metrics for EG2 alone at 0.5 and for the LLM alone.

**Criterion.**

| ID | Criterion |
|---|---|
| G-a | With Haiku 5.5 at the primary band, all three hold: FPR on A legitimate ≤ EG2-alone FPR; X recall ≥ LLM-alone X recall; LLM share ≤ 50% |

## N — Explainable, zero-training brand-impersonation flag

**Brand queries.** One text query per Phishpedia brand with ≥ 5 sites in X ("Webmail
Providers" is excluded as generic): `task: search result | query: a {brand} login page`,
using the display names in the harness. Images are scored with the A2 (screenshot-only)
embeddings by cosine similarity.

**Official domains.** A fixed brand → official registrable-domain map (in the harness),
plus a label rule for brands with country-code variants (e.g. any `orange.*`). Registrable
domain = the last two labels of the host, or three when the second-level label is in a
fixed list (`co, com, net, org, gov, ac, edu`).

**N1 — brand identification.** Top-1 and top-3 accuracy of the argmax brand on X sites
whose brand is in the query set.

**N2 — impersonation score.** s = the maximum brand similarity if the host is not an
official domain of the argmax brand, else 0. Metrics:

- ROC-AUC of X phishing against A legitimate sites.
- Recall on X at the τ giving FPR ≤ 1% on one half of A's legitimate sites, evaluated on
  the other half (split by seed 20261009).

**N3 — nearest known phishing.** Leave-one-out 1-NN over X screenshot embeddings: how often
the nearest other page shares the brand.

**Criteria.**

| ID | Criterion |
|---|---|
| N-a | N1 top-3 accuracy ≥ 0.70 |
| N-b | N2 ROC-AUC ≥ 0.90 |

## K — Phishing-kit clustering

**Data.** X screenshot (A2) embeddings, 987 pages.

**Method.** Agglomerative clustering, average linkage, cosine distance, at thresholds
**0.10** (primary) and 0.05.

**Reported.**

- Number of clusters, and the share of pages in clusters of size ≥ 2.
- Clusters spanning ≥ 2 registrable domains, with their page share.
- Weighted majority-brand purity.
- Capture-time span of multi-domain clusters, from the archive folder timestamps.

**Criterion.**

| ID | Criterion |
|---|---|
| K-a | Weighted brand purity ≥ 0.90 at the primary threshold |

## R — Robustness to page changes (open weights)

**Sample.** 100 X sites (seed 20261009), drawn from those the full-A EG2 A3 head flags at
0.5.

**Transforms.** Screenshot only; the URL is unchanged.

| Name | Change |
|---|---|
| `jpeg30` | JPEG at quality 30 |
| `half_res` | Downscale ×0.5, then upscale |
| `crop15` | Crop 15% from each border, then resize back |
| `blur2` | Gaussian blur, radius 2 |
| `hue180` | Rotate hue 180° (stress) |
| `mirror` | Horizontal flip (stress) |

**Measurement.** Re-embed with A3 and score with the full-A head. Report the flip rate
(flagged → not flagged) at 0.5 and at T2 (Battery X), and the mean change in score.

**LLM stress check.** Haiku 5.5 V3 on the 100 originals plus `hue180` and `mirror`, at most
300 calls. Report its flip rate.

**Criterion.**

| ID | Criterion |
|---|---|
| R-a | EG2 flip rate at 0.5 ≤ 10% for each of `jpeg30`, `half_res`, `crop15`, `blur2` |

**Declared limit.** These are benign perturbations, not a white-box gradient attack. Open
weights make a white-box attack possible, and it would be stronger.

## Gallery (illustrative, not a test)

Examples are chosen by these rules, taking the first match in seeded random order
(seed 20261009):

1. **Trusted-host phishing** (X): Jev ≠ attack, and EG2, Haiku 4.5 and Haiku 5.5 all
   flag it.
2. **Brand impersonation** (X): the highest N2 score with a correct N1 brand.
3. **One kit** (K): the largest multi-domain cluster, shown as 3 pages.
4. **Hard negative** (A legitimate login/signup/payment page): Jev = attack; all page
   readers clear it.
5. **Label noise** (A phishing): an audit item in `dead_parked_blank`.
6. **A miss** (X): phishing that every page reader missed, if one exists.

URLs are shown defanged. Captions state which reader said what. Labeled as illustrative.
