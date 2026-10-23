# EG2 Triage — Batteries V (vision-LLM comparator) and X (cross-dataset) — pre-registered

**Date:** 2026-10-09 · **Status:** frozen before any vision-LLM call, before the Phishpedia
archive is opened, and before any cross-dataset score. Deviations go to the results file.
**Builds on:** Battery A (`PLAN-addendum-A-urls.md`) — same 1,008-site sample, same EG2 arms.

## Questions

- **V:** Would a general vision LLM, shown the same screenshot (and URL) zero-shot, match
  EG2's trained probe? This is the obvious "why not just ask an LLM?" comparator.
- **X:** Does the EG2 probe, trained on this one 2026 dataset, still catch phishing from an
  independent, older source (Phishpedia, USENIX Security 2021)? This includes phishing hosted
  on shared hosting, site builders and shorteners, the slice Battery A had only n = 26 of.

## Battery V — vision LLM, zero-shot

**Model and request**

- Model: `claude-haiku-4-5` via the Messages API.
- Request: `temperature=0`, `max_tokens=128`, and a structured output (`output_config.format`,
  JSON schema) with fields `verdict` ∈ {phishing, legitimate} and `p_phishing` (a number,
  clipped to [0, 1]).
- One call per site per arm. Up to 4 concurrent requests, with retries on 429/5xx.

**Image:** the screenshot resized to 1092 px wide (aspect kept), JPEG quality 85.

**Prompt (fixed, verbatim in the harness):**

> System: "You are a security analyst reviewing web pages. Decide whether the page is
> phishing (it impersonates a brand, service, or login to obtain credentials, payment, or
> personal data, or is otherwise deceptive or malicious) or legitimate. Give p_phishing as
> your probability that it is phishing."
>
> User: V2 shows the screenshot alone. V3 shows the screenshot plus the line "URL: {url}".

**Arms**

| Arm | Input | Sample |
|---|---|---|
| V2 | Screenshot only | Battery A sample (336 phishing / 672 legitimate) |
| V3 | Screenshot + URL | Battery A sample, plus the Battery X test set |

**Comparator:** EG2 A3 out-of-fold predictions from Battery A records (CV-G).

**Metrics**

- Recall, FPR and precision (Wilson CIs) at the model's verdict.
- ROC-AUC and PR-AUC on `p_phishing`.
- Exact McNemar test, V3 vs A3 at threshold 0.5, on positives and negatives separately.
- The same slices as Battery A.
- p50 latency and measured cost per 1,000 calls.
- Refusals and invalid outputs are recorded and counted. They are scored as "no verdict"
  (verdict = legitimate, p = 0), which is conservative against the LLM.

**Spend cap:** $5.00 in total across V and X, computed from the returned `usage` at
$1 / $5 per million input / output tokens. The harness stops when the cap is reached.

**Criteria**

| ID | Criterion |
|---|---|
| V-a | Non-inferiority: A3 PR-AUC − V3 PR-AUC has a bootstrap 95% CI lower bound > −0.02 (EG2 is not materially worse than the LLM) |
| V-b | A3 has fewer false positives than V3 at the default operating point (exact McNemar test on negatives, p < 0.05) |

## Battery X — cross-dataset generalization

**Test data:** Phishpedia `phish_sample_30k.zip` (Google Drive id
`12ypEMPRQ43zGRqHGut0Esq2z5en0DH4g`). Only screenshots and URL metadata are read. HTML is
never extracted to disk.

**Sampling** (seed 20261009, after dropping entries with no readable screenshot or URL,
and deduplicating by exact URL)

- **X-host:** every entry whose URL host matches the Battery A S-host list. If there are
  more than 600, take a random 600.
- **X-rand:** a uniform random 600 of the remaining entries.

**Training:** EG2 heads A1 / A2 / A3, fit on all 1,008 Battery A sites with the registered
head (`C=1.0`, balanced, `max_iter=1000`, seed 42). Test embeddings use the same inputs as
Battery A.

**Thresholds**

- **T1:** 0.5.
- **T2:** the lowest threshold whose Battery A CV-G out-of-fold FPR is ≤ 1%. Declared as an
  approximation, since the full-fit head differs from the fold heads.

**Comparators on the same entries**

- Jev reading the URL alone (Battery A contract).
- V3, the vision LLM (Battery V contract, subject to the spend cap).

**Metrics:** recall with Wilson CI at T1 and T2, for each arm, separately for X-host and
X-rand. Also recall by target brand for the 10 most frequent brands.

**Criteria (CV-G-free; recall only)**

| ID | Criterion |
|---|---|
| X-a | A3 recall on X-rand at T1 ≥ 0.80 |
| X-b | A3 recall on X-host at T1 ≥ 0.80 (descriptive only if n < 50) |
| X-c | A3 recall > Jev recall on X-rand and on X-host |

## Limitations (declared)

- **Recall only for X.** X contains no legitimate pages, so false alarms come only from
  Battery A.
- **Era gap.** Phishpedia is from 2019–2020 and Battery A training data from 2026. The two
  capture pipelines differ, so a model that learned capture artifacts will lose recall
  here. That is part of what X tests.
- **Single run.** One vision-LLM model at one prompt, with no prompt tuning.
- **No proxy for our traffic.** No legitimate pages on shared hosts exist in either public
  set.
