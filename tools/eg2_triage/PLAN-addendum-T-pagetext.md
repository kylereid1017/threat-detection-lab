# EG2 Triage — Battery T: does page *text* close the gap? (pre-registered)

**Date:** 2026-10-09 · **Status:** frozen before any page text is extracted or scored.

**Question.** On trusted-host phishing, the link reader (Jev) flagged 37.5% while page readers
that saw the screenshot caught 94–99% (Batteries V, X). The inputs were unequal: Jev saw only the
link. Is the gain from *seeing* the page, or from having the page's content at all? If giving Jev
the page's visible text closes most of the gap, a text-only model needs a page-text input, not
vision. If it doesn't, the pixels are doing work the words can't.

**Data.** Unchanged from A and X.

- **A:** the 2026 benchmark, 336 phishing / 672 legitimate (`load_sample()`); phishing labels
  noisy (`AUDIT-A-PHISH.json`). Used for false alarms and to train EG2 heads.
- **X:** Phishpedia, 387 trusted-host + 600 random live phishing sites (`sample.json`).

## Page text

Windows' built-in OCR (`Windows.Media.Ocr`, recognizer language en-US, via
`tools/eg2_triage/winocr.ps1`) on every A and X screenshot, as stored. Lines joined with
newlines. No other cleaning. Images larger than the engine's maximum dimension are scaled down to
fit, aspect preserved. Records: `records/ocr-a.jsonl`, `records/ocr-x.jsonl` (path, text, error).

Declared limits: en-US recognition reads Latin-script pages; Cyrillic, CJK and Arabic text is
mostly lost. Text in images (logos) is read only when legible. Reported: share of pages with
empty OCR, per set and class.

**Truncation.** The first 2,000 characters of OCR text, everywhere it is used.

## Arms

| ID | Reader | Input |
|---|---|---|
| J0 | Jev | link only — existing records (`jev-url-20261008T234246Z.jsonl`, `jev-url-x.jsonl`) |
| **J1** | Jev | link + page text (primary) |
| J2 | Jev | page text only, no link |
| E3 | EG2 | URL + screenshot — existing A OOF / X scores |
| E1t | EG2 | URL + page text as one text input, frozen, logistic head (as A1) |
| V3 | Haiku 4.5 / 5.5 | URL + screenshot — existing records |

**Jev states.** Same questions (`run_jev.QUESTIONS`) and model as J0. States:

- J1: `From: (unknown)\nSubject: (none)\n\n{url}\n\n[Text visible on the page at that link, read from a screenshot]\n{text}`
- J2: `From: (unknown)\nSubject: (none)\n\n[Text visible on a linked web page, read from a screenshot]\n{text}`
- Empty OCR → `{text}` is `(no text found)`.

Flag = disposition `attack`, as in A/X. Also reported: the share of each label (safe / gray /
spam / attack).

**E1t.** Text = `PREFIX + url + " | page text: " + text`. Embedded with the A-contract settings
(fp32, normalized). Head and protocol exactly as A1: CV-G out-of-fold on A (same folds), and a
full-A head applied to X; thresholds T1 = 0.5 and T2 = the ≤1% A-FPR threshold from E1t's own A
out-of-fold scores.

## Metrics

Per arm: recall on X-host and X-rand; FPR on A legitimate; FPR on the A hard-negative slice
(login / signup / payment / checkout pages); recall on A phishing (noisy, reported only). Wilson
95% intervals. Paired McNemar exact tests for J1 vs J0 on X-host and on A legitimate.

## Criteria

| ID | Criterion |
|---|---|
| T-a | J1 X-host recall ≥ J0 X-host recall + 0.20 (page text helps substantially) |
| T-b | J1 X-host recall ≥ 0.90 (page text alone closes the gap) |
| T-c | J1 FPR on A legitimate ≤ J0 FPR on A legitimate (0.107) |
| T-d | E1t X-host recall at T1 ≥ E3 X-host recall at T1 − 0.05 (inside EG2, text carries the signal) |

T-b and T-d are informative either way; a MISS means the screenshot carries signal the text
does not.

## Cost and calls

About 4,000 Jev calls (J1 + J2 on 1,995 sites); input-priced, under $0.25. EG2 text embedding
on CPU. No LLM calls.

## Deviations

Any change is logged in the results file under `deviations`, with the reason. Records are
append-only; aggregates are recomputed from them.
