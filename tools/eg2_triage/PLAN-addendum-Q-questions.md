# EG2 Triage — Battery Q: analyst questions, answered by the page (pre-registered)

**Date:** 2026-10-09 · **Status:** frozen before any question is asked of any page.

**Question.** Analysts justify URL decisions with a few concrete observations ("it's a login
portal", "the brand doesn't match the domain"). Turn those into yes/no questions and answer them
from the page. Three things to learn:

1. Do the answers alone, combined by a fixed rule, separate phishing from legitimate pages? That
   makes a verdict that explains itself.
2. Can a text-only reader (Jev, on the page's OCR text, in its own question format) answer them
   as well as a reader that sees the page?
3. How accurate is each answer?

**Data.** X (987 Phishpedia phishing) and A legitimate (672). A's noisy phishing labels are not
used. Page text: Battery T's OCR records (`records/ocr-*.jsonl`), first 2,000 characters.

## Questions

| Key | Question |
|---|---|
| `login_form` | Does the page show a login or sign-in form (fields for a username, email, phone number or password)? |
| `asks_secrets` | Does the page ask the visitor to enter a password, payment card, bank details, or identity details? |
| `brand_shown` | Does the page display the name or logo of a well-known company or service? (LLM also names it) |
| `brand_domain_mismatch` | Does a brand shown on the page belong to a different organization than the one that owns the URL's domain? |
| `file_share_lure` | Does the page invite the visitor to view, download or unlock a shared document, file, invoice, fax or voicemail? |
| `urgency_or_threat` | Does the page pressure the visitor with urgency, threats, or account problems (suspended, locked, expiring, verify now)? |
| `dead_or_parked` | Is the page blank, an error, a parked or for-sale domain, or a hosting placeholder? |

## Readers

**Q-H (Haiku 5.5, sees the page).** Same transport, image width and deviations as V3 (Haiku
5.5 arm: default sampling, `max_tokens` 2048, JSON by instruction). Input: screenshot + `URL:
{url}`. System prompt:

> You are a security analyst reviewing web pages. Answer each question about the page in the
> screenshot; its URL is given. Reply with only a JSON object with these keys: "login_form",
> "asks_secrets", "brand_domain_mismatch", "file_share_lure", "urgency_or_threat",
> "dead_or_parked" (each true or false), and "brand_shown" (the brand's name, or null if none).
> Questions: login_form: {Q}. asks_secrets: {Q}. brand_shown: {Q}. brand_domain_mismatch: {Q}.
> file_share_lure: {Q}. urgency_or_threat: {Q}. dead_or_parked: {Q}.

with each `{Q}` the question text above. `brand_shown` is true when a name is returned.

**Q-J (Jev, page text).** One call per page with the seven questions as `noul` questions (no
disposition question). State = Battery T's J1 state (link + page text). Answer = noul ≥ 0.5.

**Q-E (EG2 zero-shot, sees the page).** Screenshot-only embeddings (A2 / X `a2_image.npy`).
One text query per question, `task: search result | query: {phrase}`, cosine similarity as a
continuous score:

| Key | Phrase |
|---|---|
| `login_form` | a web page with a login form asking for a username and password |
| `asks_secrets` | a web page asking for a password, credit card or bank details |
| `file_share_lure` | a web page offering to view or download a shared document or file |
| `urgency_or_threat` | a web page warning that an account is suspended or must be verified urgently |
| `dead_or_parked` | a blank, error or parked domain web page |

`brand_shown` / `brand_domain_mismatch` for EG2 are Battery N's brand similarity and N2 score.
EG2 is scored by ROC-AUC only (no threshold).

## Audit labels (accuracy reference)

**Sample.** 60 X sites and 60 A legitimate sites, `random.Random(20261009).sample` over each
set's keys in file order.

**Labeler.** The analysis agent (an LLM: Claude Opus 5.5 driving this session), viewing each
screenshot with its URL, *before* any reader's answers are read, recording all seven answers.
Declared: these are not human labels, and the labeler shares a model family with Q-H, so Q-H's
accuracy against them is likely optimistic. Kyle may spot-check; any change he makes is logged.
File: `AUDIT-Q-LABELS.json`.

## Metrics

- Per question and reader: share answered yes on X and on A legitimate; accuracy (Q-H, Q-J) or
  ROC-AUC (Q-E, Q-J noul) against the audit labels; Cohen's κ between Q-H and Q-J on all pages.
- **Rule R1 (fixed):** flag = `asks_secrets` AND (`brand_domain_mismatch` OR
  `file_share_lure`). Recall on X-host, X-rand; FPR on A legitimate and on the hard-negative
  slice. For Q-H and Q-J.
- Exploratory: a logistic regression on the seven Q-H answers (CV grouped by site on A ∪ X)
  — reported, not a criterion.
- **Explanation coverage:** among X pages Haiku 5.5 V3 flagged, the share where Q-H answered yes
  to at least one of `asks_secrets`, `brand_domain_mismatch`, `file_share_lure`,
  `urgency_or_threat`.

## Criteria

| ID | Criterion |
|---|---|
| Q-a | Q-H rule R1: X-host recall ≥ 0.80 and A-legitimate FPR ≤ 0.05 |
| Q-b | Q-H accuracy on the audit ≥ 0.85 for each of `login_form`, `asks_secrets`, `brand_domain_mismatch` |
| Q-c | Q-H vs Q-J agreement ≥ 0.80 for `login_form` and for `asks_secrets` (all pages) |
| Q-d | Explanation coverage ≥ 0.95 |

## Cost and calls

1,659 Haiku 5.5 calls (about $0.35 at list price), under the existing $5 cap, which the harness
enforces. 1,659 Jev calls (under $0.10). EG2: seven text queries.

## Deviations

Logged in the results file under `deviations`. Records append-only.
