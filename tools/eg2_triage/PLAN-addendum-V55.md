# EG2 Triage — Battery V addendum: Haiku 5.5 arm (pre-registered)

**Date:** 2026-10-09 · **Status:** frozen before any recorded Haiku 5.5 call. Two unrecorded
smoke calls checked transport and price only.

**Why:** Battery V used `claude-haiku-4-5`, the newest Haiku in the reference the plan was
written from. The proxy also serves `anthropic/claude-haiku-5.5`. A brief that says "a vision
LLM can't do this" has to test the current cheap model, not only the previous one.

**Protocol:** identical to Battery V as run, including every logged deviation:

- Transport through the account-backed proxy.
- The same system prompt with its JSON rule.
- Temperature 0, `max_tokens` 128, and the same stop sequences.
- Images resized to 1092 px JPEG.

Only the model id changes, to `anthropic/claude-haiku-5.5`. The served model id is recorded
on every call.

**Arms:**

| Arm | Data |
|---|---|
| V2-h55 | Battery A sample, screenshot only |
| V3-h55 | Battery A sample, screenshot + URL |
| V3-h55 | Battery X test set, screenshot + URL |

**Criteria (V-a / V-b repeated for this model):**

| ID | Criterion |
|---|---|
| V-a-h55 | A3 − V3-h55 PR-AUC, bootstrap 95% CI lower bound > −0.02 |
| V-b-h55 | A3 has fewer false positives than V3-h55 (exact McNemar test on negatives, p < 0.05) |

**Spend:** stays under the same $5.00 cap across all V and X calls, enforced by the harness.
